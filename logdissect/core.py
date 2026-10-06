#!/usr/bin/env python

# MIT License
# 
# Copyright (c) 2017 Dan Persons <dpersonsdev@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import sys
import string
import logdissect.parsers
import logdissect.filters
import logdissect.output
from logdissect import __version__
from argparse import ArgumentParser
import gettext
gettext.install('logdissect')

# Counters shared by streaming inputs and the last/range filters.
# Skipped lines live here (not on the floor) so every stage can audit
# the identity:
#   lines_total == lines_parsed + lines_skipped
#   len(entries) == lines_parsed - lines_filtered
COUNT_FIELDS = ('lines_total', 'lines_parsed',
        'lines_skipped', 'lines_filtered')


class LogObject(dict):
    """One parsed log stream plus its line-accounting counters.

    It is a ``dict`` so it drops straight into the legacy filter/output
    pipeline (which keys into ``entries`` and friends). The authoritative
    sort key is :data:`SORT_KEY` -- ``numeric_date_stamp_utc`` -- and
    every input, including the nginx combined parser, must normalize to
    UTC before writing it. Mixing raw ``+0800`` wall-clock strings into
    this key would shift entries by the offset during merge sort.
    """

    SORT_KEY = 'numeric_date_stamp_utc'

    def __init__(self, *args, **kwargs):
        """Initialize with zeroed counters and an empty entry list."""
        super(LogObject, self).__init__(*args, **kwargs)
        self.setdefault('entries', [])
        for field in COUNT_FIELDS:
            self.setdefault(field, 0)

    def add_raw_line(self):
        """Account for one physical line read from the source."""
        self['lines_total'] += 1

    def add_entry(self, entry):
        """Accept a parsed entry and its counters."""
        self['entries'].append(entry)
        self['lines_parsed'] += 1

    def count_entry(self):
        """Count a parsed entry without retaining its dict.

        The resident tail pipeline only needs aggregate state plus a
        bounded set of samples; storing every entry dict would let
        resident memory grow without bound on a 100MiB+ feed. Filters
        are not applied on that path, so the remaining invariant is
        ``lines_total == lines_parsed + lines_skipped``.
        """
        self['lines_parsed'] += 1

    def add_skip(self):
        """Account for one malformed line that was skipped, not dropped."""
        self['lines_skipped'] += 1

    def sort_entries(self):
        """Sort entries on the shared UTC sort key."""
        self['entries'].sort(key=lambda e: e.get(self.SORT_KEY, '0'))
        return self

    def record_filter_result(self, kept_entries):
        """Set ``lines_filtered`` from what a filter kept.

        The invariant afterwards is
        ``len(entries) == lines_parsed - lines_filtered``.
        """
        removed = self['lines_parsed'] - len(kept_entries)
        self['lines_filtered'] = removed if removed > 0 else 0
        self['entries'] = kept_entries
        return self

    def reconcile(self):
        """Return ``True`` when the counters and entries add up."""
        if self['lines_total'] != \
                self['lines_parsed'] + self['lines_skipped']:
            return False
        if len(self['entries']) != \
                self['lines_parsed'] - self['lines_filtered']:
            return False
        return True

    @classmethod
    def merge(cls, logs):
        """Merge several logs, summing counters and sorting on UTC."""
        merged = cls()
        for log in logs:
            merged['entries'].extend(log.get('entries', []))
            for field in COUNT_FIELDS:
                merged[field] += log.get(field, 0)
        merged.sort_entries()
        return merged


class LogDissectCore:

    def __init__(self):
        """Initialize logdissect job"""
        self.input_files = []
        self.parse_modules = {}
        self.filter_modules = {}
        self.output_modules = {}
        self.data_set = {}
        self.args = None
        self.arg_parser = ArgumentParser()
        self.parse_args = \
                self.arg_parser.add_argument_group('parse options')
        self.filter_args = \
                self.arg_parser.add_argument_group('filter options')
        self.output_args = \
                self.arg_parser.add_argument_group('output options')
    
    
        
    # run_job does the actual job using the other functions.
    def run_job(self):
        """Execute a logdissect job"""
        try:
            self.load_parsers()
            self.load_filters()
            self.load_outputs()
            self.config_args()
            if self.args.list_parsers:
                self.list_parsers()
            if self.args.verbosemode: print('Loading input files')
            self.load_inputs()
            if self.args.verbosemode: print('Running parsers')
            self.run_parse()
            if self.args.verbosemode: print('Merging data')
            self.data_set['finalized_data'] = \
                    logdissect.utils.merge_logs(
                            self.data_set['data_set'], sort=True)
            if self.args.verbosemode: print('Running filters')
            self.run_filters()
            if self.args.verbosemode: print('Running output')
            self.run_output()
        except KeyboardInterrupt:
            sys.exit(1)

    def run_parse(self):
        """Parse one or more log files"""
        # Data set already has source file names from load_inputs
        parsedset = {}
        parsedset['data_set'] = []
        for log in self.input_files:
            parsemodule = self.parse_modules[self.args.parser]
            try:
                if self.args.tzone:
                    parsemodule.tzone = self.args.tzone
            except NameError: pass
            parsedset['data_set'].append(parsemodule.parse_file(log))
        self.data_set = parsedset
        del(parsedset)

    def run_filters(self):
        for m in self.filter_modules:
            ourfilter = self.filter_modules[m]
            ourlog = ourfilter.filter_data(
                    self.data_set['finalized_data'],
                    args=self.args)
            self.data_set['finalized_data'] = ourlog
            del(ourlog)
            del(ourfilter)

    def run_output(self):
        """Output finalized data"""
        for f in logdissect.output.__formats__:
            ouroutput = self.output_modules[f]
            ouroutput.write_output(self.data_set['finalized_data'],
                    args=self.args)
            del(ouroutput)

        # Output to terminal if silent mode is not set:
        if not self.args.silentmode:
            if self.args.verbosemode:
                print('\n==== ++++ ==== Output: ==== ++++ ====\n')
            for line in self.data_set['finalized_data']['entries']:
                print(line['raw_text'])



    def config_args(self):
        """Set config options"""
        # Module list options:
        self.arg_parser.add_argument('--version', action='version',
                version='%(prog)s ' + str(__version__))
        self.arg_parser.add_argument('--verbose',
                action='store_true', dest = 'verbosemode',
                help=_('set verbose terminal output'))
        self.arg_parser.add_argument('-s',
                action='store_true', dest = 'silentmode',
                help=_('silence terminal output'))
        self.arg_parser.add_argument('--list-parsers',
                action='store_true', dest='list_parsers',
                help=_('return a list of available parsers'))
        self.arg_parser.add_argument('-p',
                action='store', dest='parser', default='syslog',
                help=_('select a parser (default: syslog)'))
        self.arg_parser.add_argument('-z', '--unzip',
                action='store_true', dest='unzip',
                help=_('include files compressed with gzip'))
        self.arg_parser.add_argument('-t',
                action='store', dest='tzone',
                help=_('specify timezone offset to UTC (e.g. \'+0500\')'))
        self.arg_parser.add_argument('files',
                # nargs needs to be * not + so --list-filters/etc
                # will work without file arg
                metavar='file', nargs='*',
                help=_('specify input files'))

        # self.arg_parser.add_argument_group(self.parse_args)
        self.arg_parser.add_argument_group(self.filter_args)
        self.arg_parser.add_argument_group(self.output_args)
        self.args = self.arg_parser.parse_args()

    
    
    # Load input files:
    def load_inputs(self):
        """Load the specified inputs"""
        for f in self.args.files:
            if os.path.isfile(f):
                fparts = str(f).split('.')
                if fparts[-1] == 'gz':
                    if self.args.unzip:
                        fullpath = os.path.abspath(str(f))
                        self.input_files.append(fullpath)
                    else:
                        return 0
                elif fparts[-1] == 'bz2' or fparts[-1] == 'zip':
                    return 0
                else:
                    fullpath = os.path.abspath(str(f))
                    self.input_files.append(fullpath)
            else:
                print('File '+ f + ' not found')
                return 1

    # Parsing modules:
    def list_parsers(self, *args):
        """Return a list of available parsing modules"""
        print('==== Available parsing modules: ====\n')
        for parser in sorted(self.parse_modules):
            print(self.parse_modules[parser].name.ljust(16) + \
                ': ' + self.parse_modules[parser].desc)
        sys.exit(0)
    
    def load_parsers(self):
        """Load parsing module(s)"""
        for parser in sorted(logdissect.parsers.__all__):
            self.parse_modules[parser] = \
                __import__('logdissect.parsers.' + parser, globals(), \
                locals(), [logdissect]).ParseModule()

    def load_filters(self):
        """Load filter module(s)"""
        for f in sorted(logdissect.filters.__filters__):
            self.filter_modules[f] = \
                __import__('logdissect.filters.' + f, globals(), \
                locals(), [logdissect]).FilterModule(args=self.filter_args)

    def load_outputs(self):
        """Load output module(s)"""
        for output in sorted(logdissect.output.__formats__):
            self.output_modules[output] = \
                __import__('logdissect.output.' + output, globals(), \
                locals(), [logdissect]).OutputModule(args=self.output_args)


                
def main():
    dissect = LogDissectCore()
    dissect.run_job()
                
if __name__ == "__main__":
    dissect = LogDissectCore()
    dissect.run_job()
