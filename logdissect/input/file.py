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

"""Input format dispatch table and auto-detection (sniffing).

``INPUT_FORMATS`` maps format names to a sniff regex and the module
that parses them. Order matters: legacy formats come first and nginx is
appended last, so auto-detection can never steal a file that a legacy
format already recognized. See the ``logdissect/input/nginx.py``
docstring for the rationale.
"""

import importlib
import re


def _build_table():
    """Build the ordered dispatch table (legacy formats first)"""
    from logdissect.parsers.webaccess import ParseModule as WebaccessParse
    from logdissect.input.nginx import ParseModule as NginxParse
    return [
            ('syslog',
                r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+',
                'logdissect.parsers.syslog'),
            ('syslogiso',
                r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
                'logdissect.parsers.syslogiso'),
            ('webaccess',
                WebaccessParse().format_regex,
                'logdissect.parsers.webaccess'),
            ('nginx',
                NginxParse().format_regex,
                'logdissect.input.nginx'),
            ]


INPUT_FORMATS = [(name, re.compile(regex), module)
        for name, regex, module in _build_table()]


def format_names():
    """Return the list of registered input format names"""
    return [name for name, _regex, _module in INPUT_FORMATS]


def sniff_format(sourcepath, sample_lines=50):
    """Sniff the input format of a log file.

    Each registered format scores its match count over the first
    non-empty sample lines; the highest score wins, and ties go to the
    earliest (legacy) format in the dispatch table. Returns the format
    name, or None if nothing matched.
    """
    samples = []
    with open(str(sourcepath), 'r', encoding='utf-8',
            errors='replace') as logfile:
        for line in logfile:
            ourline = line.rstrip()
            if ourline:
                samples.append(ourline)
            if len(samples) >= sample_lines:
                break
    best_name = None
    best_count = 0
    for name, regex, _module in INPUT_FORMATS:
        count = sum(1 for line in samples if regex.search(line))
        if count > best_count:
            best_name = name
            best_count = count
    return best_name


def resolve_parser(fmt, sourcepath=None):
    """Resolve an input format name (or 'auto') to a parser instance.

    Returns None when fmt is 'auto' and no format matched; raises
    ValueError for an unknown explicit format name.
    """
    if fmt == 'auto':
        if sourcepath is None:
            raise ValueError(
                    'auto input format detection requires a source path')
        name = sniff_format(sourcepath)
        if name is None:
            return None
    else:
        if fmt not in format_names():
            raise ValueError('unknown input format: ' + str(fmt) +
                    ' (available: auto, ' + ', '.join(format_names()) + ')')
        name = fmt
    modules = {n: m for n, _regex, m in INPUT_FORMATS}
    module = importlib.import_module(modules[name])
    return module.ParseModule()
