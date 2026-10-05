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

"""nginx combined access log parser.

Four interdependent design decisions are documented here, because
changing any one of them breaks the others:

1. Timezone handling: normalize to UTC for the sort key, keep the raw
   string. Each entry keeps the original line in ``raw_text`` and the
   original local timestamp (e.g. ``05/Oct/2026:10:00:01 +0800``) in
   ``date_stamp``/``tzone``, but ``numeric_date_stamp_utc`` is always
   computed via ``logdissect.utils.get_utc_date``. That key is exactly
   the sort key ``logdissect.utils.merge_logs`` uses when
   ``LogDissectCore.run_job`` merges parsed logs, so the two stay
   consistent by construction. If the local wall clock were kept as the
   sort key instead, a ``+0800`` line and a ``+0000`` line from the same
   instant would sort hours apart, and merged output from mixed-offset
   logs would interleave out of order.

2. Malformed lines: skip individually, never abort the file. Every line
   read increments ``data['total_lines']``; lines that do not match the
   combined format increment ``data['skipped_count']`` (with samples
   kept in ``data['skipped_samples']``), so
   ``total_lines == len(entries) + skipped_count`` always holds. The
   counters live on the data dict itself, and the last/range filters
   copy every key except ``entries``, so the counters survive filtering
   and the remaining entry count can be reconciled after filtering.

3. Streaming: ``parse_file`` streams the file line by line instead of
   ``readlines()``. nginx timestamps carry a four-digit year, so the
   reverse-chronological pass the legacy parsers need for Dec/Jan year
   rollover is unnecessary, and a 100 MB access log parses in roughly
   constant memory instead of a full in-memory copy. The resident tail
   pipeline (``logdissect.tail``) reports the peak memory of a run via
   ``tracemalloc`` when it shuts down.

4. Sniff order: this format is registered LAST in the ``INPUT_FORMATS``
   dispatch table in ``logdissect/input/file.py``. The legacy webaccess
   regex also matches nginx combined lines, so auto-detection compares
   per-format match counts and lets the earlier (legacy) format win
   ties; nginx only claims a file when it strictly out-matches the
   legacy parsers (e.g. lines with a named ``remote_user``, which the
   legacy webaccess regex rejects). Existing detections are therefore
   never hijacked by the newcomer.
"""

import gzip
import os
import re
from datetime import datetime

import logdissect.utils


class ParseModule:
    def __init__(self, options=[]):
        """Initialize the nginx combined access log parsing module"""
        self.name = 'nginx'
        self.desc = 'nginx combined access log parsing module'
        self.format_regex = (
                r'^(\S+)\s+(\S+)\s+(\S+)\s+'
                r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}(?::\d{2}){3})\s+'
                r'([+-]\d{4})\]\s+'
                r'"(\S+)\s+(\S+)\s+([^"]+)"\s+'
                r'(\d{3})\s+(\d+|-)\s+'
                r'"([^"]*)"\s+"([^"]*)"\s*$')
        self.fields = ['source_host', 'ident', 'remote_user',
                'date_stamp', 'tzone', 'method', 'path', 'protocol',
                'status', 'byte_count', 'referrer', 'user_agent_string']
        self.tzone = None
        self.date_regex = re.compile(self.format_regex)

    def parse_line(self, line):
        """Parse a single combined-format line into an entry dict"""
        match = re.findall(self.date_regex, line)
        if not match:
            return None
        entry = {}
        entry['raw_text'] = line
        entry['parser'] = self.name
        for field, value in zip(self.fields, match[0]):
            entry[field] = value
        entry = logdissect.utils.convert_webaccess_datestamp(entry)
        if self.tzone:
            entry['tzone'] = self.tzone
        entry = logdissect.utils.get_utc_date(entry)
        return entry

    def parse_file(self, sourcepath):
        """Stream a file into a log data dict, counting skipped lines"""
        data = {}
        data['entries'] = []
        data['parser'] = self.name
        data['source_path'] = sourcepath
        data['source_file'] = sourcepath.split('/')[-1]
        data['source_file_mtime'] = os.path.getmtime(data['source_path'])
        timestamp = datetime.fromtimestamp(data['source_file_mtime'])
        data['source_file_year'] = timestamp.year
        data['total_lines'] = 0
        data['skipped_count'] = 0
        data['skipped_samples'] = []

        if str(sourcepath).endswith('.gz'):
            logfile = gzip.open(sourcepath, 'rt',
                    encoding='utf-8', errors='replace')
        else:
            logfile = open(str(sourcepath), 'r',
                    encoding='utf-8', errors='replace')
        with logfile:
            for line in logfile:
                ourline = line.rstrip()
                data['total_lines'] += 1
                entry = self.parse_line(ourline)
                if entry:
                    entry['source_path'] = data['source_path']
                    data['entries'].append(entry)
                else:
                    data['skipped_count'] += 1
                    if len(data['skipped_samples']) < 20:
                        data['skipped_samples'].append(ourline)

        return data
