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

"""Resident tail pipeline: follow a log file and serve a summary page.

``python -m logdissect tail --format nginx tests/data/nginx.log``
processes the existing contents of the file, keeps following it for
appended lines, and serves a status-code summary page on a fixed local
port (default 8976). The page refreshes itself every 3 seconds and is
split into a non-2xx section and a parse-failure section, each with
sample lines. On SIGINT the pipeline prints one final tally (including
the tracemalloc peak memory) and exits.
"""

import argparse
import os
import signal
import sys
import threading
import time
import tracemalloc
from collections import Counter
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import logdissect.input.file as input_file

DEFAULT_PORT = 8976
REFRESH_SECONDS = 3
MAX_SAMPLES = 10
POLL_INTERVAL = 0.5

PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="{refresh}">
<title>logdissect tail - {source}</title>
</head>
<body>
<h1>logdissect tail: {source}</h1>
<p>总行数 (total lines): {total} |
已解析 (parsed): {parsed} |
解析失败 (parse failures): {failed} |
每 {refresh} 秒自动刷新 (auto-refresh every {refresh}s)</p>
<p>状态码汇总 (status counts): {status_line}</p>
<h2>非 2xx 请求 (non-2xx requests)</h2>
<table border="1">
<tr><th>status</th><th>count</th></tr>
{non2xx_rows}
</table>
<h3>样本 (samples)</h3>
<pre>{non2xx_samples}</pre>
<h2>解析失败 (parse failures)</h2>
<p>count: {failed}</p>
<h3>样本 (samples)</h3>
<pre>{failure_samples}</pre>
</body>
</html>
"""


class TailStats:
    """Running aggregate over a tailed log file"""

    def __init__(self, parser):
        """Initialize the aggregator with a parser instance"""
        self.parser = parser
        self.total_lines = 0
        self.parsed_count = 0
        self.failed_count = 0
        self.status_counts = Counter()
        self.non2xx_counts = Counter()
        self.non2xx_samples = []
        self.failure_samples = []
        self.lock = threading.Lock()

    def feed_line(self, line):
        """Parse one line and fold it into the aggregate"""
        ourline = line.rstrip()
        entry = self.parser.parse_line(ourline)
        with self.lock:
            self.total_lines += 1
            if entry is None:
                self.failed_count += 1
                if len(self.failure_samples) < MAX_SAMPLES:
                    self.failure_samples.append(ourline)
            else:
                self.parsed_count += 1
                status = str(entry.get('status', '?'))
                self.status_counts[status] += 1
                if not status.startswith('2'):
                    self.non2xx_counts[status] += 1
                    if len(self.non2xx_samples) < MAX_SAMPLES:
                        self.non2xx_samples.append(ourline)


def render_page(stats, source_path):
    """Render the summary page from a consistent snapshot"""
    with stats.lock:
        total = stats.total_lines
        parsed = stats.parsed_count
        failed = stats.failed_count
        status_counts = sorted(stats.status_counts.items())
        non2xx_counts = sorted(stats.non2xx_counts.items())
        non2xx_samples = list(stats.non2xx_samples)
        failure_samples = list(stats.failure_samples)
    status_line = ', '.join('{}: {}'.format(status, count)
            for status, count in status_counts) or '(none yet)'
    non2xx_rows = ''.join(
            '<tr><td>{}</td><td>{}</td></tr>'.format(escape(status), count)
            for status, count in non2xx_counts) or \
            '<tr><td colspan="2">(none)</td></tr>'
    return PAGE_TEMPLATE.format(
            refresh=REFRESH_SECONDS,
            source=escape(str(source_path)),
            total=total, parsed=parsed, failed=failed,
            status_line=escape(status_line),
            non2xx_rows=non2xx_rows,
            non2xx_samples=escape('\n'.join(non2xx_samples)),
            failure_samples=escape('\n'.join(failure_samples)))


def make_handler(stats, source_path):
    """Build a request handler bound to the shared stats object"""
    class SummaryHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            """Serve the summary page"""
            if self.path.split('?')[0] != '/':
                self.send_error(404)
                return
            page = render_page(stats, source_path).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *args):
            pass

    return SummaryHandler


def print_final(stats, peak_bytes, out):
    """Print the final tally (called once on shutdown)"""
    with stats.lock:
        total = stats.total_lines
        parsed = stats.parsed_count
        failed = stats.failed_count
        status_counts = sorted(stats.status_counts.items())
    status_line = ', '.join('{}: {}'.format(status, count)
            for status, count in status_counts) or '(none)'
    print('', file=out)
    print('==== final tally (SIGINT) ====', file=out)
    print('total lines: {}'.format(total), file=out)
    print('parsed: {}'.format(parsed), file=out)
    print('parse failures: {}'.format(failed), file=out)
    print('status counts: ' + status_line, file=out)
    print('peak memory: {:.2f} MiB'.format(peak_bytes / 1048576.0),
            file=out)


def run_tail(sourcepath, fmt='auto', port=DEFAULT_PORT, out=sys.stdout):
    """Follow a log file and serve the summary page until SIGINT"""
    try:
        parser = input_file.resolve_parser(fmt, sourcepath)
    except ValueError as err:
        print(str(err), file=out)
        return 1
    if parser is None:
        print('Could not detect input format for ' + str(sourcepath),
                file=out)
        return 1
    stats = TailStats(parser)
    server = ThreadingHTTPServer(
            ('127.0.0.1', port), make_handler(stats, sourcepath))
    server_thread = threading.Thread(target=server.serve_forever,
            daemon=True)
    tracemalloc.start()
    server_thread.start()
    print('input format: {}'.format(parser.name), file=out)
    print('serving summary at http://127.0.0.1:{}/ '
            '(refresh {}s), tailing {}'.format(
                port, REFRESH_SECONDS, sourcepath), file=out)
    try:
        with open(str(sourcepath), 'r', encoding='utf-8',
                errors='replace') as logfile:
            while True:
                line = logfile.readline()
                if line:
                    stats.feed_line(line)
                else:
                    time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        pass
    finally:
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        server.shutdown()
        server.server_close()
        server_thread.join()
        print_final(stats, peak, out)
    return 0


def _raise_keyboard_interrupt(signum, frame):
    raise KeyboardInterrupt


def main(argv=None):
    """Entry point for the tail subcommand"""
    arg_parser = argparse.ArgumentParser(
            prog='logdissect tail',
            description='follow a log file and serve a live '
                    'status-code summary page')
    arg_parser.add_argument('--format', dest='format', default='auto',
            help='input format (e.g. nginx), or "auto" to sniff '
                    '(default: auto)')
    arg_parser.add_argument('--port', dest='port', type=int,
            default=DEFAULT_PORT,
            help='summary page port (default: {})'.format(DEFAULT_PORT))
    arg_parser.add_argument('file', help='log file to tail')
    args = arg_parser.parse_args(argv)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _raise_keyboard_interrupt)
    if not os.path.isfile(args.file):
        print('File ' + args.file + ' not found')
        return 1
    return run_tail(args.file, fmt=args.format, port=args.port)
