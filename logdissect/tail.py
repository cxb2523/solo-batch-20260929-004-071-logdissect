"""Resident pipeline: follow an nginx log and serve a status summary.

The pipeline follows one file line by line, feeds each line to the
nginx combined input module, and keeps an aggregate by status code.
A tiny HTTP server renders the summary on a fixed local port; the page
asks browsers to refresh every three seconds. Two blocks are shown:
non-2xx responses (grouped by status class) and parse failures with
sample raw lines.

On SIGINT (and SIGTERM / Windows SIGBREAK) one final snapshot is
printed to stdout before exit.
"""

import argparse
import html
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from logdissect.core import COUNT_FIELDS, LogObject
from logdissect.input.nginx import ParseModule as NginxInput

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 8089
REFRESH_SECONDS = 3
FAILURE_SAMPLE_LIMIT = 20
NON_2XX_SAMPLE_LIMIT = 10


class StatusAggregator:
    """Thread-safe aggregate of parsed lines and failures."""

    def __init__(self, source_path):
        self.source_path = source_path
        self.lock = threading.Lock()
        self.status_counts = {}
        self.class_counts = {}
        self.failure_samples = []
        self.non_2xx_samples = []
        self.first_seen_utc = None
        self.last_seen_utc = None
        self.log = LogObject()

    def consume(self, line):
        """Feed one raw physical line through the nginx parser."""
        with self.lock:
            self.log.add_raw_line()
            entry = _NGINX.parse(line)
            if entry is None:
                self.log.add_skip()
                if len(self.failure_samples) < FAILURE_SAMPLE_LIMIT:
                    self.failure_samples.append(line.rstrip('\r\n'))
                return
            # Resident path: count the entry for line accounting but do
            # not retain it; only the aggregate and bounded samples are
            # kept so memory stays flat on an unbounded feed.
            self.log.count_entry()
            status = entry['status_int']
            self.status_counts[status] = \
                    self.status_counts.get(status, 0) + 1
            status_class = '{}xx'.format(status // 100)
            self.class_counts[status_class] = \
                    self.class_counts.get(status_class, 0) + 1
            stamp = entry.get('numeric_date_stamp_utc')
            if stamp:
                if self.first_seen_utc is None or \
                        stamp < self.first_seen_utc:
                    self.first_seen_utc = stamp
                if self.last_seen_utc is None or \
                        stamp > self.last_seen_utc:
                    self.last_seen_utc = stamp
            if not 200 <= status <= 299:
                if len(self.non_2xx_samples) < NON_2XX_SAMPLE_LIMIT:
                    self.non_2xx_samples.append({
                        'status': status,
                        'raw_text': entry['raw_text']})

    def snapshot(self):
        """Return a consistent dict copy of the current aggregate."""
        with self.lock:
            return {
                'source_path': self.source_path,
                'status_counts': dict(sorted(self.status_counts.items())),
                'class_counts': dict(sorted(self.class_counts.items())),
                'failure_samples': list(self.failure_samples),
                'non_2xx_samples': list(self.non_2xx_samples),
                'first_seen_utc': self.first_seen_utc,
                'last_seen_utc': self.last_seen_utc,
                'counters': {f: self.log[f] for f in COUNT_FIELDS},
                'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
            }


_NGINX = NginxInput()


def render_page(aggregator):
    """Render the two-block summary as a single HTML page."""
    snap = aggregator.snapshot()
    counters = snap['counters']
    parts = [
        '<!DOCTYPE html>',
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="refresh" content="{}">'.format(
            REFRESH_SECONDS),
        '<title>logdissect tail - nginx status summary</title>',
        '<style>',
        'body{font-family:monospace;margin:2em;}',
        'table{border-collapse:collapse;margin:1em 0;}',
        'td,th{border:1px solid #888;padding:4px 10px;}',
        'h2{margin-top:1.5em;}',
        '.bad{color:#b00;}',
        'pre{background:#f4f4f4;padding:8px;white-space:pre-wrap;}',
        '</style></head><body>',
        '<h1>nginx status summary</h1>',
        '<p>source: {}</p>'.format(html.escape(snap['source_path'])),
        '<p>total lines: {lines_total} | parsed: {lines_parsed} '
        '| skipped: {lines_skipped} | refreshed: {}</p>'.format(
            snap['updated'], **counters),
        '<h2>by status code</h2>',
        '<table><tr><th>status</th><th>count</th></tr>',
    ]
    if snap['status_counts']:
        for status, count in snap['status_counts'].items():
            css = ' class="bad"' if not 200 <= status <= 299 else ''
            parts.append(
                '<tr{}><td>{}</td><td>{}</td></tr>'.format(
                    css, status, count))
    else:
        parts.append('<tr><td colspan="2">no parsed entries yet</td></tr>')
    parts.append('</table>')

    parts.append('<h2 class="bad">non-2xx responses</h2>')
    non_2xx = [(s, c) for s, c in snap['status_counts'].items()
               if not 200 <= s <= 299]
    parts.append('<table><tr><th>status</th><th>count</th></tr>')
    if non_2xx:
        for status, count in non_2xx:
            parts.append(
                '<tr><td>{}</td><td>{}</td></tr>'.format(status, count))
    else:
        parts.append('<tr><td colspan="2">none</td></tr>')
    parts.append('</table>')
    if snap['non_2xx_samples']:
        parts.append('<p>samples (first {}):</p>'.format(
            NON_2XX_SAMPLE_LIMIT))
        for sample in snap['non_2xx_samples']:
            parts.append('<pre>{} {}</pre>'.format(
                sample['status'],
                html.escape(sample['raw_text'])))

    parts.append('<h2 class="bad">parse failures</h2>')
    parts.append('<p>{lines_skipped} malformed line(s) skipped; '
                 'malformed lines are skipped individually, never '
                 'dropping the whole feed.</p>'.format(**counters))
    if snap['failure_samples']:
        parts.append('<p>samples (first {}):</p>'.format(
            FAILURE_SAMPLE_LIMIT))
        for sample in snap['failure_samples']:
            parts.append('<pre>{}</pre>'.format(html.escape(sample)))
    else:
        parts.append('<p>none</p>')

    parts.append('</body></html>')
    return '\n'.join(parts)


class _SummaryHandler(BaseHTTPRequestHandler):
    aggregator = None

    def do_GET(self):
        if self.path not in ('/', '/summary'):
            self.send_response(404)
            self.end_headers()
            return
        body = render_page(self.aggregator).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _follow_file(path, aggregator, stop_event, from_start=True):
    """Stream ``path`` line by line, reopening on rotation/truncation."""
    position = 0
    logfile = None
    while not stop_event.is_set():
        if logfile is None:
            try:
                logfile = open(path, 'r', encoding='utf-8',
                               errors='replace')
                if not from_start and position:
                    logfile.seek(position)
            except OSError:
                stop_event.wait(0.5)
                continue
        line = logfile.readline()
        if not line:
            position = logfile.tell()
            stop_event.wait(0.5)
            try:
                size = os.path.getsize(path)
            except OSError:
                logfile.close()
                logfile = None
                continue
            if size < position:
                # Truncated or rotated: replay from the top.
                logfile.close()
                logfile = None
                position = 0
            continue
        ourline = line.rstrip('\r\n')
        if ourline.strip():
            aggregator.consume(ourline)
    if logfile is not None:
        logfile.close()


class TailRunner:
    """Run-able tail pipeline with injectable port and stop hook."""

    def __init__(self, path, fmt='nginx', host=DEFAULT_HOST,
                 port=DEFAULT_PORT, from_start=True):
        self.path = os.path.abspath(path)
        self.fmt = fmt
        self.host = host
        self.port = port
        self.from_start = from_start
        self.aggregator = StatusAggregator(self.path)
        self.stop_event = threading.Event()
        self._httpd = None
        self._thread = None
        self._server_thread = None

    def start(self):
        """Start the HTTP server and follower thread."""
        handler = type('BoundHandler', (_SummaryHandler,),
                       {'aggregator': self.aggregator})
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self._server_thread = threading.Thread(
            target=self._httpd.serve_forever,
            kwargs={'poll_interval': 0.5}, daemon=True)
        self._server_thread.start()
        self._thread = threading.Thread(
            target=_follow_file,
            args=(self.path, self.aggregator, self.stop_event,
                  self.from_start),
            daemon=True)
        self._thread.start()

    def wait(self):
        """Block until :meth:`stop` is called."""
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(0.5)
        finally:
            pass

    def stop(self):
        """Stop the follower and print one final snapshot."""
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        self.print_final()

    def print_final(self):
        """Emit the final aggregate exactly once to stdout."""
        snap = self.aggregator.snapshot()
        counters = snap['counters']
        print('\nlogdissect tail final summary: ' + self.path)
        print('  lines total   : {lines_total}'.format(**counters))
        print('  lines parsed  : {lines_parsed}'.format(**counters))
        print('  lines skipped : {lines_skipped}'.format(**counters))
        print('  by status     : ' +
              (', '.join('{}={}'.format(s, c) for s, c in
                         snap['status_counts'].items()) or '(none)'))
        non_2xx = sum(c for s, c in snap['status_counts'].items()
                      if not 200 <= s <= 299)
        print('  non-2xx total : {}'.format(non_2xx))

    def install_signal_handlers(self):
        """Make SIGINT/SIGTERM (and SIGBREAK) flush the final summary."""
        def handler(signum, frame):
            self.stop()
        for signame in ('SIGINT', 'SIGTERM', 'SIGBREAK'):
            sig = getattr(signal, signame, None)
            if sig is not None:
                try:
                    signal.signal(sig, handler)
                except (ValueError, OSError):
                    # Not main thread or unsupported on this platform.
                    pass

    def serve_forever(self):
        """Start, install signal handlers, and block until signaled."""
        self.start()
        self.install_signal_handlers()
        print('logdissect tail following {} on http://{}:{} '
              '(refresh every {}s)'.format(
                  self.path, self.host, self.port, REFRESH_SECONDS))
        self.wait()
        self.stop()


def build_parser():
    """CLI parser for the ``tail`` subcommand."""
    parser = argparse.ArgumentParser(
        prog='logdissect tail',
        description='follow a log file and serve a status summary')
    parser.add_argument('file', help='log file to follow')
    parser.add_argument('-i', '--input', '--format',
                        dest='fmt', default='nginx',
                        help='input format (default: nginx; also auto)')
    parser.add_argument('--host', default=DEFAULT_HOST)
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--end', dest='from_end', action='store_true',
                        help='start at end of file instead of replaying')
    parser.add_argument('--once', action='store_true',
                        help='parse once and print counts, do not serve')
    return parser


def main(argv=None):
    """Entry point for ``python -m logdissect tail``."""
    args = build_parser().parse_args(argv)
    fmt = args.fmt
    if fmt == 'auto':
        from logdissect.input import file as file_input
        fmt = file_input.sniff_input(args.file) or 'nginx'
    if fmt != 'nginx':
        print('tail currently supports the nginx input; '
              'sniffed/selected: {}'.format(fmt), file=sys.stderr)
        return 2

    if args.once:
        from logdissect.input import file as file_input
        data = file_input.get_input(fmt).parse_file(args.file)
        print('{}/{}/{}'.format(
            data['lines_total'], data['lines_parsed'],
            data['lines_skipped']))
        return 0

    runner = TailRunner(args.file, host=args.host, port=args.port,
                        from_start=not args.from_end)
    runner.serve_forever()
    return 0
