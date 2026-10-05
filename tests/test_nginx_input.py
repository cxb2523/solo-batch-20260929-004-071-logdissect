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
import signal
import subprocess
import sys
import time
import urllib.request

import pytest

import logdissect.utils
from logdissect import tail
from logdissect.input import file as input_file
from logdissect.input import nginx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, 'tests', 'data', 'nginx.log')
EXSYSLOG = os.path.join(ROOT, 'tests', 'files', 'exsyslog')


def parse_data():
    return nginx.ParseModule().parse_file(DATA)


def test_parse_counts_reconcile():
    data = parse_data()
    assert data['total_lines'] == 14
    assert len(data['entries']) == 12
    assert data['skipped_count'] == 2
    assert data['total_lines'] == \
            len(data['entries']) + data['skipped_count']
    assert len(data['skipped_samples']) == 2


def test_utc_sort_key_normalization():
    data = parse_data()
    entry = next(e for e in data['entries']
            if '/index.html' in e['raw_text'])
    assert entry['tzone'] == '+0800'
    assert entry['date_stamp'] == '05/Oct/2026:10:00:01'
    assert entry['numeric_date_stamp_utc'].startswith('20261005020001')
    assert '+0800' in entry['raw_text']


def test_mixed_timezone_merge_order():
    data = parse_data()
    merged = logdissect.utils.merge_logs([data], sort=True)
    tstamps = [e['numeric_date_stamp_utc'] for e in merged['entries']]
    assert tstamps == sorted(tstamps)
    raws = [e['raw_text'] for e in merged['entries']]
    index = next(i for i, raw in enumerate(raws) if '/tzcheck' in raw)
    assert '10:00:06' in raws[index - 1]
    assert '10:00:08' in raws[index + 1]


def test_sniff_nginx():
    assert input_file.sniff_format(DATA) == 'nginx'


def test_sniff_legacy_formats_hit_first(tmp_path):
    legacy = tmp_path / 'combined.log'
    legacy.write_text(
            '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326 "-" "Mozilla/4.08"\n'
            * 3)
    assert input_file.sniff_format(str(legacy)) == 'webaccess'
    assert input_file.sniff_format(EXSYSLOG) == 'syslog'
    names = input_file.format_names()
    assert names.index('webaccess') < names.index('nginx')


def test_resolve_parser_explicit_and_auto():
    parser = input_file.resolve_parser('nginx', DATA)
    assert isinstance(parser, nginx.ParseModule)
    auto_parser = input_file.resolve_parser('auto', DATA)
    assert isinstance(auto_parser, nginx.ParseModule)
    with pytest.raises(ValueError):
        input_file.resolve_parser('nosuchformat', DATA)


def test_filters_preserve_counters():
    from logdissect.filters.last import FilterModule as LastFilter
    from logdissect.filters.range import FilterModule as RangeFilter
    data = parse_data()
    ranged = RangeFilter().filter_data(
            data, value='202001010000-202712312359', utc=True)
    assert ranged['skipped_count'] == 2
    assert ranged['total_lines'] == 14
    assert len(ranged['entries']) == 12
    lasted = LastFilter().filter_data(data, value='9999d')
    assert lasted['skipped_count'] == 2
    assert len(lasted['entries']) + lasted['skipped_count'] == \
            lasted['total_lines']


def test_tail_stats_and_page():
    stats = tail.TailStats(nginx.ParseModule())
    with open(DATA, encoding='utf-8') as logfile:
        for line in logfile:
            stats.feed_line(line)
    assert stats.total_lines == 14
    assert stats.parsed_count == 12
    assert stats.failed_count == 2
    assert stats.status_counts['200'] == 6
    assert stats.non2xx_counts['404'] == 2
    assert stats.non2xx_counts['500'] == 1
    page = tail.render_page(stats, DATA)
    assert '非 2xx' in page
    assert '解析失败' in page
    assert 'http-equiv="refresh" content="3"' in page
    assert '404' in page


def run_cli(*cli_args):
    return subprocess.run(
            [sys.executable, '-m', 'logdissect'] + list(cli_args),
            cwd=ROOT, capture_output=True, text=True, timeout=60)


def test_cli_input_format_nginx():
    result = run_cli('-i', 'nginx', '-s', DATA)
    assert result.returncode == 0
    result = run_cli('-i', 'nginx', DATA)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 12


def test_cli_input_format_auto():
    result = run_cli('-i', 'auto', DATA)
    assert result.returncode == 0
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) == 12


def test_tail_sigint_final_tally():
    port = 8876
    creationflags = 0
    if os.name == 'nt':
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(
            [sys.executable, '-m', 'logdissect', 'tail',
                '--format', 'nginx', '--port', str(port), DATA],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, creationflags=creationflags)
    try:
        page = None
        for _attempt in range(50):
            try:
                with urllib.request.urlopen(
                        'http://127.0.0.1:{}/'.format(port),
                        timeout=1) as response:
                    body = response.read().decode('utf-8')
                if '404' in body:
                    page = body
                    break
            except Exception:
                pass
            time.sleep(0.2)
        assert page is not None
        assert '非 2xx' in page
        assert '解析失败' in page
    finally:
        if os.name == 'nt':
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            proc.send_signal(signal.SIGINT)
        out, _err = proc.communicate(timeout=30)
    assert proc.returncode == 0
    assert 'total lines: 14' in out
    assert 'parsed: 12' in out
    assert 'parse failures: 2' in out
    assert '200: 6' in out
    assert 'peak memory:' in out
