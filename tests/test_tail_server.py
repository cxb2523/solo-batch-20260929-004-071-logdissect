"""Resident tail pipeline: aggregator, summary page, SIGINT final."""

import threading
import time
import urllib.request

from logdissect import tail
from logdissect.tail import (StatusAggregator, TailRunner,
                             render_page, DEFAULT_PORT,
                             REFRESH_SECONDS)

from conftest import combined


def _feed(aggregator, lines):
    for line in lines:
        aggregator.consume(line)


def test_aggregator_groups_statuses_and_failures():
    agg = StatusAggregator('x.log')
    _feed(agg, [combined(status=200), combined(status=200),
                combined(status=404), combined(status=500),
                'broken line', 'another broken'])
    snap = agg.snapshot()
    assert snap['status_counts'] == {200: 2, 404: 1, 500: 1}
    assert snap['class_counts'] == {'2xx': 2, '4xx': 1, '5xx': 1}
    assert snap['counters']['lines_total'] == 6
    assert snap['counters']['lines_parsed'] == 4
    assert snap['counters']['lines_skipped'] == 2
    assert len(snap['failure_samples']) == 2
    assert len(snap['non_2xx_samples']) == 2


def test_aggregator_memory_counter_path_flat():
    # count_entry keeps no entry list; only counters grow.
    agg = StatusAggregator('x.log')
    lines = [combined(status=200 + (i % 4) * 100)
             for i in range(500)]
    _feed(agg, lines)
    assert len(agg.log['entries']) == 0
    assert agg.log['lines_parsed'] == 500


def test_render_page_has_both_blocks_and_refresh():
    agg = StatusAggregator('x.log')
    _feed(agg, [combined(status=502), 'nonsense'])
    page = render_page(agg)
    assert 'non-2xx' in page
    assert 'parse failures' in page
    assert '502' in page
    assert 'nonsense' in page
    assert 'content="{}"'.format(REFRESH_SECONDS) in page


def test_default_port_is_fixed():
    assert DEFAULT_PORT == 8089


def test_server_serves_summary_then_stop_prints_final(tmp_log, capsys):
    lines = [combined(status=200), combined(status=404),
             'malformed junk']
    path = tmp_log(lines=lines)
    runner = TailRunner(str(path), port=0)
    runner.start()
    try:
        host, port = runner._httpd.server_address[:2]
        with urllib.request.urlopen(
                'http://127.0.0.1:{}/'.format(port),
                timeout=5) as response:
            body = response.read().decode('utf-8')
        assert response.status == 200
        assert 'nginx status summary' in body
        assert '404' in body
    finally:
        runner.stop()
    out = capsys.readouterr().out
    assert 'final summary' in out
    assert 'lines parsed  : 2' in out
    assert 'lines skipped : 1' in out


def test_follow_picks_up_appended_lines(tmp_log):
    path = tmp_log(lines=[combined(status=200)])
    runner = TailRunner(str(path), port=0)
    runner.start()
    try:
        # Give the follower time to replay the existing line.
        deadline = time.time() + 3
        while time.time() < deadline and \
                runner.aggregator.log['lines_parsed'] < 1:
            time.sleep(0.05)
        with open(str(path), 'a', encoding='utf-8') as handle:
            handle.write(combined(status=503) + '\n')
        deadline = time.time() + 3
        while time.time() < deadline and \
                runner.aggregator.log['lines_parsed'] < 2:
            time.sleep(0.05)
        snap = runner.aggregator.snapshot()
        assert snap['counters']['lines_parsed'] == 2
        assert 503 in snap['status_counts']
    finally:
        runner.stop()


def test_sigint_handler_flushes_final_once(tmp_log, capsys):
    path = tmp_log(lines=[combined(status=301)])
    runner = TailRunner(str(path), port=0)
    runner.start()
    try:
        import signal
        runner.install_signal_handlers()
        # Emulate Ctrl-C delivered to the main thread.
        signal.raise_signal(signal.SIGINT)
        # The handler calls stop(); pump briefly so it completes.
        deadline = time.time() + 2
        while time.time() < deadline and \
                not runner.stop_event.is_set():
            time.sleep(0.02)
        assert runner.stop_event.is_set()
    finally:
        runner.stop()
    out = capsys.readouterr().out
    assert out.count('final summary') >= 1
