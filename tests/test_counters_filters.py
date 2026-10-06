"""Counters must stay auditable through the last/range filters."""

from logdissect.core import LogObject
from logdissect.filters.last import FilterModule as LastFilter
from logdissect.filters.range import FilterModule as RangeFilter
from logdissect.input.nginx import ParseModule


class _Args:
    last = None
    range = None
    utc = False


def test_skipped_lines_are_counted_not_dropped(nginx_log_path):
    data = ParseModule().parse_file(nginx_log_path)
    assert data['lines_total'] == \
        data['lines_parsed'] + data['lines_skipped']
    log = LogObject(data)
    assert log.reconcile()


def test_range_filter_updates_lines_filtered(nginx_log_path):
    data = ParseModule().parse_file(nginx_log_path)
    before = len(data['entries'])
    args = _Args()
    args.range = '202610051030-202610051100'
    args.utc = True
    result = RangeFilter().filter_data(data, args=args)
    kept = len(result['entries'])
    assert kept < before
    assert result['lines_filtered'] == before - kept
    assert result['lines_parsed'] == data['lines_parsed']
    # Post-filter invariant.
    assert kept == result['lines_parsed'] - result['lines_filtered']


def test_last_filter_accounts_removed_entries(nginx_log_path):
    # All sample timestamps are in the past relative to "now", so a
    # 1-second window keeps nothing and must report every line removed.
    data = ParseModule().parse_file(nginx_log_path)
    before = len(data['entries'])
    args = _Args()
    args.last = '1s'
    result = LastFilter().filter_data(data, args=args)
    assert len(result['entries']) == 0
    assert result['lines_filtered'] == before


def test_logobject_merge_sums_counters(nginx_log_path):
    a = LogObject(ParseModule().parse_file(nginx_log_path))
    b = LogObject(ParseModule().parse_file(nginx_log_path))
    merged = LogObject.merge([a, b])
    assert merged['lines_parsed'] == 2 * 68
    assert merged['lines_skipped'] == 2 * 7
    assert len(merged['entries']) == 2 * 68
    assert merged.reconcile()
