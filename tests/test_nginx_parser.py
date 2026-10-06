"""Tests for the streaming nginx combined parser."""

from logdissect.core import LogObject
from logdissect.input.nginx import ParseModule

from conftest import combined


def test_parses_standard_combined_line():
    parser = ParseModule()
    entry = parser.parse(combined(status=404))
    assert entry is not None
    assert entry['source_host'] == '10.0.0.1'
    assert entry['method'] == 'GET'
    assert entry['path'] == '/index.html'
    assert entry['protocol'] == 'HTTP/1.1'
    assert entry['status'] == '404'
    assert entry['status_int'] == 404
    assert entry['byte_count'] == '512'
    assert entry['tzone'] == '+0800'
    assert entry['parser'] == 'nginx'


def test_timestamp_offset_normalized_to_utc():
    # 12:00:00 +0800 == 04:00:00 UTC.
    entry = ParseModule().parse(combined(tz='+0800',
                                         time_part='12:00:00'))
    assert entry['numeric_date_stamp'] == '20261005120000'
    assert entry['numeric_date_stamp_utc'] == '20261005040000'
    # The original +0800 string and wall clock are preserved.
    assert entry['tzone'] == '+0800'
    assert '+0800' in entry['date_stamp']


def test_negative_offset_normalizes_other_direction():
    # 12:00:00 -0500 == 17:00:00 UTC.
    entry = ParseModule().parse(combined(tz='-0500',
                                         time_part='12:00:00'))
    assert entry['numeric_date_stamp_utc'] == '20261005170000'


def test_same_instant_different_offsets_share_utc_sort_key():
    # 12:00 +0800 and 04:00 +0000 are the same instant and must line
    # up under LogObject's UTC sort key instead of being 8h apart.
    east = ParseModule().parse(combined(tz='+0800',
                                        time_part='12:00:00'))
    utc = ParseModule().parse(combined(tz='+0000',
                                       time_part='04:00:00'))
    assert east['numeric_date_stamp_utc'] == \
        utc['numeric_date_stamp_utc'] == '20261005040000'


def test_malformed_line_returns_none_not_raise():
    parser = ParseModule()
    assert parser.parse('this is not a log line at all') is None
    assert parser.parse('') is None
    # Non-numeric status code.
    bad_status = combined(status='abc')
    assert parser.parse(bad_status) is None
    # Unbalanced brackets around the timestamp.
    broken = ('10.0.0.9 - - [05/Oct/2026:11:33:00 +0800 '
              '"GET / HTTP/1.1" 200 12 "-" "-"')
    assert parser.parse(broken) is None


def test_dash_byte_count_is_accepted():
    entry = ParseModule().parse(combined(size='-'))
    assert entry is not None
    assert entry['byte_count'] == '-'


def test_backup_regex_accepts_request_with_spaces_in_path():
    # Spaces in the request URL defeat the strict token regex but the
    # permissive backup branch still extracts the status code.
    line = ('10.0.0.2 - - [05/Oct/2026:12:05:00 +0000] '
            '"GET /search q=log dissect HTTP/1.1" 302 0 "-" "x"')
    entry = ParseModule().parse(line)
    assert entry is not None
    assert entry['status_int'] == 302
    assert entry['path'] == '/search q=log dissect'


def test_parse_file_streams_and_counts(tmp_log):
    lines = [combined(status=200), combined(status=500),
             'garbage line', combined(status=301)]
    path = tmp_log(lines=lines)
    data = ParseModule().parse_file(str(path))
    # 'garbage line' is a physical non-blank line that fails to parse:
    # it is counted as total + skipped, not dropped silently.
    assert data['lines_total'] == 4
    assert data['lines_parsed'] == 3
    assert data['lines_skipped'] == 1
    assert len(data['entries']) == 3
    log = LogObject(data)
    assert log.reconcile()


def test_parse_file_sample_counts(nginx_log_path):
    data = ParseModule().parse_file(nginx_log_path)
    # 68 valid combined lines; 6 non-blank malformed lines are skipped.
    assert data['lines_parsed'] == 68
    assert data['lines_skipped'] == 7
    assert data['lines_total'] == 75
    log = LogObject(data)
    assert log.reconcile()


def test_status_distribution_of_sample(nginx_log_path):
    data = ParseModule().parse_file(nginx_log_path)
    counts = {}
    for entry in data['entries']:
        counts[entry['status_int']] = \
            counts.get(entry['status_int'], 0) + 1
    assert counts[200] == 34
    assert counts[404] == 5
    assert counts[503] == 1
    non_2xx = sum(c for s, c in counts.items() if not 200 <= s <= 299)
    assert non_2xx == 28
