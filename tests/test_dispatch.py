"""Tests for the file.py dispatch table: -i lookup and sniffing."""

import pytest

from logdissect.input import file as file_input

from conftest import combined


def test_explicit_nginx_lookup():
    module = file_input.get_input('nginx')
    assert module.name == 'nginx'


def test_unknown_input_raises_keyerror():
    with pytest.raises(KeyError):
        file_input.get_input('definitely-not-a-format')


def test_table_places_nginx_last():
    # Legacy formats must be sniffed first so a permissive newcomer
    # cannot intercept an established format.
    names = list(file_input.dispatch_table().keys())
    assert names[-1] == 'nginx'
    for legacy in ('syslog', 'webaccess', 'ciscoios'):
        assert names.index(legacy) < names.index('nginx')


def test_sniff_detects_nginx(nginx_log_path):
    assert file_input.sniff_input(nginx_log_path) == 'nginx'


def test_sniff_detects_legacy_syslog_before_nginx():
    import os
    syslog_sample = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'tests', 'files', 'exsyslog')
    if not os.path.exists(syslog_sample):
        pytest.skip('legacy exsyslog fixture not present')
    assert file_input.sniff_input(syslog_sample) == 'syslog'


def test_sniff_returns_none_for_unreadable_format(tmp_log):
    path = tmp_log(lines=['nothing useful here',
                          'more random words 12345',
                          'nope nope nope'])
    assert file_input.sniff_input(str(path)) is None


def test_sniff_missing_file_returns_none():
    assert file_input.sniff_input('no/such/file.log') is None


def test_legacy_adapter_parses_a_line():
    # The dispatch adapter wraps a legacy parser uniformly.
    table = file_input.dispatch_table()
    module = table['syslog']
    line = ('Feb 27 21:30:46 shade systemd[1]: '
            'started some service')
    assert module.parse(line) is not None


def test_nginx_does_not_hijack_plain_syslog(tmp_log):
    path = tmp_log(lines=[
        'Feb 27 21:30:46 hostA app[12]: message one',
        'Feb 27 21:30:47 hostA app[12]: message two',
        'Feb 27 21:30:48 hostA app[12]: message three',
    ])
    assert file_input.sniff_input(str(path)) == 'syslog'
