"""Shared pytest fixtures and path helpers for the logdissect suite."""

import os

import pytest


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


def data_path(name):
    """Return the absolute path of a fixture under tests/data."""
    return os.path.join(DATA, name)


@pytest.fixture
def nginx_log_path():
    """Path of the checked-in combined-format sample."""
    return data_path('nginx.log')


@pytest.fixture
def tmp_log(tmp_path):
    """Factory returning (path, write_callable) for a scratch log."""
    def _make(name='access.log', lines=None):
        path = tmp_path / name
        if lines is not None:
            path.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return path
    return _make


COMBINED = (
    '10.0.0.1 - - [05/Oct/2026:12:00:00 {tz}] '
    '"GET /index.html HTTP/1.1" {status} 512 '
    '"https://example.com/" "curl/8.4.0"'
)


def combined(tz='+0800', status=200, ip='10.0.0.1',
             method='GET', path='/index.html',
             day='05', month='Oct', year='2026',
             time_part='12:00:00', size='512',
             referrer='https://example.com/', ua='curl/8.4.0'):
    """Build one combined log line from keyword parts."""
    return ('{ip} - - [{day}/{mon}/{year}:{t} {tz}] '
            '"{m} {p} HTTP/1.1" {s} {b} "{r}" "{ua}"').format(
        ip=ip, day=day, mon=month, year=year, t=time_part, tz=tz,
        m=method, p=path, s=status, b=size, r=referrer, ua=ua)
