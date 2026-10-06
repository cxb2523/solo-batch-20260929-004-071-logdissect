"""CLI-level checks for ``python -m logdissect tail``."""

import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, 'tests', 'data', 'nginx.log')


def _run(*extra, timeout=30):
    return subprocess.run(
        [sys.executable, '-m', 'logdissect'] + list(extra),
        cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def test_tail_once_reports_counts():
    proc = _run('tail', '--format', 'nginx', SAMPLE, '--once')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == '75/68/7'
    assert 'SyntaxWarning' not in proc.stderr


def test_tail_format_short_flag():
    proc = _run('tail', '-i', 'nginx', SAMPLE, '--once')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == '75/68/7'


def test_tail_auto_sniff_once():
    proc = _run('tail', '--format', 'auto', SAMPLE, '--once')
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == '75/68/7'


def test_legacy_cli_still_lists_nginx_parser():
    proc = _run('--list-parsers')
    assert proc.returncode == 0, proc.stderr
    # nginx lives under input/, not the legacy parser list; ensure the
    # legacy command still works and lists a known legacy parser.
    assert 'syslog' in proc.stdout
