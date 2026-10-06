"""File input dispatch table: explicit ``-i`` selection and sniffing.

Every input is exposed through two entry points:

* :func:`get_input` -- direct lookup used by ``-i nginx`` /
  ``--format nginx``; the name wins, no sniffing ambiguity possible.
* :func:`sniff_input` -- auto detection used when no format is given.

The sniffing table deliberately lists every legacy parser *before*
nginx: the new module's backup regex is deliberately permissive and
would otherwise swallow older ``webaccess``-style lines, so legacy
formats must get first crack at a sample.
"""

import os
import re
import warnings

import logdissect.parsers
from logdissect.input import nginx

SNIFF_SAMPLE_LINES = 40
SNIFF_MIN_MATCH_RATIO = 0.6


class LegacyInput:
    """Adapter exposing a legacy :mod:`logdissect.parsers` module.

    Legacy parsers parse a whole file at once (in reverse, for year
    rollover handling). This adapter keeps that behavior for
    ``parse_file`` and adds a streaming ``parse`` so the dispatch table
    has one uniform shape.
    """

    def __init__(self, parser):
        self._parser = parser
        self.name = parser.name
        self.desc = getattr(parser, 'desc', '')

    def parse(self, line):
        return self._parser.parse_line(line.rstrip('\r\n'))

    def parse_file(self, sourcepath):
        return self._parser.parse_file(sourcepath)


def _load_legacy_inputs():
    """Instantiate every shipped legacy parser, in registered order."""
    inputs = {}
    for parser_name in sorted(logdissect.parsers.__all__):
        with warnings.catch_warnings():
            # Legacy modules predate raw-string regexes; their
            # SyntaxWarnings about invalid escapes are pre-existing and
            # irrelevant to the tail pipeline.
            warnings.simplefilter('ignore', SyntaxWarning)
            module = __import__(
                'logdissect.parsers.' + parser_name,
                globals(), locals(), [logdissect])
        if parser_name == 'blank':
            continue
        parser = module.ParseModule()
        if not getattr(parser, 'format_regex', None):
            continue
        parser.date_regex = re.compile(
            r'{}'.format(parser.format_regex))
        if getattr(parser, 'backup_format_regex', None):
            parser.backup_date_regex = re.compile(
                r'{}'.format(parser.backup_format_regex))
        inputs[parser.name] = LegacyInput(parser)
    return inputs


def dispatch_table():
    """Return a fresh ``{name: input_module}`` mapping.

    Legacy parsers are inserted first in their registered order and
    ``nginx`` is appended last, which is exactly the order the sniffer
    walks. A fresh table is returned each call because legacy parsers
    carry per-file state (year rollover, timezone) during ``parse_file``.
    """
    table = _load_legacy_inputs()
    table['nginx'] = nginx.ParseModule()
    return table


def get_input(name):
    """Look up an input by name (the ``-i`` / ``--format`` entry point).

    Raises :class:`KeyError` for unknown names; callers translate that
    into a user-facing list of available inputs.
    """
    return dispatch_table()[name]


def _sample_lines(sourcepath, limit=SNIFF_SAMPLE_LINES):
    """Read up to ``limit`` non-blank lines without loading the file."""
    sample = []
    with open(sourcepath, 'r', encoding='utf-8',
              errors='replace') as logfile:
        for line in logfile:
            ourline = line.rstrip('\r\n')
            if not ourline.strip():
                continue
            sample.append(ourline)
            if len(sample) >= limit:
                break
    return sample


def sniff_input(sourcepath):
    """Auto-detect the input format for ``sourcepath``.

    The table is walked in order (legacy first, nginx last); each
    candidate scores how many sampled lines it can parse, and the first
    candidate reaching :data:`SNIFF_MIN_MATCH_RATIO` wins. Ordering the
    table oldest-first guarantees a newly added permissive module can
    never intercept lines an established parser owns.

    Returns ``None`` when nothing matches confidently enough.
    """
    if not os.path.isfile(sourcepath):
        return None
    sample = _sample_lines(sourcepath)
    if not sample:
        return None
    threshold = max(1, int(len(sample) * SNIFF_MIN_MATCH_RATIO))
    for name, module in dispatch_table().items():
        hits = 0
        for line in sample:
            if module.parse(line) is not None:
                hits += 1
        if hits >= threshold:
            return name
    return None
