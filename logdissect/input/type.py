"""Base class for streaming input modules."""


class InputModule:
    """An input module turns one raw log line into one entry dict.

    Implementations must provide :attr:`name` and :meth:`parse`.
    ``parse`` returns ``None`` for malformed lines; it must never raise
    on bad input, because the resident pipeline skips bad lines instead
    of aborting the whole feed.
    """

    name = ''
    desc = ''

    def parse(self, line):
        """Parse one raw line into an entry dict, or ``None``."""
        raise NotImplementedError

    def sniff_score(self, lines):
        """Return how many of ``lines`` this module can parse."""
        score = 0
        for line in lines:
            if self.parse(line) is not None:
                score += 1
        return score
