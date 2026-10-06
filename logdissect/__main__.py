"""``python -m logdissect`` entry point.

``tail`` is routed to the resident pipeline; every other invocation is
the legacy one-shot CLI in :mod:`logdissect.core`.
"""

import sys


def main():
    """Dispatch ``tail`` to the resident pipeline, else legacy CLI."""
    if len(sys.argv) > 1 and sys.argv[1] == 'tail':
        from logdissect import tail
        return tail.main(sys.argv[2:])
    from logdissect.core import LogDissectCore
    LogDissectCore().run_job()
    return 0


if __name__ == '__main__':
    sys.exit(main())
