"""Streaming input modules used by the resident ``tail`` pipeline.

Unlike the one-shot modules in :mod:`logdissect.parsers`, input modules
parse a single physical line on demand so a follower never has to hold a
whole log file in memory.
"""

__inputs__ = ['nginx']

import logdissect.input.nginx
