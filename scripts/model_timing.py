"""Allowlisted numeric observations from the pinned synthetic-only server log.

Log events describe server behavior, not independent proof of request identity
or cancellation. No prompt, path, model response or arbitrary log text is kept.
"""

import re

TIMING = re.compile(
    r"\b(prompt eval|eval|total) time\s*=\s*([0-9]+(?:\.[0-9]+)?) ms\s*/\s*([0-9]+) tokens"
)
IDENTITY = re.compile(r"\bid\s+(\d+)\s*\|\s*task\s+(-?\d+)")
RELEASE = re.compile(r"\bstop processing: n_tokens = (\d+), truncated = (\d+)")


def parse_server_line(line, elapsed):
    identity = IDENTITY.search(line)
    if not identity:
        return None
    record = {
        "slot": int(identity[1]),
        "task": int(identity[2]),
        "observed_elapsed_seconds": elapsed,
    }
    if match := TIMING.search(line):
        record.update(
            kind=match[1].replace(" ", "_"), milliseconds=float(match[2]), tokens=int(match[3])
        )
    elif match := RELEASE.search(line):
        record.update(kind="slot_release", tokens=int(match[1]), truncated=bool(int(match[2])))
    else:
        return None
    return record
