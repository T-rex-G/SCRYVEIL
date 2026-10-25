"""Allowlisted numeric observations from the pinned synthetic-only server log.

Log events describe server behavior, not independent proof of request identity
or cancellation. No prompt, path, model response or arbitrary log text is kept.
"""

import re

NUMBER = r"[0-9]{1,12}(?:\.[0-9]{1,8})?"
TIMING = re.compile(
    rf"\b(prompt eval|eval|total) time\s*=\s*({NUMBER}) ms\s*/\s*([0-9]{{1,12}}) tokens"
)
IDENTITY = re.compile(r"\bid\s+(\d{1,12})\s*\|\s*task\s+(-?\d{1,12})(?!\d)")
RELEASE = re.compile(r"\bstop processing: n_tokens = (\d{1,12}), truncated = ([01])(?!\d)")
PROMPT = re.compile(
    rf"\bprompt processing, n_tokens =\s*(\d{{1,12}}), progress = ({NUMBER}), t =\s*({NUMBER}) s / ({NUMBER}) tokens per second"
)
GENERATION = re.compile(
    rf"\bn_gen =\s*(\d{{1,12}}), tg =\s*({NUMBER}) t/s, tg_3s =\s*({NUMBER}) t/s"
)


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
    elif match := PROMPT.search(line):
        record.update(
            kind="prompt_progress",
            tokens=int(match[1]),
            progress=float(match[2]),
            seconds=float(match[3]),
            tokens_per_second=float(match[4]),
        )
    elif match := GENERATION.search(line):
        record.update(
            kind="generation_progress",
            tokens=int(match[1]),
            tokens_per_second=float(match[2]),
            recent_tokens_per_second=float(match[3]),
        )
    elif "processing task, is_child =" in line:
        record.update(kind="task_started")
    elif match := RELEASE.search(line):
        record.update(kind="slot_release", tokens=int(match[1]), truncated=bool(int(match[2])))
    else:
        return None
    return record
