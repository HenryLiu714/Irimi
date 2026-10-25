"""Reads back what a `writer.DirectoryStore` wrote: the runs a root holds, and one run's events."""

import json
import logging
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from irimi.protocol import trace
from irimi.protocol.trace import (
    UNATTRIBUTED,
    BodyRef,
    RunRecord,
    StoredRun,
    TraceFormatError,
)
from irimi.record.store.layout import EVENTS_FILE, RUN_FILE, StoreLayout, read_run_json

logger = logging.getLogger(__name__)


class RunNotFound(KeyError):
    """No stored run has this id."""


class StoreReader:
    """Reads what a DirectoryStore wrote under `root`."""

    def __init__(self, root: Path) -> None:
        self.layout = StoreLayout(root)

    def list_runs(self) -> list[RunRecord]:
        """Return every run, newest `started_at` first and None last.

        A run.json irimi cannot read, or one naming another run than its directory, is skipped
        with a warning so one run cannot hide the others. Raises OSError if `runs/` cannot be
        listed.
        """
        records = []
        try:
            # Not `Path.is_dir`, which reads an unreadable store as absent.
            runs = sorted(self.layout.runs.iterdir())
        except (FileNotFoundError, NotADirectoryError):
            runs = []
        for directory in runs:
            try:
                if not _holds_run_file(directory):
                    continue
                record = read_run_json(directory)
            except (TraceFormatError, OSError) as exc:
                logger.warning("irimi: skipping stored run %s: %s", directory.name, exc)
                continue
            if record.run_id != directory.name:
                logger.warning(
                    "irimi: skipping stored run %s: its run.json names another run", directory.name
                )
                continue
            records.append(record)
        return sorted(
            records,
            key=lambda r: (r.started_at is None, -(r.started_at or 0.0), r.run_id),
        )

    def load_run(self, run_id: str, *, bodies: bool = True) -> StoredRun:
        """Return one run, events in `seq` order; `UNATTRIBUTED` gives the unattributed events.

        A half-written last line is skipped, and the run's `cut_tail` says so. Raises
        RunNotFound for an unknown id, TraceFormatError for damage (any other unparsable line, a
        missing or resized blob), and OSError for a run irimi may not read. `bodies=False` checks
        each blob's size but reads none, for callers that only count events.
        """
        get_body = self._get_body if bodies else self._check_body
        if run_id == UNATTRIBUTED:
            events = self.layout.unattributed_events
            return self._run(RunRecord.header(UNATTRIBUTED), events, get_body)
        if not trace.is_valid_run_id(run_id):
            raise RunNotFound(run_id)
        directory = self.layout.run_dir(run_id)
        if not _holds_run_file(directory):
            raise RunNotFound(run_id)
        record = read_run_json(directory)
        # On a case-insensitive filesystem `run1` opens `Run1/`: that is another run, not this one.
        if record.run_id != run_id:
            raise RunNotFound(run_id)
        return self._run(record, directory / EVENTS_FILE, get_body)

    def _run(self, record: RunRecord, path: Path, get_body: trace.GetBody) -> StoredRun:
        lines, cut_tail = _lines(path)
        numbered = []
        for line, d in lines:
            # Every refusal names its file and line, so it can be found among thousands of events.
            try:
                numbered.append(trace.event_from_json(d, get_body))
            except TraceFormatError as exc:
                raise TraceFormatError(f"{path}, line {line}: {exc}") from exc
        events = [event for _, event in sorted(numbered, key=lambda pair: pair[0])]
        return StoredRun(record, events, cut_tail)

    def _get_body(self, ref: BodyRef) -> bytes:
        try:
            data = self.layout.blob(ref.sha256).read_bytes()
        except OSError as exc:
            raise TraceFormatError(f"blob {ref.sha256} is missing: {exc}") from exc
        if len(data) != ref.size:
            raise TraceFormatError(f"blob {ref.sha256} holds {len(data)} bytes, not {ref.size}")
        return data

    def _check_body(self, ref: BodyRef) -> bytes:
        """Run `_get_body`'s existence and size checks without reading the blob."""
        try:
            size = self.layout.blob(ref.sha256).stat().st_size
        except OSError as exc:
            raise TraceFormatError(f"blob {ref.sha256} is missing: {exc}") from exc
        if size != ref.size:
            raise TraceFormatError(f"blob {ref.sha256} holds {size} bytes, not {ref.size}")
        return b""


def _holds_run_file(directory: Path) -> bool:
    """Return whether a run directory holds a run.json; any OSError but absence is raised."""
    try:
        return stat.S_ISREG((directory / RUN_FILE).stat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


def _lines(path: Path) -> tuple[Iterator[tuple[int, Any]], bool]:
    """Return an `events.jsonl`'s `(line number, parsed line)` pairs, and whether it is cut off.

    An unparsable final line is a half-written one: it is skipped, and the file is cut off. Any
    other is damage, raised as the pairs are read. A missing file has none.
    """
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return iter(()), False
    *lines, last = data.split(b"\n")
    # No newline after it, so a crash, or a writer still appending it, may have cut it off.
    try:
        tail = [(len(lines) + 1, json.loads(last))] if last else []
    except (ValueError, RecursionError):
        return _parsed(path, lines, []), True
    return _parsed(path, lines, tail), False


def _parsed(
    path: Path, lines: list[bytes], tail: list[tuple[int, Any]]
) -> Iterator[tuple[int, Any]]:
    """Yield `(line number, parsed line)` for each of `lines`, then `tail`; empty lines are none."""
    for i, line in enumerate(lines):
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except (ValueError, RecursionError) as exc:
            raise TraceFormatError(f"{path}, line {i + 1}: {exc}") from exc
        yield i + 1, parsed
    yield from tail
