"""`irimi serve`: the engine as a sidecar, with no child process."""

import argparse
import contextlib
import logging
import queue
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from time import monotonic
from typing import Any

from irimi.cli import CliError, compose, runner
from irimi.cli.options import DEFAULT_PORT, add_proxy_options, epilog, help_formatted
from irimi.core import exitcodes
from irimi.core.exchange import Exchange
from irimi.protocol.trace import UNATTRIBUTED, ToolCall
from irimi.record.store import writer
from irimi.report import terminal
from irimi.report.model import RunView
from irimi.report.summary import summary_lines, tls_failure_lines
from irimi.servicemaps import MapIndex

logger = logging.getLogger(__name__)

# How often the main thread checks for a recorded signal or a stop.
SERVE_POLL_S = 0.1
# How long serve's stop gives its store to write what is queued and its printer the summaries left,
# together, from when the store starts closing: the store's own bound, so a stop takes no longer.
SUMMARIES_TIMEOUT_S = writer.CLOSE_TIMEOUT_S


def register(subparsers: "argparse._SubParsersAction[Any]") -> None:
    serve = subparsers.add_parser(
        "serve",
        **help_formatted(
            help="run the proxy for agents you start yourself, until stopped",
            description="Run irimi's proxy as a sidecar until SIGINT or SIGTERM, for agents you "
            "start yourself\nand point at it with HTTPS_PROXY. Each run the SDK names prints its "
            "summary as it ends;\nrequests no run names are stored as unattributed.",
            epilog=epilog(
                [
                    "irimi serve",
                    "irimi serve --bind 0.0.0.0 --port 4000 --store /data/irimi",
                ]
            ),
        ),
    )
    add_proxy_options(serve, DEFAULT_PORT)
    serve.set_defaults(func=cmd_serve)


def cmd_serve(
    args: argparse.Namespace,
    stop: threading.Event | None = None,
    *,
    engine_factory: compose.EngineFactory = compose.build_engine,
) -> int:
    """Run `irimi serve` until SIGINT, SIGTERM, or `stop` is set (for callers on another thread).

    Either signal drains the store, releases `serve.lock` and exits 0; a run still open gets no
    end. Signal handlers go in first, so no signal finds serve without them.
    """
    with runner.stopping_on_signals() as signalled:
        return _run_serve(args, stop or threading.Event(), signalled, engine_factory)


class _ServeOutput:
    """What serve prints: a line per exchange and tool call, and each run's summary when it ends.

    Called from the engine, store writer and summaries threads; one lock keeps lines from
    interleaving. A summary is read back and printed on a thread of its own (`summaries`), so the
    store writes on.
    """

    def __init__(self, store_root: Path, quiet: bool = False) -> None:
        self.store_root = store_root
        self.quiet = quiet
        self._printing = threading.Lock()
        self.unattributed = 0  # counted for the stop line, since no summary shows them
        # No run's summary shows a failed handshake, so serve warns once per host itself.
        self.ca_cert: Path | None = None
        self._tls_warned: set[str] = set()
        # Each ended run whose summary waits for the printer; None stops it.
        self._ended: queue.SimpleQueue[tuple[MapIndex, str, int | None] | None] = (
            queue.SimpleQueue()
        )
        self._summaries_given_up = False  # set under `_printing` when serve stops waiting
        self._stop_by: float | None = None  # when the printer must be done (`stopping`)

    def say(self, lines: list[str], *, err: bool = False) -> None:
        with self._printing:
            _print(lines, err)

    def exchange(self, ex: Exchange) -> None:
        if ex.run_id == UNATTRIBUTED:
            self.unattributed += 1
        if not self.quiet:
            self.say([terminal.exchange_line(ex)])

    def tool_call(self, call: ToolCall) -> None:
        """Print the tool's name and error, never its args or result, which would print raw."""
        if not self.quiet:
            self.say([terminal.tool_call_line(call)])

    def tls_failure(self, host: str) -> None:
        """Warn, once per host, that a client refused irimi's certificate for `host`."""
        if host in self._tls_warned:
            return
        self._tls_warned.add(host)
        [line] = tls_failure_lines({host: 1}, self.ca_cert)
        self.say([f"warning: {line.strip()}"], err=True)

    def run_ended(self, index: MapIndex, run_id: str, last_seq: int | None) -> None:
        """Queue the run's summary; the store calls this on its writer once the end is written."""
        self._ended.put((index, run_id, last_seq))

    def stopping(self) -> None:
        """Start the stop's clock as the store starts closing; the summaries left share it."""
        self._stop_by = monotonic() + SUMMARIES_TIMEOUT_S

    @contextlib.contextmanager
    def summaries(self) -> Iterator[None]:
        """Print each ended run's summary on a thread of serve's own until the block exits.

        On exit it prints those still queued, until SUMMARIES_TIMEOUT_S after `stopping` (or after
        the exit, if `stopping` was never called).
        """
        printer = threading.Thread(
            target=self._print_summaries, name="irimi-summaries", daemon=True
        )
        printer.start()
        try:
            yield
        finally:
            self._ended.put(None)
            stop_by = monotonic() + SUMMARIES_TIMEOUT_S if self._stop_by is None else self._stop_by
            printer.join(max(0.0, stop_by - monotonic()))
            if printer.is_alive():
                self._give_up_summaries()

    def _give_up_summaries(self) -> None:
        """Warn that summaries went unprinted; the printer prints nothing after this."""
        # A printer stuck writing to a full pipe holds the lock, so it is waited on only briefly.
        locked = self._printing.acquire(timeout=SERVE_POLL_S)
        try:
            self._summaries_given_up = True
            warning = "warning: serve stopped before printing every ended run's summary"
            _print([f"{warning}; irimi runs list shows the runs"], err=True)
        finally:
            if locked:
                self._printing.release()

    def _say_summary(self, lines: list[str], *, err: bool = False) -> None:
        with self._printing:
            if not self._summaries_given_up:
                _print(lines, err)

    def _print_summaries(self) -> None:
        while (ended := self._ended.get()) is not None:
            index, run_id, last_seq = ended
            try:
                self._print_summary(index, run_id, last_seq)
            except Exception as exc:
                # The type only: a message may quote what it choked on.
                logger.warning(
                    "irimi: run %s's summary could not be printed: %s", run_id, type(exc).__name__
                )

    def _print_summary(self, index: MapIndex, run_id: str, last_seq: int | None) -> None:
        """Print the run's summary from the store, as the run stood when its end was written.

        A read failure warns with the exception type only: its message may quote unredacted data.
        """
        try:
            stored = compose.load_stored_run(self.store_root, run_id, last_seq=last_seq)
        except CliError as exc:
            why = type(exc.__cause__).__name__
            warning = f"warning: run {run_id} ended but could not be read back: {why}"
            self._say_summary([warning], err=True)
            return
        summary = summary_lines(RunView(stored.record, stored.events), index)
        self._say_summary([f"--- run {run_id} ---", *summary])


def _print(lines: list[str], err: bool) -> None:
    for line in lines:
        print(line, file=sys.stderr if err else sys.stdout, flush=True)


def _run_serve(
    args: argparse.Namespace,
    stop: threading.Event,
    signalled: list[int],
    engine_factory: compose.EngineFactory,
) -> int:
    """Run the engine from start to stop; `signalled` holds each signal that arrived."""
    output = _ServeOutput(compose.store_root(args), args.quiet)
    died = threading.Event()
    # The printer starts first and stops last, so each end the store writes as it closes still
    # prints, before the stop line.
    with output.summaries():
        run = compose.prepare_run(args, serve=True, on_run_ended=output.run_ended)
        if run is None:
            return exitcodes.ERROR
        with run:
            output.ca_cert = run.ca.cert
            engine = engine_factory(run, output.exchange, output.tool_call, output.tls_failure)
            if signalled:  # stopped before it served: no engine to start, no banner to print
                return exitcodes.OK
            handle = compose.start_engine(engine)
            if handle is None:
                return exitcodes.ERROR
            try:
                if not signalled:  # a banner for a proxy already stopping would say it serves
                    host, port = run.config.listen_host, handle.port()
                    compose.print_startup("serve", args, run.index, None, host, port, run.ca.cert)
                threading.Thread(
                    target=runner.watch_engine, args=(handle.thread, stop, died), daemon=True
                ).start()
                while not signalled and not stop.wait(SERVE_POLL_S):
                    pass
            finally:
                stop.set()  # before the engine stops, so `watch_engine` sees serve stopping it
                handle.stop()
                output.stopping()  # the store closes next
    if output.unattributed:
        count = output.unattributed
        exchanges = "1 exchange" if count == 1 else f"{count} exchanges"
        output.say([f"stopped · {exchanges} not in any run: irimi runs show unattributed"])
    if died.is_set():
        print("error: the proxy stopped on its own", file=sys.stderr)
        return exitcodes.ERROR
    return exitcodes.OK
