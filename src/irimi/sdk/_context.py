"""Track the current run in a context variable; only `_runs.RunScope` sets it."""

import contextvars
import functools
import os
from collections.abc import Callable

from irimi.protocol.env import ENGINE_ACTIVE_ENV, REPLAY_RUN_ENV, RUN_ENV


class Live:
    """One run as the contexts it was entered in hold it, until `end` makes it current in none.

    A context's copies share this object, so the end also reaches a task or a pool worker that
    kept a copy past the run, as a free-threaded build's threads keep their creator's context.
    """

    __slots__ = ("ended", "run_id")

    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.ended = False

    def end(self) -> None:
        """Make this run current in no context, so nothing joins it or is labelled with it."""
        self.ended = True


_RUN: contextvars.ContextVar[Live | None] = contextvars.ContextVar("irimi_run", default=None)


def is_active() -> bool:
    """Return whether irimi is running this process (`IRIMI_ENGINE_ACTIVE=1`, read at each call).

    Returns:
        True under irimi; when False, triggers and tools call straight through, unrecorded.

    Example:
        if sdk.is_active():
            log.info("running under irimi")
    """
    return os.environ.get(ENGINE_ACTIVE_ENV) == "1"


def replay_run_id() -> str | None:
    """Return the replayed run if `IRIMI_REPLAY_RUN` matches `IRIMI_RUN` (a stale export won't)."""
    if not is_active():
        return None
    replaying = os.environ.get(REPLAY_RUN_ENV) or None
    if replaying is None or replaying != os.environ.get(RUN_ENV):
        return None
    return replaying


def current_run_id() -> str | None:
    """Return the id of the run this code is running in.

    Returns:
        The run's id, or None outside a run, once the run has ended, or while the SDK is
        inactive. It follows asyncio tasks and `asyncio.to_thread`; a thread needs `propagate`.

    Example:
        log.info("handling ticket", extra={"irimi_run": sdk.current_run_id()})
    """
    run = _RUN.get()
    return None if run is None or run.ended else run.run_id


def enter(run: Live) -> contextvars.Token[Live | None]:
    """Make `run` current in this context, until `leave` is given the token."""
    return _RUN.set(run)


def leave(token: contextvars.Token[Live | None]) -> None:
    """Restore the previous run; ValueError unless called in the context `enter` ran in."""
    _RUN.reset(token)


def propagate[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    """Keep work handed to another thread in the current run, while that run lasts.

    Each call runs `fn` in a fresh copy of the context captured now, so it may run on many threads.
    A call made once the run has ended runs `fn` in no run.

    Args:
        fn: The callable to run in the current run.

    Returns:
        A callable with `fn`'s signature that runs it in the current run.

    Example:
        executor.submit(sdk.propagate(refund_one), charge_id)
    """
    context = contextvars.copy_context()

    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        return context.copy().run(fn, *args, **kwargs)

    return wrapper
