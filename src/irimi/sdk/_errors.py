"""Record what a tool raised, and raise it again in a replay without importing the class it names.

- Rebuilding never raises and never imports a module.
"""

import builtins
import dataclasses
import threading

from irimi.protocol import trace
from irimi.sdk._capture import BYTES_KEY, NotReplayable, capture, revive

# What bytes among an exception's args are stored as. Redaction cannot read base64, and a decode
# error's args hold the whole buffer it failed on.
BYTES_DESCRIBED = {trace.REPR_KEY: "<bytes>"}


class RecordedToolError(Exception):
    """An exception a read tool raised in the recorded run, raised again in a replay.

    For a builtin such as KeyError it also subclasses that builtin, so `except KeyError` still
    catches it. `args` are the original's when the recording holds them as JSON can (a tuple in
    them comes back as a list), else `(message,)`. Picklable.

    Attributes:
        type_name: The original's type as the recording names it, such as `builtins.KeyError`.
        message: The original's `str`.

    Example:
        try:
            row = lookup_customer(customer_id)
        except sdk.RecordedToolError as e:
            log.info("the recorded run's lookup raised %s", e.type_name)
    """

    def __init__(
        self, type_name: str, message: str, args: tuple[object, ...] | None = None
    ) -> None:
        super().__init__(*((message,) if args is None else args))
        self.type_name = type_name
        self.message = message
        # The error as the recording holds it, so a call answered with this records it unchanged.
        self._recorded: trace.ErrorInfo | None = None

    def __str__(self) -> str:
        return self.message

    def __reduce__(self) -> tuple[object, tuple[object, ...]]:
        return _rebuilt, (self.type_name, self.message, self.args, self._recorded)


# One class per builtin, so two recorded KeyErrors are of one type.
_AS_BUILTIN: dict[type[Exception], type[RecordedToolError]] = {}
_as_builtin_lock = threading.Lock()


def recorded_error(error: trace.ErrorInfo) -> RecordedToolError:
    """Return the RecordedToolError for `error`, subclassing the builtin it names. Never raises."""
    return _rebuilt(error.type, error.message, _revived_args(error.args), error)


def _revived_args(captured: trace.JSONValue) -> tuple[object, ...] | None:
    """Return a recorded error's args rebuilt, or None if it holds none that can be."""
    try:
        args = revive(captured)
    except NotReplayable:  # a description, such as an object's repr or the truncation marker
        return None
    return tuple(args) if isinstance(args, list) else None


def _rebuilt(
    type_name: str,
    message: str,
    args: tuple[object, ...] | None,
    recorded: trace.ErrorInfo | None = None,
) -> RecordedToolError:
    raised = _raised_as(type_name, message, args)
    raised._recorded = recorded
    return raised


def _raised_as(type_name: str, message: str, args: tuple[object, ...] | None) -> RecordedToolError:
    module, _, name = type_name.rpartition(".")
    builtin = getattr(builtins, name, None) if module == "builtins" else None
    if isinstance(builtin, type) and issubclass(builtin, Exception):
        # Catchable as the builtin matters more than the args, which its constructor may refuse.
        for given in (args, None) if args is not None else (None,):
            try:
                return _as_builtin(builtin)(type_name, message, given)
            except Exception:  # a builtin whose layout or constructor this cannot share
                pass
    return RecordedToolError(type_name, message, args)


def _as_builtin(builtin: type[Exception]) -> type[RecordedToolError]:
    with _as_builtin_lock:
        made = _AS_BUILTIN.get(builtin)
        if made is None:
            # The builtin's name keeps tracebacks as recorded; pickling uses `__reduce__`.
            made = type(
                builtin.__name__,
                (RecordedToolError, builtin),
                {"__qualname__": builtin.__qualname__, "__module__": builtin.__module__},
            )
            _AS_BUILTIN[builtin] = made
        return made


def error_info(exc: BaseException) -> trace.ErrorInfo:
    """Return how to record `exc`; a RecordedToolError keeps its original type name. Never raises.

    A subclass whose `__init__` skipped RecordedToolError's is recorded as any exception is.
    """
    if isinstance(exc, RecordedToolError):
        type_name, message = getattr(exc, "type_name", None), getattr(exc, "message", None)
        if isinstance(type_name, str) and isinstance(message, str):
            return trace.ErrorInfo(type_name, message)
    return trace.ErrorInfo.from_exception(exc)


def tool_error_info(exc: BaseException) -> trace.ErrorInfo:
    """Return how a tool call records `exc`: `error_info`, with its args captured. Never raises.

    A RecordedToolError a replay raised is recorded as its recording holds it.
    """
    recorded = getattr(exc, "_recorded", None) if isinstance(exc, RecordedToolError) else None
    if isinstance(recorded, trace.ErrorInfo):
        return recorded
    try:
        args = exc.args
    except Exception:  # an `args` property that raises: recorded without them
        return error_info(exc)
    return dataclasses.replace(error_info(exc), args=_bytes_described(capture(args)[0]))


def _bytes_described(value: trace.JSONValue) -> trace.JSONValue:
    """Return captured `value` with each bytes in it replaced by BYTES_DESCRIBED."""
    if isinstance(value, list):
        return [_bytes_described(item) for item in value]
    if not isinstance(value, dict):
        return value
    if BYTES_KEY in value:
        return dict(BYTES_DESCRIBED)
    return {key: _bytes_described(item) for key, item in value.items()}
