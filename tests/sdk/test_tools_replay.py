"""The tool decorators under replay: each test records a run, then replays it on a second engine.

A real read for `_FORBIDDEN` accounts, or any real write, raises, so one that runs fails loudly."""

import asyncio
import contextlib
import copy
import dataclasses
import http.client
import http.server
import inspect
import json
import pickle
import sys
import threading
import time
import traceback
import types
from collections.abc import Callable, Coroutine, Iterator
from decimal import Decimal
from typing import Any

import pytest

from irimi import sdk
from irimi.cli import runner
from irimi.decide.policy import ShadowPolicy
from irimi.engine import control as engine_control
from irimi.protocol import control as protocol_control
from irimi.protocol.control import NO_RECORDED_CALL, RECORDED_ACTION, RecordedOutcome
from irimi.protocol.env import (
    AGENT_VERSION_ENV,
    CONTROL_ENV,
    ENGINE_ACTIVE_ENV,
    REPLAY_RUN_ENV,
    RUN_ENV,
)
from irimi.protocol.headers import RUN_HEADER
from irimi.protocol.trace import (
    REPR_KEY,
    TRUNCATED_KEY,
    ErrorInfo,
    JSONValue,
    RunRecord,
    ToolCall,
    new_run_id,
)
from irimi.record import redact
from irimi.record.store.reader import StoreReader
from irimi.record.store.writer import DirectoryStore
from irimi.replay.index import ReplayIndex
from irimi.replay.policy import ReplayPolicy
from irimi.sdk import _context as context
from irimi.sdk import _control_client as client
from irimi.sdk import _runs as runs
from irimi.sdk import _tools as tools
from irimi.sdk._errors import recorded_error, tool_error_info
from irimi.sdk._state import state
from tests.support.engine import RealWriteRan, engine_config, start_engine

# The accounts whose real read must not run in this test: the replay must answer them.
_FORBIDDEN: set[str] = set()
# What the real `db.balance` answers, account by account, and how often it has run.
_BALANCES: dict[str, int] = {}
_REAL_READS: list[str] = []
SECRET = "sk_test_" + "a" * 24


class _RealReadRan(AssertionError):
    """A read tool's real function ran where the recording should have answered it."""


@dataclasses.dataclass(frozen=True)
class Statement:
    account: str
    lines: list[int]


def _real(account: str) -> None:
    if account in _FORBIDDEN:
        raise _RealReadRan(account)
    _REAL_READS.append(account)


@sdk.read_tool(name="db.balance")
def balance(account: str) -> dict[str, Any]:
    _real(account)
    if account == "acc_missing":
        raise KeyError(account)
    if account == "acc_mystery":
        raise LookupError("no such account")
    return {"account": account, "balance": _BALANCES.get(account, 100)}


@sdk.read_tool(name="db.balance_async")
async def balance_async(account: str) -> dict[str, Any]:
    _real(account)
    await asyncio.sleep(0)
    return {"account": account, "balance": 100}


@sdk.read_tool(name="db.score")
def score(account: str) -> dict[str, Any]:
    """A result JSON cannot hold: it is recorded as `__irimi_repr__`, which does not revive."""
    _real(account)
    return {"score": Decimal("0.87")}


@sdk.read_tool(name="db.statement")
def statement(account: str) -> Statement:
    _real(account)
    return Statement(account, [1, 2])


@sdk.read_tool(name="db.api_key")
def api_key(account: str) -> dict[str, Any]:
    _real(account)
    return {"account": account, "key": SECRET}


async def _history(account: str) -> list[int]:
    _real(account)
    await asyncio.sleep(0)
    return [1, 2, 3]


@sdk.read_tool(name="db.history")
def history(account: str) -> Coroutine[Any, Any, list[int]]:
    """A sync read that returns a coroutine: recorded with what the coroutine returned."""
    return _history(account)


@dataclasses.dataclass(frozen=True)
class Profile:
    account: str
    balance: int


# `Profile`'s module, which `profile`'s body imports: a replay has not imported it when it asks.
_PROFILES = types.ModuleType("irimi_test_profiles")
Profile.__module__ = _PROFILES.__name__
_PROFILES.__dict__["Profile"] = Profile


@sdk.read_tool(name="db.profile")
def profile(account: str) -> Profile:
    """A result named by a module the body imports, built from a read tool the body calls."""
    sys.modules[_PROFILES.__name__] = _PROFILES
    _real(account)
    return Profile(account, balance("acc_1")["balance"])


def _debit_stand_in(account: str, amount: int) -> dict[str, Any]:
    return {"stood_in": True, "account": account, "amount": amount}


@sdk.write_tool(fake=_debit_stand_in, name="db.debit")
def debit(account: str, amount: int) -> dict[str, Any]:
    raise RealWriteRan(account)


@pytest.fixture(autouse=True)
def _a_fresh_world() -> Iterator[None]:
    _FORBIDDEN.clear()
    _BALANCES.clear()
    _REAL_READS.clear()
    yield
    _FORBIDDEN.clear()


class _Irimi:
    """Records a run through one engine, then replays it through another, both on one store."""

    def __init__(self, tmp_path, monkeypatch) -> None:
        self.tmp_path = tmp_path
        self.monkeypatch = monkeypatch
        self.cfg = engine_config(tmp_path, monkeypatch)
        self.root = tmp_path / "store"
        self.key = redact.load_key(tmp_path)
        monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
        monkeypatch.delenv(RUN_ENV, raising=False)
        monkeypatch.delenv(REPLAY_RUN_ENV, raising=False)
        monkeypatch.delenv(AGENT_VERSION_ENV, raising=False)
        monkeypatch.setattr(state, "reporter", client.ControlClient())

    def record(self, script: Callable[[], Any]) -> str:
        """`script` run in one SDK run under a shadow engine: the run's id."""
        self._serve(ShadowPolicy(), DirectoryStore(self.root, self.key), script)
        return self._only_sdk_run(StoreReader(self.root), set())

    def replay(self, run_id: str, script: Callable[[], Any]) -> tuple[Any, list[ToolCall]]:
        """Run `script` again under an engine replaying `run_id`; return its value and tool calls.

        The script's SDK run adopts the engine's run, as `irimi replay`'s child does."""
        before = {r.run_id for r in StoreReader(self.root).list_runs()}
        events = StoreReader(self.root).load_run(run_id).events
        recording = ReplayIndex.from_events(events, self.key, self.cfg.maps)
        # Each replay is a run of its own, the engine's, as each `irimi replay` mints one.
        self.cfg = dataclasses.replace(self.cfg, run_id=new_run_id())
        store = DirectoryStore(self.root, self.key, replay_of=run_id)
        # Stored before the script runs, as `irimi replay` stores its run before its child exists.
        store.start_run(
            RunRecord.process(self.cfg.run_id, ["script"], None, time.time(), replay_of=run_id)
        )
        self.monkeypatch.setenv(RUN_ENV, self.cfg.run_id)
        self.monkeypatch.setenv(REPLAY_RUN_ENV, self.cfg.run_id)
        policy = ReplayPolicy(recording, maps=self.cfg.maps)
        result = self._serve(policy, store, script)
        reader = StoreReader(self.root)
        # The script's `sdk.run` adopted the replay's run, the engine's own, and posted no start.
        replay_run = self.cfg.run_id
        assert replay_run not in before
        assert reader.load_run(replay_run).record.replay_of == run_id
        calls = [e for e in reader.load_run(replay_run).events if isinstance(e, ToolCall)]
        return result, calls

    def _serve(self, policy, store, script) -> Any:
        eng, _seen, stop = start_engine(self.cfg, policy=policy, store=store)
        self.port = eng.listen_port()
        self.monkeypatch.setenv(CONTROL_ENV, f"http://127.0.0.1:{self.port}/_irimi")
        try:
            with sdk.run("script", inputs={"test": True}):
                return script()
        finally:
            stop()

    @staticmethod
    def _only_sdk_run(reader: StoreReader, before: set[str]) -> str:
        [run] = [r for r in reader.list_runs() if r.attribution == "sdk" and r.run_id not in before]
        return run.run_id


@pytest.fixture
def irimi(tmp_path, monkeypatch) -> _Irimi:
    return _Irimi(tmp_path, monkeypatch)


def _post(port: int, path: str, body: object, method: str = "POST") -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=json.dumps(body).encode())
    resp = conn.getresponse()
    data = json.loads(resp.read() or b"null")
    conn.close()
    return resp.status, data


# -- tools answered from the recording ------------------------------------------------------------


def test_a_read_tool_the_recording_holds_returns_its_recorded_result_and_never_runs(irimi):
    _BALANCES["acc_1"] = 100
    run_id = irimi.record(lambda: balance("acc_1"))
    # Live state differs from the recording, and the real read must not run at all.
    _BALANCES["acc_1"] = 5
    _FORBIDDEN.add("acc_1")
    result, [call] = irimi.replay(run_id, lambda: balance("acc_1"))
    assert result == {"account": "acc_1", "balance": 100}
    assert (call.name, call.kind, call.ran) == ("db.balance", "read", "recording")
    assert (call.args, call.result, call.error) == ({"account": "acc_1"}, result, None)


def test_the_same_read_tool_with_other_args_runs_the_real_function(irimi):
    run_id = irimi.record(lambda: balance("acc_1"))
    result, [call] = irimi.replay(run_id, lambda: balance("acc_2"))
    assert result == {"account": "acc_2", "balance": 100}
    assert _REAL_READS == ["acc_1", "acc_2"]
    assert (call.ran, call.args) == ("real", {"account": "acc_2"})


def test_a_recorded_key_error_comes_back_as_recorded_tool_error_catchable_as_key_error(irimi):
    def look() -> Any:
        try:
            balance("acc_missing")
        except KeyError as exc:
            return exc

    run_id = irimi.record(look)
    _FORBIDDEN.add("acc_missing")
    raised, [call] = irimi.replay(run_id, look)
    assert isinstance(raised, sdk.RecordedToolError) and isinstance(raised, KeyError)
    assert (raised.type_name, raised.message) == ("builtins.KeyError", "'acc_missing'")
    # Its args are the original's: the key, not the key quoted.
    assert raised.args == ("acc_missing",)
    # Its `str` is the recorded message, not KeyError's quoting of it again.
    assert str(raised) == "'acc_missing'"
    # Named as recorded, module included, so a traceback says `KeyError: 'acc_missing'`.
    assert (type(raised).__module__, type(raised).__qualname__) == ("builtins", "KeyError")
    assert traceback.format_exception_only(raised) == ["KeyError: 'acc_missing'\n"]
    assert (call.ran, call.result) == ("recording", None)
    # Recorded as it was recorded, not as the class it was raised as.
    assert call.error == ErrorInfo("builtins.KeyError", "'acc_missing'", ["acc_missing"])


def test_a_recorded_result_held_as_its_repr_runs_the_real_function(irimi):
    run_id = irimi.record(lambda: score("acc_1"))
    [recorded] = [
        e for e in StoreReader(irimi.root).load_run(run_id).events if isinstance(e, ToolCall)
    ]
    assert recorded.result == {"score": {"__irimi_repr__": "Decimal('0.87')"}}
    result, [call] = irimi.replay(run_id, lambda: score("acc_1"))
    assert result == {"score": Decimal("0.87")}
    assert _REAL_READS == ["acc_1", "acc_1"]
    assert call.ran == "real"


def test_a_write_tool_runs_its_stand_in_in_a_replay_and_never_the_real_function(irimi):
    run_id = irimi.record(lambda: debit("acc_1", 5))
    result, [call] = irimi.replay(run_id, lambda: debit("acc_1", 5))
    assert result == {"stood_in": True, "account": "acc_1", "amount": 5}
    assert (call.kind, call.ran) == ("write", "shadow")


def test_the_lookup_route_answers_404_under_an_engine_that_is_not_replaying(tmp_path, monkeypatch):
    cfg = engine_config(tmp_path, monkeypatch)
    eng, _seen, stop = start_engine(
        cfg, store=DirectoryStore(tmp_path / "store", redact.load_key(tmp_path))
    )
    try:
        status, body = _post(
            eng.listen_port(),
            f"/_irimi/runs/abcd1234abcd1234/{RECORDED_ACTION}",
            {"name": "db.balance", "args": {"account": "acc_1"}},
        )
    finally:
        stop()
    assert (status, body) == (
        404,
        {"error": {"type": "irimi_control_refused", "message": "no recorded call"}},
    )


# -- the rest of the replay branch ---------------------------------------------------------------


def test_two_identical_calls_take_the_two_recorded_results_in_order_and_a_third_runs(irimi):
    def twice() -> list[Any]:
        first = balance("acc_1")
        _BALANCES["acc_1"] = 200
        return [first, balance("acc_1")]

    run_id = irimi.record(twice)
    _FORBIDDEN.add("acc_1")
    result, calls = irimi.replay(run_id, twice)
    assert [r["balance"] for r in result] == [100, 200]
    assert [c.ran for c in calls] == ["recording", "recording"]
    _FORBIDDEN.clear()
    _, calls = irimi.replay(run_id, lambda: [balance("acc_1") for _ in range(3)])
    assert [c.ran for c in calls] == ["recording", "recording", "real"]


def test_an_async_read_tool_is_answered_from_the_recording(irimi):
    run_id = irimi.record(lambda: asyncio.run(balance_async("acc_1")))
    _FORBIDDEN.add("acc_1")
    result, [call] = irimi.replay(run_id, lambda: asyncio.run(balance_async("acc_1")))
    assert result == {"account": "acc_1", "balance": 100}
    assert call.ran == "recording"


def test_a_sync_tool_that_returned_a_coroutine_is_answered_with_a_coroutine_again(irimi):
    """A sync tool that returned a coroutine is answered with one, so the agent's `await` works."""

    async def awaits() -> list[int]:
        return await history("acc_1")

    run_id = irimi.record(lambda: asyncio.run(awaits()))
    [recorded] = [
        e for e in StoreReader(irimi.root).load_run(run_id).events if isinstance(e, ToolCall)
    ]
    assert (recorded.result, recorded.awaited) == ([1, 2, 3], True)
    _FORBIDDEN.add("acc_1")
    result, [call] = irimi.replay(run_id, lambda: asyncio.run(awaits()))
    assert result == [1, 2, 3]
    assert (call.ran, call.awaited) == ("recording", True)


def test_a_dataclass_result_is_revived_as_the_dataclass(irimi):
    run_id = irimi.record(lambda: statement("acc_1"))
    _FORBIDDEN.add("acc_1")
    result, [call] = irimi.replay(run_id, lambda: statement("acc_1"))
    assert result == Statement("acc_1", [1, 2])
    assert call.ran == "recording"


def test_a_secret_in_a_recorded_result_comes_back_as_its_placeholder(irimi):
    """A secret in a recorded result comes back as its placeholder: the store redacted it."""
    run_id = irimi.record(lambda: api_key("acc_1"))
    _FORBIDDEN.add("acc_1")
    result, [call] = irimi.replay(run_id, lambda: api_key("acc_1"))
    assert result["key"] != SECRET and result["key"].startswith("<redacted:")
    assert call.ran == "recording"


def test_a_recorded_error_that_is_not_a_builtin_is_a_plain_recorded_tool_error(irimi, monkeypatch):
    run_id = irimi.record(lambda: _raised(lambda: balance("acc_mystery")))
    _FORBIDDEN.add("acc_mystery")
    raised, [call] = irimi.replay(run_id, lambda: _raised(lambda: balance("acc_mystery")))
    # LookupError is a builtin: it is caught as one.
    assert isinstance(raised, LookupError) and isinstance(raised, sdk.RecordedToolError)
    assert call.error == ErrorInfo("builtins.LookupError", "no such account", ["no such account"])


def _raised(fn: Callable[[], Any]) -> BaseException | None:
    try:
        fn()
    except Exception as exc:
        return exc
    return None


def test_a_lookup_that_fails_runs_the_tool_for_real_and_warns_once(
    irimi, monkeypatch, warnings, refused_port
):
    run_id = irimi.record(lambda: balance("acc_1"))

    def unreachable() -> Any:
        monkeypatch.setenv(CONTROL_ENV, f"http://127.0.0.1:{refused_port}/_irimi")
        return [balance("acc_1"), balance("acc_1")]

    result, calls = irimi.replay(run_id, unreachable)
    assert [r["balance"] for r in result] == [100, 100]
    assert calls == []  # their posts could not reach the engine either
    assert _REAL_READS == ["acc_1", "acc_1", "acc_1"]
    said = [w.getMessage() for w in warnings()]
    [lookup] = [w for w in said if "look up a recorded call of tool db.balance" in w]
    # The failure paused every send, so the posts after it were skipped, and not warned of.
    assert "irimi is not asked again for 30s" in lookup
    assert not [w for w in said if "could not record a tool call" in w]


def test_a_miss_is_said_by_no_warning(irimi, warnings):
    """The endpoint's 404 is a miss, not a failure: the tool runs, and nothing is logged."""
    run_id = irimi.record(lambda: balance("acc_1"))
    irimi.replay(run_id, lambda: balance("acc_2"))
    assert warnings() == []


def test_an_inactive_sdk_never_asks_the_recording(monkeypatch):
    monkeypatch.delenv(ENGINE_ACTIVE_ENV, raising=False)
    monkeypatch.setenv(RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")

    class _Refuses:
        def post(self, *args: Any) -> None:
            raise AssertionError("an inactive SDK posts nothing")

        def recorded(self, *args: Any) -> None:
            raise AssertionError("an inactive SDK asks nothing")

    monkeypatch.setattr(state, "reporter", _Refuses())
    assert balance("acc_1") == {"account": "acc_1", "balance": 100}


@pytest.mark.parametrize("run_env", [None, "another0another0"])
def test_a_replay_id_irimi_did_not_set_asks_no_recording(monkeypatch, run_env):
    """A stale `IRIMI_REPLAY_RUN` is ignored: the read tool runs for real and posts its call."""
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")
    if run_env is None:
        monkeypatch.delenv(RUN_ENV, raising=False)
    else:
        monkeypatch.setenv(RUN_ENV, run_env)
    posted: list[str] = []

    class _Writes:
        """Note each post and lookup; a lookup is counted, since a raise would be swallowed."""

        def post(self, run_id: str, kind: str, payload: Any) -> None:
            posted.append(kind)

        def recorded(self, *args: Any) -> None:
            posted.append("recorded")

    monkeypatch.setattr(state, "reporter", _Writes())
    assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    assert (posted, _REAL_READS) == (["tool-calls"], ["acc_1"])


def test_a_hit_is_used_up_and_is_not_itself_a_tool_call(irimi):
    run_id = irimi.record(lambda: balance("acc_1"))
    events = StoreReader(irimi.root).load_run(run_id).events
    recording = ReplayIndex.from_events(events, irimi.key, irimi.cfg.maps)
    store = DirectoryStore(irimi.root, irimi.key, replay_of=run_id)
    eng, _seen, stop = start_engine(irimi.cfg, policy=ReplayPolicy(recording), store=store)
    route = f"/_irimi/runs/abcd1234abcd1234/{RECORDED_ACTION}"
    posted = {"name": "db.balance", "args": {"account": "acc_1"}}
    try:
        first = _post(eng.listen_port(), route, posted)
        second = _post(eng.listen_port(), route, posted)
    finally:
        stop()
    answer = {"result": {"account": "acc_1", "balance": 100}, "error": None, "awaited": False}
    status, found = first
    assert (status, {k: v for k, v in found.items() if k != "answer_id"}) == (200, answer)
    assert second == (
        404,
        {"error": {"type": "irimi_control_refused", "message": "no recorded call"}},
    )
    assert "abcd1234abcd1234" not in {r.run_id for r in StoreReader(irimi.root).list_runs()}


@pytest.mark.parametrize(
    ("path", "body", "method", "status", "said"),
    [
        ("runs/abcd1234abcd1234/tool-calls/recorded", {"name": "x"}, "POST", 400, "'args'"),
        (
            "runs/abcd1234abcd1234/tool-calls/recorded",
            {"name": 1, "args": {}},
            "POST",
            400,
            "'name'",
        ),
        (
            "runs/abcd1234abcd1234/tool-calls/recorded",
            {"name": "x", "args": {}},
            "GET",
            405,
            "POST",
        ),
        (
            "runs/../tool-calls/recorded",
            {"name": "x", "args": {}},
            "POST",
            400,
            "cannot name a run",
        ),
        ("runs/tool-calls/recorded", {"name": "x", "args": {}}, "POST", 404, "no control route"),
        (
            "runs/abcd1234abcd1234/recorded",
            {"name": "x", "args": {}},
            "POST",
            404,
            "no control route",
        ),
    ],
)
def test_the_lookup_route_is_validated_like_every_control_route(
    tmp_path, monkeypatch, path, body, method, status, said
):
    cfg = engine_config(tmp_path, monkeypatch)
    eng, _seen, stop = start_engine(cfg)
    try:
        got, answer = _post(eng.listen_port(), f"/_irimi/{path}", body, method)
    finally:
        stop()
    assert got == status and said in answer["error"]["message"]


@pytest.mark.parametrize("run_id", ["unattributed", "t3st"])
def test_a_tool_called_in_no_run_or_the_process_run_may_ask_the_recording(irimi, run_id):
    """A tool in no SDK run asks the recording from the process run, or from `unattributed`."""
    recorded = irimi.record(lambda: balance("acc_1"))
    events = StoreReader(irimi.root).load_run(recorded).events
    recording = ReplayIndex.from_events(events, irimi.key, irimi.cfg.maps)
    store = DirectoryStore(irimi.root, irimi.key, replay_of=recorded)
    eng, _seen, stop = start_engine(irimi.cfg, policy=ReplayPolicy(recording), store=store)
    try:
        status, _ = _post(
            eng.listen_port(),
            f"/_irimi/runs/{run_id}/{RECORDED_ACTION}",
            {"name": "db.balance", "args": {"account": "acc_1"}},
        )
    finally:
        stop()
    assert status == 200


def test_a_replay_s_child_is_told_it_replays_and_a_shadow_run_s_never_is(tmp_path):
    base = {REPLAY_RUN_ENV: "stale"}
    shadow = runner.child_env(base, "127.0.0.1", 4000, tmp_path / "ca.pem", "abcd1234abcd1234")
    replay = runner.child_env(
        base, "127.0.0.1", 4000, tmp_path / "ca.pem", "abcd1234abcd1234", replaying=True
    )
    assert REPLAY_RUN_ENV not in shadow
    assert replay[REPLAY_RUN_ENV] == "abcd1234abcd1234"
    assert base == {REPLAY_RUN_ENV: "stale"}


def test_a_run_that_ends_on_a_recorded_error_records_the_recorded_type(irimi):
    """A replay re-raises the recorded `builtins.KeyError` as `RecordedToolError`.

    The adopted run posts no end of its own: `irimi replay` ends it with how its child exited."""

    def ends_on_it() -> None:
        balance("acc_missing")

    with pytest.raises(KeyError):
        irimi.record(ends_on_it)
    [recorded] = [r for r in StoreReader(irimi.root).list_runs() if r.attribution == "sdk"]
    assert recorded.end is not None
    assert recorded.end.error == ErrorInfo("builtins.KeyError", "'acc_missing'")
    _FORBIDDEN.add("acc_missing")
    with pytest.raises(sdk.RecordedToolError) as raised:
        irimi.replay(recorded.run_id, ends_on_it)
    assert isinstance(raised.value, KeyError)
    replayed = StoreReader(irimi.root).load_run(irimi.cfg.run_id).record
    assert replayed.end is None


@pytest.mark.parametrize("kind", ["builtins.KeyboardInterrupt", "builtins.SystemExit"])
def test_a_recorded_builtin_that_is_no_exception_is_never_raised_as_itself(kind):
    """A recorded Ctrl-C or exit comes back as a plain RecordedToolError, never as itself."""
    raised = recorded_error(ErrorInfo(kind, ""))
    assert type(raised) is sdk.RecordedToolError


@pytest.mark.parametrize(
    ("error", "builtin", "args"),
    [
        (ErrorInfo("builtins.KeyError", "'acc_1'", ["acc_1"]), KeyError, ("acc_1",)),
        (ErrorInfo("builtins.ValueError", "", []), ValueError, ()),
        (ErrorInfo("builtins.KeyError", "['a', 1]", [["a", 1]]), KeyError, (["a", 1],)),
        (ErrorInfo("myapp.errors.NotFound", "acc_1 (3)", ["acc_1", 3]), None, ("acc_1", 3)),
    ],
)
def test_a_recorded_error_s_args_come_back_as_its_args(error, builtin, args):
    """A recorded error raised again has the args the original had, as JSON holds them."""
    raised = recorded_error(error)
    assert raised.args == args
    assert str(raised) == error.message
    assert builtin is None or isinstance(raised, builtin)


def test_a_recorded_os_error_s_args_give_back_its_errno_and_strerror():
    """OSError reads `errno` and `strerror` from its args; its filename is not one of them."""
    raised = recorded_error(ErrorInfo("builtins.FileNotFoundError", "x", [2, "No such file"]))
    assert isinstance(raised, FileNotFoundError)
    assert (raised.errno, raised.strerror, raised.filename) == (2, "No such file", None)


def test_a_builtin_that_needs_its_args_is_raised_as_itself_once_they_are_recorded():
    """UnicodeDecodeError takes five arguments: with them it is a builtin, without them plain."""
    said = "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte"
    args: list[JSONValue] = ["utf-8", {"__irimi_bytes__": "/w=="}, 0, 1, "invalid start byte"]
    raised = recorded_error(ErrorInfo("builtins.UnicodeDecodeError", said, args))
    assert isinstance(raised, UnicodeDecodeError)
    assert (raised.object, raised.start, raised.reason) == (b"\xff", 0, "invalid start byte")
    assert type(recorded_error(ErrorInfo("builtins.UnicodeDecodeError", said))) is (
        sdk.RecordedToolError
    )


@pytest.mark.parametrize(
    "args",
    [
        None,  # recorded before args were, or by a client that sends none
        [{REPR_KEY: "<object object at 0x1>"}],  # a description, not the value
        {TRUNCATED_KEY: True, "bytes": 2_000_000},  # past the capture budget
        redact.REDACTION_FAILED,  # what redaction stores when it cannot read them
    ],
)
def test_a_recorded_error_with_no_args_that_rebuild_has_its_message_as_its_args(args):
    raised = recorded_error(ErrorInfo("builtins.KeyError", "'acc_1'", args))
    assert isinstance(raised, KeyError)
    assert raised.args == ("'acc_1'",)


def test_args_a_builtin_refuses_still_raise_it_as_that_builtin_with_its_message():
    """Being caught as the builtin matters more than the args, which a trace may hold damaged."""
    raised = recorded_error(ErrorInfo("builtins.SyntaxError", "bad", ["bad", "no details"]))
    assert isinstance(raised, SyntaxError)
    assert raised.args == ("bad",)


@pytest.mark.parametrize(
    "args",
    [None, ["acc_1"], [{REPR_KEY: "<object object at 0x1>"}], {TRUNCATED_KEY: True, "bytes": 9}],
    ids=["none", "args", "a-description", "truncated"],
)
def test_a_replayed_error_is_recorded_again_as_its_recording_holds_it(args):
    """A call a replay answered records the recorded error, not args read off what it rebuilt."""
    error = ErrorInfo("builtins.KeyError", "'acc_1'", args)
    raised = recorded_error(error)
    for again in (raised, pickle.loads(pickle.dumps(raised)), copy.copy(raised)):
        assert tool_error_info(again) == error
        assert tool_error_info(again).args == args


def test_a_recorded_tool_error_built_by_hand_records_its_own_args():
    raised = sdk.RecordedToolError("builtins.KeyError", "'acc_1'", ("acc_1",))
    assert tool_error_info(raised) == ErrorInfo("builtins.KeyError", "'acc_1'", ["acc_1"])


@pytest.mark.parametrize("args", [None, ["acc_1", 2]], ids=["no-args", "args"])
@pytest.mark.parametrize("kind", ["builtins.KeyError", "myapp.errors.NotFound"])
def test_a_recorded_tool_error_pickles_and_copies_as_itself(kind, args):
    """A RecordedToolError pickles and copies, args too, so agents can hand it across processes."""
    raised = recorded_error(ErrorInfo(kind, "'acc_1'", args))
    for again in (pickle.loads(pickle.dumps(raised)), copy.copy(raised)):
        assert type(again) is type(raised)
        assert (again.type_name, again.message, str(again)) == (kind, "'acc_1'", "'acc_1'")
        assert again.args == raised.args == (("'acc_1'",) if args is None else tuple(args))


def test_an_async_tool_outside_a_replay_runs_its_body_without_a_hop_off_the_loop(
    irimi, monkeypatch
):
    """Under shadow, async tools go straight to their bodies; only a replay's read waits."""
    hops: list[str] = []
    real = runs.off_the_loop

    async def counted(fn: Any, *args: Any) -> Any:
        hops.append(getattr(fn, "__name__", repr(fn)))
        return await real(fn, *args)

    monkeypatch.setattr(tools, "off_the_loop", counted)
    irimi.record(lambda: asyncio.run(balance_async("acc_1")))
    assert "_replay_answer" not in hops


# -- misses, bounds and the lookup's path ----------------------------------------------------------


@sdk.read_tool(name="db.slow")
async def slow(account: str) -> dict[str, Any]:
    _REAL_READS.append(account)
    await asyncio.sleep(30)  # longer than any test waits: the agent's timeout always cancels it
    return {"account": account}


def _times_out() -> str:
    async def main() -> str:
        try:
            await asyncio.wait_for(slow("acc_1"), 0.05)
        except TimeoutError:
            return "timed out"
        return "answered"

    return asyncio.run(main())


def test_a_recorded_call_that_was_cancelled_is_a_miss_and_the_tool_runs(irimi):
    """A recorded `CancelledError` is a miss: the tool runs again, and is cancelled again.

    Answered with it, the agent's `except TimeoutError` would meet a RecordedToolError instead."""
    run_id = irimi.record(_times_out)
    [recorded] = [
        e for e in StoreReader(irimi.root).load_run(run_id).events if isinstance(e, ToolCall)
    ]
    assert recorded.error == ErrorInfo("asyncio.exceptions.CancelledError", "", [])
    result, [call] = irimi.replay(run_id, _times_out)
    assert result == "timed out"
    assert _REAL_READS == ["acc_1", "acc_1"]
    assert (call.ran, call.error) == ("real", recorded.error)


@pytest.mark.parametrize("stopped", ["builtins.GeneratorExit", "trio.Cancelled"])
def test_a_recorded_call_closed_unawaited_or_cancelled_under_trio_is_a_miss(monkeypatch, stopped):
    """A recorded `GeneratorExit` or trio cancellation is a miss: no outcome of the tool's own."""
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
    monkeypatch.setenv(RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")
    posted: list[Any] = []

    class _Closed:
        def post(self, run_id: str, action: str, doc: Any) -> None:
            posted.append(doc)

        def recorded(self, *args: Any) -> RecordedOutcome:
            return RecordedOutcome(None, ErrorInfo(stopped, ""), awaited=False)

    monkeypatch.setattr(state, "reporter", _Closed())
    assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    assert [doc["ran"] for doc in posted] == ["real"]


# -- an answer the SDK cannot use ---------------------------------------------------------------


def test_a_result_this_process_cannot_rebuild_is_released_so_its_body_is_answered(irimi, warnings):
    """A recorded result whose class is not imported yet runs the tool again, its body answered.

    The SDK releases the answer before the body runs, so the `db.balance` the body calls takes the
    result it took when recorded, and the agent's own `db.balance` after it the next one."""

    def script() -> list[Any]:
        first = profile("acc_p")
        _BALANCES["acc_1"] = 200
        return [first, balance("acc_1")]

    try:
        run_id = irimi.record(script)
        del sys.modules[_PROFILES.__name__]
        _FORBIDDEN.add("acc_1")
        result, calls = irimi.replay(run_id, script)
    finally:
        sys.modules.pop(_PROFILES.__name__, None)
    assert result == [Profile("acc_p", 100), {"account": "acc_1", "balance": 200}]
    assert [(c.name, c.ran) for c in calls] == [
        ("db.balance", "recording"),
        ("db.profile", "real"),
        ("db.balance", "recording"),
    ]
    assert _REAL_READS == ["acc_p", "acc_1", "acc_1", "acc_p"]
    assert warnings() == []


def _profile_then_balance() -> list[Any]:
    """`db.profile`, whose body calls `db.balance`, then the agent's own `db.balance`."""
    first = profile("acc_p")
    _BALANCES["acc_1"] = 200
    return [first, balance("acc_1")]


# What an SDK or an irimi from before `tool-calls/recorded/release` gets in a replay of that:
# the answer is used up with its body's `db.balance`, so the body takes the agent's recorded one.
_USED_UP_WITH_ITS_BODY = (
    [Profile("acc_p", 200), {"account": "acc_1", "balance": 200}],
    [("db.balance", "recording"), ("db.profile", "real"), ("db.balance", "real")],
)


def test_an_sdk_from_before_the_release_route_is_answered_as_it_was(irimi, monkeypatch, warnings):
    """An SDK that reads only `result`, `error` and `awaited`, and never releases, still replays.

    Its answers hold the fields they did, plus `answer_id`; its tool's body misses as it did."""

    class _Before:
        def __init__(self, reporter: client.Reporter) -> None:
            self.reporter = reporter

        def post(self, *args: Any) -> None:
            self.reporter.post(*args)

        def recorded(self, *args: Any) -> RecordedOutcome | None:
            found = self.reporter.recorded(*args)
            return None if found is None else dataclasses.replace(found, answer_id=None)

    try:
        run_id = irimi.record(_profile_then_balance)
        del sys.modules[_PROFILES.__name__]
        monkeypatch.setattr(state, "reporter", _Before(state.reporter))
        result, calls = irimi.replay(run_id, _profile_then_balance)
    finally:
        sys.modules.pop(_PROFILES.__name__, None)
    assert (result, [(c.name, c.ran) for c in calls]) == _USED_UP_WITH_ITS_BODY
    assert warnings() == []


def test_an_answer_holds_the_fields_an_older_sdk_reads_as_they_were(irimi):
    """A hit's answer is the outcome an older SDK read, its fields unchanged, and an `answer_id`."""
    run_id = irimi.record(lambda: balance("acc_1"))
    lookup = {"name": "db.balance", "args": {"account": "acc_1"}}

    def asks() -> tuple[int, dict[str, Any]]:
        return _post(irimi.port, f"/_irimi/runs/{irimi.cfg.run_id}/{RECORDED_ACTION}", lookup)

    (status, answer), _ = irimi.replay(run_id, asks)
    assert status == 200 and sorted(answer) == ["answer_id", "awaited", "error", "result"]
    assert (answer["result"], answer["error"], answer["awaited"]) == (
        {"account": "acc_1", "balance": 100},
        None,
        False,
    )


def test_this_sdk_against_an_irimi_from_before_the_release_route_releases_nothing(
    irimi, monkeypatch, warnings
):
    """Against an irimi whose answers name no `answer_id`, the SDK posts no release.

    That irimi answers the route `404`, which the SDK would warn of; it says nothing."""
    encode = protocol_control.recorded_outcome_to_json
    monkeypatch.setattr(
        protocol_control, "recorded_outcome_to_json", lambda call, answer_id=None: encode(call)
    )
    monkeypatch.setattr(engine_control, "RELEASE_ACTION", "tool-calls/recorded/not-a-route")

    def script() -> tuple[list[Any], tuple[int, dict[str, Any]]]:
        replayed = _profile_then_balance()
        route = f"/_irimi/runs/{irimi.cfg.run_id}/{RECORDED_ACTION}/release"
        return replayed, _post(irimi.port, route, {"answer_id": "a1"})

    try:
        run_id = irimi.record(_profile_then_balance)
        del sys.modules[_PROFILES.__name__]
        (result, released), calls = irimi.replay(run_id, script)
    finally:
        sys.modules.pop(_PROFILES.__name__, None)
    assert (result, [(c.name, c.ran) for c in calls]) == _USED_UP_WITH_ITS_BODY
    assert released[0] == 404 and released[1]["error"]["message"].startswith("no control route")
    assert warnings() == []


def test_an_answer_with_no_id_from_an_older_irimi_is_never_released(monkeypatch, warnings):
    body = json.dumps({**_HIT, "result": _GONE}).encode()
    with _answering(monkeypatch, 200, body) as seen:
        assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    route = "/_irimi/runs/abcd1234abcd1234/tool-calls"
    assert [path for path, _ in seen] == [f"{route}/recorded", route]
    assert warnings() == []


def _replaying_with(monkeypatch, reporter: object) -> None:
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
    monkeypatch.setenv(RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setattr(state, "reporter", reporter)


_GONE: JSONValue = {"__irimi_type__": "nowhere:Gone", "value": {}}
_ONE: JSONValue = {"account": "acc_1", "balance": 1}


@pytest.mark.parametrize("tool", [balance, balance_async], ids=["sync", "async"])
@pytest.mark.parametrize(
    ("outcome", "released"),
    [
        (RecordedOutcome(_GONE, None, False, "a1"), ["a1"]),
        (RecordedOutcome(None, ErrorInfo("trio.Cancelled", ""), False, "a1"), ["a1"]),
        (RecordedOutcome(_GONE, None, False), []),
        (RecordedOutcome(_ONE, None, False, "a1"), []),
    ],
    ids=["not-rebuilt", "stopped", "from-an-irimi-without-release", "used"],
)
def test_an_answer_the_sdk_cannot_use_is_released_before_the_tool_runs(
    monkeypatch, tool, outcome, released
):
    """An answer the SDK cannot use is released, if it came with an id, before the body runs."""
    seen: list[str] = []

    class _Answers:
        def post(self, run_id: str, action: str, doc: Any) -> None:
            seen.append(f"{action} {doc['ran']}")

        def recorded(self, *args: Any) -> RecordedOutcome:
            seen.append("lookup")
            return outcome

        def release(self, run_id: str, answer_id: str) -> None:
            seen.append(f"release {run_id} {answer_id} after {len(_REAL_READS)} reads")

    _replaying_with(monkeypatch, _Answers())
    called = tool("acc_1")
    if inspect.iscoroutine(called):
        asyncio.run(called)
    ran = "recording" if outcome.result == _ONE else "real"
    assert seen == [
        "lookup",
        *[f"release abcd1234abcd1234 {a} after 0 reads" for a in released],
        f"tool-calls {ran}",
    ]


def test_an_async_read_cancelled_while_it_asks_releases_the_answer_once_it_comes(monkeypatch):
    """Cancelled while its lookup waits off the loop, a read releases the answer it then gets.

    Nothing of it runs or is recorded, so a retry finds the recorded body's answers unused."""
    asking, answering = threading.Event(), threading.Event()
    seen: list[str] = []

    class _Slow:
        def post(self, *args: Any) -> None:
            seen.append("tool-calls")

        def recorded(self, *args: Any) -> RecordedOutcome:
            asking.set()
            answering.wait(10)
            return RecordedOutcome(_ONE, None, False, "a1")

        def release(self, run_id: str, answer_id: str) -> None:
            seen.append(f"release {answer_id}")

    async def main() -> None:
        task = asyncio.create_task(balance_async("acc_1"))
        await asyncio.to_thread(asking.wait, 10)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        assert task.cancelled()
        answering.set()

    _replaying_with(monkeypatch, _Slow())
    asyncio.run(main())  # which waits for the lookup's thread to end
    assert seen == ["release a1"]
    assert _REAL_READS == []


def test_an_async_read_cancelled_once_its_answer_came_releases_it(monkeypatch):
    """Cancelled after its lookup came back but before it resumed, a read releases the answer."""
    seen: list[str] = []

    class _Answers:
        def post(self, *args: Any) -> None:
            seen.append("tool-calls")

        def recorded(self, *args: Any) -> RecordedOutcome:
            return RecordedOutcome(_ONE, None, False, "a1")

        def release(self, run_id: str, answer_id: str) -> None:
            seen.append(f"release {answer_id}")

    off_the_loop = runs.off_the_loop

    async def cancelled_once_answered(fn: Callable[..., Any], *args: Any) -> Any:
        if fn is tools._replay_answer:
            fn(*args)
            raise asyncio.CancelledError
        return await off_the_loop(fn, *args)

    _replaying_with(monkeypatch, _Answers())
    monkeypatch.setattr(tools, "off_the_loop", cancelled_once_answered)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(balance_async("acc_1"))
    assert seen == ["release a1"]
    assert _REAL_READS == []


def test_an_async_read_closed_once_its_answer_came_releases_it_inline(monkeypatch):
    """Closed while it waits for its lookup, a read releases a kept answer without awaiting.

    A closed coroutine may not await; one that did would raise `RuntimeError` into the closer."""
    seen: list[str] = []
    answering, kept = threading.Event(), threading.Event()
    keep = tools._Asked.keep

    class _Answers:
        def post(self, *args: Any) -> None:
            seen.append("tool-calls")

        def recorded(self, *args: Any) -> RecordedOutcome:
            answering.wait(10)
            return RecordedOutcome(_ONE, None, False, "a1")

        def release(self, run_id: str, answer_id: str) -> None:
            seen.append(f"release {answer_id}")

    def keeps(asked: Any, run_id: str, answer_id: str | None) -> bool:
        try:
            return keep(asked, run_id, answer_id)
        finally:
            kept.set()

    async def main() -> None:
        called = balance_async("acc_1")
        called.send(None)  # suspended where it waits for the lookup's thread
        answering.set()
        await asyncio.to_thread(kept.wait, 10)
        called.close()

    _replaying_with(monkeypatch, _Answers())
    monkeypatch.setattr(tools._Asked, "keep", keeps)
    asyncio.run(main())
    assert seen == ["release a1"]
    assert _REAL_READS == []


def test_an_inactive_sdk_is_never_told_it_replays(monkeypatch):
    """With the SDK inactive, a leftover `IRIMI_REPLAY_RUN` does not make a replay."""
    monkeypatch.setenv(RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
    assert context.replay_run_id() == "abcd1234abcd1234"
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "0")
    assert context.replay_run_id() is None


class _Answers(http.server.BaseHTTPRequestHandler):
    """Answers every request `status` with `body`, and keeps each one's path and headers."""

    status = 200
    body = b""
    seen: list[tuple[str, dict[str, str]]]

    def do_POST(self) -> None:
        self.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
        self.rfile.read(int(self.headers["content-length"]))
        self.send_response(self.status)
        self.send_header("content-length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


@contextlib.contextmanager
def _answering(monkeypatch, status: int, body: bytes) -> Iterator[list[tuple[str, dict[str, str]]]]:
    """A control endpoint that answers every request `status` with `body`, for a replay's child."""
    seen: list[tuple[str, dict[str, str]]] = []
    handler = type("Handler", (_Answers,), {"status": status, "body": body, "seen": seen})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}).start()
    monkeypatch.setenv(ENGINE_ACTIVE_ENV, "1")
    monkeypatch.setenv(RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(REPLAY_RUN_ENV, "abcd1234abcd1234")
    monkeypatch.setenv(CONTROL_ENV, f"http://127.0.0.1:{server.server_address[1]}/_irimi")
    monkeypatch.setattr(state, "reporter", client.ControlClient())
    try:
        yield seen
    finally:
        server.shutdown()
        server.server_close()


_HIT = {"result": {"account": "acc_1", "balance": 1}, "error": None, "awaited": False}


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"\xff\xfe",
        b"[1]",
        b'{"result": 1}',
        json.dumps({**_HIT, "error": {"type": 1, "message": "x"}}).encode(),
        json.dumps({**_HIT, "awaited": "yes"}).encode(),
        b"[" * 100_000 + b"]" * 100_000,
    ],
)
def test_an_answer_the_sdk_cannot_read_is_a_miss_warned_once(monkeypatch, warnings, body):
    with _answering(monkeypatch, 200, body):
        assert [balance("acc_1"), balance("acc_1")] == [{"account": "acc_1", "balance": 100}] * 2
    said = [w.getMessage() for w in warnings()]
    assert len([w for w in said if "look up a recorded call of tool db.balance" in w]) == 1


def _refused(message: str) -> bytes:
    return json.dumps({"error": {"type": "irimi_control_refused", "message": message}}).encode()


def _lookup_warnings(warnings: Callable[[], Any]) -> list[str]:
    return [w.getMessage() for w in warnings() if "look up a recorded call" in w.getMessage()]


@pytest.mark.parametrize(
    "body",
    [
        _refused("no control route '/_irimi/runs/abcd1234abcd1234/tool-calls/recorded'"),
        b"<html>Not Found</html>",
        b'{"error": "no recorded call"}',
        b"[]",
        b"",
    ],
    ids=["no-route", "not-json", "not-irimi-s-error", "not-an-object", "empty"],
)
def test_a_404_that_is_not_the_endpoint_s_miss_runs_the_tool_and_is_warned_once(
    monkeypatch, warnings, body
):
    """A 404 for a route this irimi does not have, as an SDK newer than it gets, is no miss.

    Taken for one, every read tool of every replay would run for real with nothing said."""
    with _answering(monkeypatch, 404, body):
        assert [balance("acc_1"), balance("acc_1")] == [{"account": "acc_1", "balance": 100}] * 2
    [said] = _lookup_warnings(warnings)
    assert "(rejected: HTTP 404: " in said and said.endswith(
        "; the tool runs for real; further failures of this kind are not logged"
    )


def test_the_endpoint_s_404_for_a_miss_is_silent_whoever_sends_it(monkeypatch, warnings):
    with _answering(monkeypatch, 404, _refused(NO_RECORDED_CALL)):
        assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    assert _lookup_warnings(warnings) == []


def test_a_release_is_posted_beside_the_lookup_and_said_by_no_warning(monkeypatch, warnings):
    body = json.dumps({**_HIT, "result": _GONE, "answer_id": "a1"}).encode()
    with _answering(monkeypatch, 200, body) as seen:
        assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    route = "/_irimi/runs/abcd1234abcd1234/tool-calls"
    assert [path for path, _ in seen] == [f"{route}/recorded", f"{route}/recorded/release", route]
    assert warnings() == []


def test_a_release_that_fails_is_warned_of_once(monkeypatch, warnings, refused_port):
    """A release irimi does not get is warned of once; the breaker it opens skips the next."""
    monkeypatch.setenv(CONTROL_ENV, f"http://127.0.0.1:{refused_port}/_irimi")
    reporter = client.ControlClient()
    reporter.release("abcd1234abcd1234", "a1")
    reporter.release("abcd1234abcd1234", "a2")
    [said] = [w.getMessage() for w in warnings()]
    assert said.startswith(
        "irimi: could not give back a recorded answer the tool could not use in run "
        "abcd1234abcd1234 (unreachable: "
    )
    assert said.endswith(
        "; the requests its body makes may miss the recording; irimi is not asked again for 30s; "
        "further failures of this kind are not logged"
    )


def test_an_answer_past_the_bound_is_a_miss_and_is_never_read_whole(monkeypatch, warnings):
    """An answer larger than any recorded call is a miss, and is not read whole."""
    monkeypatch.setattr(client, "MAX_ANSWER", 1000, raising=False)
    body = json.dumps({**_HIT, "result": {"account": "acc_1", "pad": "x" * 2000}}).encode()
    with _answering(monkeypatch, 200, body):
        assert balance("acc_1") == {"account": "acc_1", "balance": 100}
    [said] = [w.getMessage() for w in warnings() if "look up" in w.getMessage()]
    assert "the answer is past 1000 bytes" in said


def test_a_lookup_carries_no_run_header_and_never_goes_through_a_proxy(monkeypatch, refused_port):
    """A lookup goes unlabelled, straight to the endpoint, whatever `HTTP_PROXY` says."""
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{refused_port}")
    with (
        _answering(monkeypatch, 200, json.dumps(_HIT).encode()) as seen,
        sdk.run("labelled", inputs={}),  # which instruments the HTTP clients
    ):
        assert balance("acc_1") == {"account": "acc_1", "balance": 1}
    [lookup] = [h for path, h in seen if path.endswith(RECORDED_ACTION)]
    assert RUN_HEADER not in lookup


class Ledger:
    """Read tools on a method, a static method and a class method, as W3's ledger has."""

    def __init__(self, owner: str) -> None:
        self.owner = owner

    @sdk.read_tool(name="ledger.entry")
    def entry(self, account: str) -> dict[str, Any]:
        _real(account)
        return {"owner": self.owner, "account": account}

    @staticmethod
    @sdk.read_tool(name="ledger.rate")
    def rate(account: str) -> int:
        _real(account)
        return len(_REAL_READS)

    @sdk.read_tool(name="ledger.kind")
    @classmethod
    def kind(cls, account: str) -> str:
        _real(account)
        return f"{cls.__name__}:{len(_REAL_READS)}"


def test_method_tools_and_a_tool_on_a_thread_are_answered_from_the_recording(irimi):
    """A method tool matches without its receiver, and a propagated thread asks from its run."""

    def script() -> list[Any]:
        got: list[Any] = []
        ledger = Ledger("first")

        def ask() -> None:
            got.append(balance("acc_t"))

        worker = threading.Thread(target=sdk.propagate(ask))
        worker.start()
        worker.join()
        return [ledger.entry("acc_m"), Ledger.rate("acc_s"), Ledger.kind("acc_c"), *got]

    run_id = irimi.record(script)
    _FORBIDDEN.update({"acc_m", "acc_s", "acc_c", "acc_t"})
    result, calls = irimi.replay(run_id, script)
    assert result == [
        {"owner": "first", "account": "acc_m"},
        3,
        "Ledger:4",
        {"account": "acc_t", "balance": 100},
    ]
    assert sorted((c.name, c.ran) for c in calls) == [
        ("db.balance", "recording"),
        ("ledger.entry", "recording"),
        ("ledger.kind", "recording"),
        ("ledger.rate", "recording"),
    ]
    assert {c.name: c.args for c in calls}["ledger.entry"] == {"account": "acc_m"}
