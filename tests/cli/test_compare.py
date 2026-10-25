"""`irimi compare`: two stored runs' writes side by side.

Runs are stored from hand-made events and read back through the real command and shipped maps."""

import dataclasses
import functools
import json
import random
import unicodedata

import pytest

from irimi import servicemaps
from irimi.cli import main
from irimi.cli.compose import maps_for_stored_runs
from irimi.core import exitcodes
from irimi.core.exchange import Exchange, Flag, Precondition, Request, Response
from irimi.protocol import trace
from irimi.protocol.trace import ErrorInfo, Event, RunRecord, StoredRun, ToolCall, Trigger
from irimi.record import redact
from irimi.record.store.reader import StoreReader
from irimi.record.store.writer import DirectoryStore
from irimi.replay import compare
from irimi.replay.index import compared_body
from irimi.report.model import RunView
from irimi.report.summary import summary_lines
from irimi.servicemaps import MapError
from tests.support import builders
from tests.support.builders import FORM_HEADER

AT = 1_700_000_000.0
FORM = (FORM_HEADER,)
TICKET: dict[str, trace.JSONValue] = {"ticket": "T-1"}
HEADER = "irimi compare · a vs b"
LABELS = [
    "  A  refund_ticket  agent:refund_ticket  agent 1.0",
    "  B  refund_ticket  agent:refund_ticket  agent 1.0",
]
REFUND = "○ stripe  refund $49.00 on ch_1  faked; checked against live state: would succeed"
SENT_ALIKE = "(both sent the same; only the outcome differs)"
TOOL = "○ tool  db.mark_refunded  fake ran instead"


def _refund(amount: int = 4900, **changes) -> Exchange:
    """A refund irimi faked after its precondition check passed; `REFUND` prints it at 4900."""
    return builders.refund_exchange(amount, **changes)


def _post(text: str) -> Exchange:
    body = json.dumps({"channel": "C1", "text": text}).encode()
    headers = (("content-type", "application/json"),)
    return Exchange(
        request=Request(
            "POST", "https", "slack.com", 443, "/api/chat.postMessage", "", headers, body
        ),
        response=Response(200, (), b'{"ok":true}'),
        service="slack",
        operation="chat.postMessage",
        kind="write",
        answered_by="fake-L1",
        run_id="",
    )


def _read(path: str, answered: bytes = b"{}") -> Exchange:
    return Exchange(
        request=Request("GET", "https", "api.stripe.com", 443, path, "", (), b""),
        response=Response(200, (), answered),
        service="stripe",
        operation="charges.retrieve",
        kind="read",
        answered_by="live",
        run_id="",
    )


def _llm(prompt: str) -> Exchange:
    body = json.dumps({"messages": [{"role": "user", "content": prompt}]}).encode()
    headers = (("content-type", "application/json"),)
    return Exchange(
        request=Request(
            "POST", "https", "api.anthropic.com", 443, "/v1/messages", "", headers, body
        ),
        response=Response(200, (), b"{}"),
        service="anthropic",
        operation="messages.create",
        kind="llm",
        answered_by="live",
        run_id="",
    )


def _tool(name: str = "db.mark_refunded", kind: str = "write", ran: str = "shadow") -> ToolCall:
    return builders.tool_call(
        tool_call_id="tc", run_id="", name=name, kind=kind, ran=ran, started_at=AT, ended_at=AT + 1
    )


def _record(run_id: str, args: trace.JSONValue = TICKET, **changes) -> RunRecord:
    """An SDK run of `refund_ticket` that started at `AT` and ended a second later."""
    end = trace.RunEnd(changes.pop("ended_at", AT + 1), "ok", None, None)
    record = builders.run_record(
        run_id,
        AT,
        attribution="sdk",
        trigger=Trigger("refund_ticket", "agent:refund_ticket", args, True),
        agent_version="1.0",
        sdk_version="0.0.0",
        end=end,
    )
    return dataclasses.replace(record, **changes)


def _store(home, runs: dict[str, tuple[RunRecord, list[Event]]]) -> None:
    """Each run's record and its events, in `seq` order, in `home`'s default store."""
    s = DirectoryStore(home / "store", redact.load_key(home))
    for run_id, (record, events) in runs.items():
        s.start_run(record)
        for event in events:
            if isinstance(event, ToolCall):
                s.record_tool_call(dataclasses.replace(event, run_id=run_id))
            else:
                assert isinstance(event, Exchange)
                s.record(dataclasses.replace(event, run_id=run_id))
    s.close()


def _run(events: list[Event]) -> StoredRun:
    """A run as `StoreReader.load_run` returns one, never stored."""
    return StoredRun(_record("r"), events)


def _compare(home, capfd, a: list[Event], b: list[Event], **b_record) -> tuple[int, list[str]]:
    """Return `irimi compare a b`'s exit code and the lines after its header.

    The two runs hold `a`'s and `b`'s events. Nothing may go to stderr."""
    _store(home, {"a": (_record("a"), a), "b": (_record("b", **b_record), b)})
    code = main(["compare", "a", "b"])
    out, err = capfd.readouterr()
    assert err == ""
    lines = out.splitlines()
    assert lines[0] == HEADER
    return code, lines[1:]


def test_two_runs_that_wrote_the_same_print_every_write_as_same_and_exit_0(home, capfd):
    events: list[Event] = [_read("/v1/charges/ch_1"), _refund(), _tool()]
    assert _compare(home, capfd, events, events) == (
        0,
        [
            *LABELS,
            "",
            f"  = {REFUND}",
            f"  = {TOOL}",
            "",
            "  2 same · 0 changed · 0 only in A · 0 only in B",
        ],
    )


def test_a_refund_of_another_amount_is_one_write_changed(home, capfd):
    code, lines = _compare(home, capfd, [_refund(), _tool()], [_refund(2450), _tool()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ~ A {REFUND}",
            "    B ○ stripe  refund $24.50 on ch_1  faked; checked against live state: "
            "would succeed",
            f"  = {TOOL}",
            "",
            "  1 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def _update(body: bytes) -> Exchange:
    """A customer update irimi faked: `update customer {customer}` names no body field."""
    path = "/v1/customers/cus_1"
    return Exchange(
        request=Request("POST", "https", "api.stripe.com", 443, path, "", FORM, body),
        response=Response(200, (), b"{}"),
        service="stripe",
        operation="customers.update",
        kind="write",
        answered_by="fake-L1",
        run_id="",
    )


UPDATE = "○ stripe  update customer cus_1  faked; not checked"


def test_two_updates_that_print_alike_but_send_other_fields_are_changed_and_say_which(home, capfd):
    """Two updates whose map sentence names only the customer are compared by their fields."""
    a: list[Event] = [_update(b"email=alice%40x.com")]
    b: list[Event] = [_update(b"metadata[blocked]=true&email=")]
    code, lines = _compare(home, capfd, a, b)
    assert (code, lines[3:]) == (
        1,
        [
            f"  ~ A {UPDATE}",
            f"    B {UPDATE}",
            '      body.email: "alice@x.com" -> ""',
            '      body.metadata: (absent) -> {"blocked":"true"}',
            "",
            "  0 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def test_a_refund_whose_reason_alone_differs_is_changed(home, capfd):
    a = _refund()
    b = dataclasses.replace(
        a, request=dataclasses.replace(a.request, body=a.request.body + b"&reason=fraudulent")
    )
    code, lines = _compare(home, capfd, [a], [b])
    assert (code, lines[3:6]) == (
        1,
        [f"  ~ A {REFUND}", f"    B {REFUND}", '      body.reason: (absent) -> "fraudulent"'],
    )


def test_an_ignored_field_is_not_compared_and_any_other_is():
    """A field in the route's `compare_ignores:` is left out, as a replay's match leaves it out.

    The test map is the shipped one with `nonce` ignored on the refund route."""
    index = servicemaps.MapIndex(
        tuple(
            dataclasses.replace(
                sm,
                routes=tuple(
                    dataclasses.replace(route, compare_ignores=("nonce",))
                    if route.operation == "refunds.create"
                    else route
                    for route in sm.routes
                ),
            )
            for sm in servicemaps.loader.load_shipped()
        )
    )

    def refund(body: bytes) -> Exchange:
        request = dataclasses.replace(_refund().request, body=body)
        return dataclasses.replace(_refund(), request=request)

    one = refund(b"charge=ch_1&amount=4900&currency=usd&nonce=n-1")
    other = refund(b"currency=usd&nonce=n-2&amount=4900&charge=ch_1")
    assert compare.compare_runs(_run([one]), _run([other]), index).exit_code == exitcodes.OK
    reason = refund(b"charge=ch_1&amount=4900&currency=usd&nonce=n-1&reason=duplicate")
    assert compare.compare_runs(_run([one]), _run([reason]), index).exit_code == exitcodes.DIFFERENT


def test_a_write_answered_otherwise_is_changed_though_its_line_reads_the_same():
    """What irimi did with a write is compared too: here, the currency its check read found.

    The target and a refusal's reasons are compared the same way."""
    index = servicemaps.load()
    a = dataclasses.replace(_update(b"email=a%40x.com"), precondition=Precondition(currency="usd"))
    b = dataclasses.replace(a, precondition=Precondition(currency="eur"))
    assert compare.compare_runs(_run([a]), _run([b]), index).lines() == [
        f"  ~ A {UPDATE}",
        f"    B {UPDATE}",
        f"      {SENT_ALIKE}",
        '      currency: "usd" -> "eur"',
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


def test_a_field_diff_shows_five_fields_each_cut_to_a_readable_length():
    many = "&".join(f"metadata[k{n}]={n}" for n in range(3))
    a = _update(f"name={'x' * 100}&email=a&phone=p1&{many}".encode())
    added = "description=d&invoice_prefix=P&balance=5"
    b = _update(f"name={'y' * 100}&email=b&phone=p2&{added}&{many}".encode())
    lines = compare.compare_runs(_run([a]), _run([b]), servicemaps.load()).lines()
    # In name order, as a body's fields are compared; a form integer is a number.
    assert lines[2:8] == [
        "      body.balance: (absent) -> 5",
        '      body.description: (absent) -> "d"',
        '      body.email: "a" -> "b"',
        '      body.invoice_prefix: (absent) -> "P"',
        f'      body.name: "{"x" * 59}… -> "{"y" * 59}…',
        "      and 1 more",
    ]


def test_two_stand_ins_given_other_args_are_changed_and_print_the_args():
    a = dataclasses.replace(_tool(), args={"ticket": "T-1"})
    b = dataclasses.replace(_tool(), args={"ticket": "T-2"})
    assert compare.compare_runs(_run([a]), _run([b]), None).lines() == [
        f"  ~ A {TOOL}",
        f"    B {TOOL}",
        '      args.ticket: "T-1" -> "T-2"',
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]
    again = dataclasses.replace(_tool(), args={"ticket": "T-1"})
    assert compare.compare_runs(_run([a]), _run([again]), None).exit_code == exitcodes.OK


def test_an_update_to_another_customer_is_changed_by_the_object_its_path_names():
    other = dataclasses.replace(
        _update(b"email=a"),
        request=dataclasses.replace(
            _update(b"").request, path="/v1/customers/cus_2", body=b"email=a"
        ),
    )
    lines = compare.compare_runs(_run([_update(b"email=a")]), _run([other]), servicemaps.load())
    assert lines.lines()[:2] == [
        f"  ~ A {UPDATE}",
        "    B ○ stripe  update customer cus_2  faked; not checked",
    ]


def test_a_webhook_s_redacted_path_is_not_compared_and_its_text_is():
    """A webhook's redacted path is left out of the comparison, and its text is compared.

    The path is redacted with each install's own key, so two installs spell one webhook apart."""

    def hook(path: str, text: str) -> Exchange:
        body = json.dumps({"text": text}).encode()
        headers = (("content-type", "application/json"),)
        return Exchange(
            request=Request("POST", "https", "hooks.slack.com", 443, path, "", headers, body),
            response=Response(200, (), b"ok"),
            service="slack",
            operation="incoming_webhook",
            kind="write",
            answered_by="fake-L0",
            run_id="",
        )

    index = servicemaps.load()
    a, b = hook("/<redacted:aaaa>", "hi"), hook("/<redacted:bbbb>", "hi")
    assert compare.compare_runs(_run([a]), _run([b]), index).exit_code == exitcodes.OK
    c = hook("/<redacted:aaaa>", "bye")
    assert compare.compare_runs(_run([a]), _run([c]), index).exit_code == exitcodes.DIFFERENT


def test_an_llm_body_is_compared_less_who_asked_and_how_as_a_replay_matches_it():
    """An llm body is compared less its route's `compare_ignores:` and every `cache_control`."""
    asked = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    noisy = {
        **asked,
        "metadata": {"user_id": "u-1"},
        "stream": True,
        "user": "u-1",
        "messages": [{"role": "user", "content": "hi", "cache_control": {"type": "ephemeral"}}],
    }
    request = _llm("hi").request
    body = dataclasses.replace(request, body=json.dumps(noisy).encode())
    found = servicemaps.load().route_for(request.host, request.method, request.path)
    assert found is not None
    assert compared_body(body, "llm", found[1]) == asked


def test_a_slack_post_only_b_made_is_one_write_added(home, capfd):
    code, lines = _compare(home, capfd, [_refund()], [_refund(), _post("refunded T-1")])
    assert (code, lines[3:]) == (
        1,
        [
            f"  = {REFUND}",
            '  + ○ slack  post to #C1: "refunded T-1"  faked; not checked',
            "",
            "  1 same · 0 changed · 0 only in A · 1 only in B",
        ],
    )


def test_a_write_tool_b_dropped_is_one_write_only_in_a(home, capfd):
    code, lines = _compare(home, capfd, [_refund(), _tool()], [_refund()])
    assert (code, lines[3:]) == (
        1,
        [f"  = {REFUND}", f"  - {TOOL}", "", "  1 same · 0 changed · 1 only in A · 0 only in B"],
    )


def test_a_refund_l3_rejected_in_b_is_the_same_write_changed_and_shows_its_mark(home, capfd):
    rejected = _refund(9800, precondition=Precondition("rejected", "amount_too_large"))
    code, lines = _compare(home, capfd, [_refund()], [rejected])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ~ A {REFUND}",
            "    B ✗ stripe  refund $98.00 on ch_1  faked; would fail: amount_too_large",
            "",
            "  0 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def test_a_refund_irimi_could_not_check_in_b_says_both_sent_the_same_and_what_irimi_did():
    """B's refund prints otherwise, as irimi could not check it, though the agent sent the same.

    It is still changed and exits 1: a check irimi could not make again is a difference."""
    sent = builders.request(
        method="POST", path="/v1/refunds", headers=FORM, body=b"charge=ch_1&amount=4900"
    )
    checked = _refund(request=sent, precondition=Precondition("passed", currency="usd"))
    unchecked = _refund(
        request=sent, answered_by="fake-L2", precondition=Precondition("not_evaluable")
    )
    comparison = compare.compare_runs(_run([checked]), _run([unchecked]), servicemaps.load())
    assert (comparison.exit_code, comparison.lines()) == (
        exitcodes.DIFFERENT,
        [
            f"  ~ A {REFUND}",
            "    B ○ stripe  refund 4900 (minor units, currency unknown) on ch_1  faked; could not "
            "check: irimi made no check read",
            f"      {SENT_ALIKE}",
            '      answered by: "fake-L1" -> "fake-L2"',
            '      currency: "usd" -> (absent)',
            '      precondition: "passed" -> "not_evaluable"',
            "",
            "  0 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def test_a_stand_in_that_raised_in_b_given_the_same_args_says_both_sent_the_same():
    raised = dataclasses.replace(
        _tool(), error=ErrorInfo("builtins.LookupError", "no such account")
    )
    assert compare.compare_runs(_run([_tool()]), _run([raised]), None).lines() == [
        f"  ~ A {TOOL}",
        "    B ○ tool  db.mark_refunded  fake raised builtins.LookupError",
        f"      {SENT_ALIKE}",
        '      raised: (absent) -> "builtins.LookupError"',
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


def test_a_pair_whose_data_json_cannot_hold_is_never_said_to_have_sent_the_same():
    """Two writes whose fields JSON cannot hold equal nothing, so they never sent the same."""
    a = compare.Action((compare.TOOL_KEY, "db.x"), "x", fields=None)
    b = compare.Action((compare.TOOL_KEY, "db.x"), "y", fields=None)
    assert compare.Comparison(compare.align([a], [b])).lines() == [
        "  ~ A x",
        "    B y",
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


@pytest.mark.parametrize(
    "sent_to",
    [{"query": "expand[]=charge"}, {"headers": (*FORM, ("stripe-account", "acct_2"))}],
    ids=["query", "scope"],
)
def test_a_refund_sent_with_another_query_or_account_is_never_said_to_have_sent_the_same(sent_to):
    """A write's query and scope headers are part of what it sent, as its body is."""
    a = _refund()
    b = _refund(
        request=dataclasses.replace(a.request, **sent_to),
        precondition=Precondition("rejected", "charge_already_refunded"),
    )
    assert compare.compare_runs(_run([a]), _run([b]), servicemaps.load()).lines() == [
        f"  ~ A {REFUND}",
        "    B ✗ stripe  refund $49.00 on ch_1  faked; would fail: charge_already_refunded",
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


def test_the_line_that_says_both_sent_the_same_is_not_one_of_the_five_parts_shown():
    names = ("answered by", "currency", "flags", "precondition", "rejection code", "target")
    a = compare.Action((compare.TOOL_KEY, "db.x"), "x", outcome=tuple((n, '"a"') for n in names))
    b = compare.Action((compare.TOOL_KEY, "db.x"), "y", outcome=tuple((n, '"b"') for n in names))
    assert compare.Comparison(compare.align([a], [b])).lines() == [
        "  ~ A x",
        "    B y",
        f"      {SENT_ALIKE}",
        *(f'      {name}: "a" -> "b"' for name in names[:5]),
        "      and 1 more",
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


def test_a_second_refused_refund_is_the_write_added_not_the_first(home, capfd):
    """Equal writes pair first, so B's refused second refund is the one marked `+`."""
    refused = _refund(precondition=Precondition("rejected", "charge_already_refunded"))
    code, lines = _compare(home, capfd, [_refund(), _tool()], [_refund(), refused, _tool()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  = {REFUND}",
            "  + ✗ stripe  refund $49.00 on ch_1  faked; would fail: charge_already_refunded",
            f"  = {TOOL}",
            "",
            "  2 same · 0 changed · 0 only in A · 1 only in B",
        ],
    )


@pytest.mark.parametrize("repeated", ["a", "b"])
def test_a_changed_write_before_a_repeated_one_is_one_write_changed(home, capfd, repeated):
    """A refund of another amount, then one both runs made, against that refund made twice.

    Pairing the first of the two identical refunds instead leaves a refund only in each run."""
    other = "○ stripe  refund $24.00 on ch_1  faked; checked against live state: would succeed"
    twice: list[Event] = [_refund(), _refund()]
    changed: list[Event] = [_refund(2400), _refund()]
    a, b = (twice, changed) if repeated == "a" else (changed, twice)
    first = (REFUND, other) if repeated == "a" else (other, REFUND)
    code, lines = _compare(home, capfd, a, b)
    assert (code, lines[3:]) == (
        1,
        [
            f"  ~ A {first[0]}",
            f"    B {first[1]}",
            f"  = {REFUND}",
            "",
            "  1 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def test_reads_llm_calls_read_tools_real_tools_and_a_replayed_retry_are_not_writes(home, capfd):
    a: list[Event] = [_read("/v1/charges/ch_1"), _llm("refund it"), _refund(), _tool()]
    replayed = _refund(flags=(Flag.IDEMPOTENT_REPLAY,))
    b: list[Event] = [
        _llm("refund it, politely"),
        _read("/v1/charges/ch_1", b'{"amount": 1}'),
        _read("/v1/customers/cus_1"),
        _tool("db.lookup", kind="read", ran="real"),
        # A write tool the SDK ran for real is in no summary: it is not a faked write.
        _tool("db.archive", ran="real"),
        _refund(),
        replayed,
        _tool(),
    ]
    code, lines = _compare(home, capfd, a, b)
    assert (code, lines[3:]) == (
        0,
        [f"  = {REFUND}", f"  = {TOOL}", "", "  2 same · 0 changed · 0 only in A · 0 only in B"],
    )


def test_a_delegated_write_is_a_write_and_prints_where_it_went(home, capfd):
    """The summary prints a write a target answered, so it is compared too."""
    delegated = _refund(
        answered_by="delegated", target="http://127.0.0.1:9999", precondition=Precondition()
    )
    code, lines = _compare(home, capfd, [_refund()], [delegated])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ~ A {REFUND}",
            "    B ○ stripe  refund $49.00 on ch_1  sent to target 127.0.0.1:9999",
            f"      {SENT_ALIKE}",
            '      answered by: "fake-L1" -> "delegated"',
            '      precondition: "passed" -> (absent)',
            '      target: (absent) -> "http://127.0.0.1:9999"',
            "",
            "  0 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )


def test_two_writes_whose_bodies_were_cut_are_not_compared_and_not_called_the_same(home, capfd):
    cut = _refund(2450, flags=(Flag.BODY_TRUNCATED,))
    code, lines = _compare(home, capfd, [_refund(), _tool()], [cut, _tool()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ? A {REFUND}",
            "    B ○ stripe  refund $24.50 on ch_1  faked; checked against live state: "
            "would succeed",
            f"  = {TOOL}",
            "",
            "  1 same · 0 changed · 0 only in A · 0 only in B · 1 not compared "
            "(a write was not stored whole)",
        ],
    )


def test_a_cut_pair_whose_lines_read_the_same_is_still_not_compared_and_exits_1(home, capfd):
    """A pair with either side cut is `?` whatever its lines say.

    A cut body prints one line for different requests, so two cut refunds can print alike."""
    cut = _refund(flags=(Flag.BODY_TRUNCATED,))
    code, lines = _compare(home, capfd, [_refund(), _tool()], [cut, _tool()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ? A {REFUND}",
            f"    B {REFUND}",
            f"  = {TOOL}",
            "",
            "  1 same · 0 changed · 0 only in A · 0 only in B · 1 not compared "
            "(a write was not stored whole)",
        ],
    )
    # Nor is a cut write the same as itself: a run compared with itself says so.
    _store(home, {"c": (_record("c"), [cut, _tool()])})
    assert main(["compare", "c", "c"]) == 1
    assert capfd.readouterr().out.splitlines()[4:] == [
        f"  ? A {REFUND}",
        f"    B {REFUND}",
        f"  = {TOOL}",
        "",
        "  1 same · 0 changed · 0 only in A · 0 only in B · 1 not compared "
        "(a write was not stored whole)",
    ]


def _unredactable(text: str) -> Exchange:
    """A post whose JSON names `text` twice, so the store cannot redact its body and flags it."""
    post = _post(text)
    body = b'{"channel": "C1", "text": "", "text": ' + json.dumps(text).encode() + b"}"
    return dataclasses.replace(post, request=dataclasses.replace(post.request, body=body))


def test_two_posts_irimi_could_not_redact_are_not_compared_though_their_lines_read_the_same(
    home, capfd
):
    """A write stored as `<redaction-failed>` is `?`, as a cut one is: its body says nothing.

    The two posts' texts differ, and a run's post is `?` compared with itself too."""
    a, b = _unredactable("deploy started"), _unredactable("deploy finished")
    unknown = '○ slack  post to #?: "?"  faked; not checked'
    not_compared = (
        "  0 same · 0 changed · 0 only in A · 0 only in B · 1 not compared "
        "(a write was not stored whole)"
    )
    code, lines = _compare(home, capfd, [a, _tool()], [b, _tool()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  ? A {unknown}",
            f"    B {unknown}",
            f"  = {TOOL}",
            "",
            not_compared.replace("  0 same", "  1 same"),
        ],
    )
    [stored, _] = StoreReader(home / "store").load_run("b").events
    assert isinstance(stored, Exchange) and stored.flags == (Flag.REDACTION_FAILED,)
    assert main(["compare", "b", "b"]) == 1
    assert capfd.readouterr().out.splitlines()[4:] == [
        f"  ? A {unknown}",
        f"    B {unknown}",
        f"  = {TOOL}",
        "",
        not_compared.replace("  0 same", "  1 same"),
    ]


@pytest.mark.parametrize(
    "unredacted",
    [{"args": redact.REDACTION_FAILED}, {"error": ErrorInfo(redact.REDACTION_FAILED, "boom")}],
    ids=["args", "error-type"],
)
def test_a_stand_in_whose_args_or_error_irimi_could_not_redact_is_not_compared(unredacted):
    """A tool call's args or error type stored as `<redaction-failed>` say nothing to compare."""
    tool = dataclasses.replace(_tool(), **unredacted)
    comparison = compare.compare_runs(_run([tool]), _run([tool]), None)
    assert (comparison.exit_code, comparison.lines()[-1]) == (
        exitcodes.DIFFERENT,
        "  0 same · 0 changed · 0 only in A · 0 only in B · 1 not compared "
        "(a write was not stored whole)",
    )


def test_a_run_whose_last_event_a_crash_cut_off_says_so_and_is_never_the_same(home, capfd):
    """The store reads B without its half-written last line, which may have been a write.

    So compare says so under the header and exits 1, though every write it read is the same."""
    _store(home, {"a": (_record("a"), [_refund()]), "b": (_record("b"), [_refund()])})
    with open(home / "store" / "runs" / "b" / "events.jsonl", "a") as f:
        f.write('{"seq": 2, "type": "exchange", "run_id": "b", "servi')
    assert main(["compare", "a", "b"]) == 1
    assert capfd.readouterr().out.splitlines() == [
        HEADER,
        *LABELS,
        "  B's last event was cut off when stored, so it is not compared",
        "",
        f"  = {REFUND}",
        "",
        "  1 same · 0 changed · 0 only in A · 0 only in B",
    ]
    assert main(["compare", "b", "b"]) == 1
    assert capfd.readouterr().out.splitlines()[3:6] == [
        "  A's last event was cut off when stored, so it is not compared",
        "  B's last event was cut off when stored, so it is not compared",
        "",
    ]
    assert main(["compare", "a", "a"]) == 0


def test_a_run_the_store_dropped_events_of_says_so_and_is_never_the_same(home, capfd):
    """A dropped event may have been a write too, so compare says so and exits 1.

    A run with a last event cut off as well says both, in that order."""
    _store(home, {"a": (_record("a"), [_refund()]), "b": (_record("b"), [_refund()])})
    # The store counts its own drops, so the record is rewritten to say three.
    (home / "store" / "runs" / "b" / "run.json").write_text(
        json.dumps(trace.run_to_json(_record("b", dropped_events=3)))
    )
    assert main(["compare", "a", "b"]) == 1
    assert capfd.readouterr().out.splitlines()[3:7] == [
        "  the store dropped 3 of B's events, which are not compared",
        "",
        f"  = {REFUND}",
        "",
    ]
    with open(home / "store" / "runs" / "b" / "events.jsonl", "a") as f:
        f.write('{"seq": 2, "ty')
    assert main(["compare", "a", "b"]) == 1
    assert capfd.readouterr().out.splitlines()[3:6] == [
        "  the store dropped 3 of B's events, which are not compared",
        "  B's last event was cut off when stored, so it is not compared",
        "",
    ]


def test_a_cut_write_no_write_of_its_key_pairs_with_is_only_in_its_run(home, capfd):
    cut = _post("hi")
    cut = dataclasses.replace(cut, flags=(Flag.BODY_TRUNCATED,))
    code, lines = _compare(home, capfd, [_refund(), cut], [_refund()])
    assert (code, lines[3:]) == (
        1,
        [
            f"  = {REFUND}",
            '  - ○ slack  post to #C1: "hi"  faked; not checked',
            "",
            "  1 same · 0 changed · 1 only in A · 0 only in B",
        ],
    )


def test_runs_that_wrote_nothing_print_only_the_totals_and_exit_0(home, capfd):
    code, lines = _compare(home, capfd, [_read("/v1/charges/ch_1")], [])
    assert (code, lines) == (0, [*LABELS, "", "  0 same · 0 changed · 0 only in A · 0 only in B"])


@pytest.mark.parametrize(
    "args", [{"ticket": "T-2"}, {"ticket": "T-1", "n": 1}, {"ticket": True}, {"ticket": ["T-1"]}]
)
def test_triggers_given_other_args_say_so_under_the_labels(home, capfd, args):
    _, lines = _compare(home, capfd, [_refund()], [_refund()], args=args)
    assert lines[:4] == [*LABELS, "  (the triggers' args differ)", ""]


def test_args_are_compared_as_json_so_true_is_not_1_and_key_order_is_nothing():
    one, true = _record("a", args={"n": 1, "m": 2}), _record("b", args={"n": True, "m": 2})
    assert compare.header_lines(one, true)[3:] == ["  (the triggers' args differ)"]
    assert compare.header_lines(one, _record("b", args={"m": 2, "n": 1}))[3:] == []


def test_args_nested_deeper_than_json_writes_are_called_different_and_never_raise():
    """Args a million deep, past what `json.dumps` writes, compare as different."""
    deep: trace.JSONValue = []
    for _ in range(1_000_000):
        deep = [deep]
    a, b = _record("a", args=deep), _record("b", args=deep)
    assert compare.header_lines(a, b)[3:] == ["  (the triggers' args differ)"]


def test_a_write_s_text_is_escaped_so_one_write_is_one_line_and_printing_never_raises(home, capfd):
    """A post's text is escaped: newlines, escape sequences and lone surrogates.

    Unescaped, a newline would split the row and a lone surrogate would raise out of `print`."""
    code, lines = _compare(home, capfd, [_post("hi")], [_post("hi\nthere\x1b[31m\ud800")])
    assert (code, lines[3:5]) == (
        1,
        [
            '  ~ A ○ slack  post to #C1: "hi"  faked; not checked',
            '    B ○ slack  post to #C1: "hi\\nthere\\x1b[31m\\ud800"  faked; not checked',
        ],
    )


def test_a_tool_never_lines_up_with_an_exchange_of_a_service_named_tool(home, capfd):
    """A write of a service named `tool` never pairs with a tool call of its operation's name."""
    write = dataclasses.replace(_refund(), service="tool", operation="db.mark_refunded")
    code, lines = _compare(home, capfd, [write], [_tool()])
    assert (code, [line[:3] for line in lines[3:5]]) == (1, ["  -", "  +"])


def test_a_label_leaves_out_what_the_run_did_not_record(home, capfd):
    _store(
        home,
        {
            "a": (_record("a", trigger=None, agent_version=None, attribution="process"), []),
            "b": (_record("b", trigger=Trigger("t\nx", None, {"n": 1}, False)), []),
        },
    )
    assert main(["compare", "a", "b"]) == 0
    assert capfd.readouterr().out.splitlines()[1:4] == [
        "  A",
        "  B  t\\nx  agent 1.0",
        "  (the triggers' args differ)",
    ]


def test_a_label_escapes_the_entrypoint_and_the_agent_version_too(home, capfd):
    """The entrypoint and agent version are escaped as `runs show` escapes them."""
    trigger = Trigger("t", "mod:f\x1b[2J", {"n": 1}, False)
    _store(
        home,
        {
            "a": (_record("a", trigger=trigger, agent_version="1.0\nB  forged"), []),
            "b": (_record("b", trigger=trigger, agent_version="\ud800"), []),
        },
    )
    assert main(["compare", "a", "b"]) == 0
    assert capfd.readouterr().out.splitlines()[1:4] == [
        "  A  t  mod:f\\x1b[2J  agent 1.0\\nB  forged",
        "  B  t  mod:f\\x1b[2J  agent \\ud800",
        "",
    ]


@pytest.mark.parametrize("missing", ["a", "b"])
def test_an_unknown_run_exits_2_with_the_documented_message(home, capfd, missing):
    present = "b" if missing == "a" else "a"
    _store(home, {present: (_record(present), [])})
    assert main(["compare", "a", "b"]) == exitcodes.ERROR
    out, err = capfd.readouterr()
    assert (out, err) == ("", f"error: no run {missing} in {home / 'store'}\n")


def test_a_damaged_run_exits_2_and_names_it(home, capfd):
    _store(home, {"a": (_record("a"), [_refund()]), "b": (_record("b"), [])})
    for blob in (home / "store" / "blobs").iterdir():
        blob.unlink()
    assert main(["compare", "a", "b"]) == exitcodes.ERROR
    out, err = capfd.readouterr()
    events = home / "store" / "runs" / "a" / "events.jsonl"
    assert out == ""
    assert err.startswith(f"error: run a could not be read: {events}, line 1: blob ")


def test_a_store_named_with_store_is_the_one_read(home, capfd, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    s = DirectoryStore(elsewhere, redact.load_key(home))
    s.start_run(_record("a"))
    s.start_run(_record("b"))
    s.close()
    assert main(["compare", "a", "b", "--store", str(elsewhere)]) == 0
    assert main(["compare", "a", "b"]) == exitcodes.ERROR
    assert capfd.readouterr().err == f"error: no run a in {home / 'store'}\n"


def test_writes_print_as_requests_with_a_warning_when_the_maps_do_not_load(
    home, capfd, monkeypatch
):
    _store(home, {"a": (_record("a"), [_refund()]), "b": (_record("b"), [_refund()])})

    def refuse(**_kwargs):
        raise MapError("broken")

    monkeypatch.setattr("irimi.servicemaps.load", refuse)
    assert main(["compare", "a", "b"]) == 0
    out, err = capfd.readouterr()
    assert err == "warning: maps did not load; writes are shown as requests\n"
    assert out.splitlines()[4] == (
        "  = ○ stripe  POST api.stripe.com/v1/refunds  faked; checked against live state: "
        "would succeed"
    )


def test_an_action_s_text_is_its_summary_line_without_the_indent():
    """The comparison and the summary print one string for one write."""
    run = _run([_refund(), _tool()])
    summary = summary_lines(RunView(run.record, run.events), None)
    assert [f"  {a.text}" for a in compare.actions(run, None)] == [
        line for line in summary if line.startswith("  ○ ")
    ]


def test_a_newline_and_a_typed_backslash_n_print_alike_and_are_still_not_the_same(home, capfd):
    """A newline and a typed `\\n` are changed, and the pair escapes its backslashes to differ.

    Escaping leaves a backslash as it is, so the summary prints both posts as one line."""
    code, lines = _compare(home, capfd, [_post("line1\nline2")], [_post("line1\\nline2")])
    assert (code, lines[3:]) == (
        1,
        [
            '  ~ A ○ slack  post to #C1: "line1\\nline2"  faked; not checked',
            '    B ○ slack  post to #C1: "line1\\\\nline2"  faked; not checked',
            "",
            "  0 same · 1 changed · 0 only in A · 0 only in B",
        ],
    )
    # A tool's name is its key, but the error type its fake raised is only in its line.
    raised: list[Event] = [
        dataclasses.replace(_tool(), error=ErrorInfo(kind, "")) for kind in ("a\nb", "a\\nb")
    ]
    comparison = compare.compare_runs(_run(raised[:1]), _run(raised[1:]), None)
    assert comparison.lines() == [
        "  ~ A ○ tool  db.mark_refunded  fake raised a\\nb",
        "    B ○ tool  db.mark_refunded  fake raised a\\\\nb",
        f"      {SENT_ALIKE}",
        '      raised: "a\\nb" -> "a\\\\nb"',
        "",
        "  0 same · 1 changed · 0 only in A · 0 only in B",
    ]


def test_a_pair_printed_unlike_keeps_the_summary_s_lines_and_a_cut_pair_alike_is_not_escaped():
    """Only a pair that prints alike though it differs escapes its backslashes.

    A pair that prints unlike, or a cut write compared with itself, keeps the summary's lines."""
    index = servicemaps.load()
    pair = compare.compare_runs(_run([_post("a\\b")]), _run([_post("a\\c")]), index)
    assert pair.lines()[:2] == [
        '  ~ A ○ slack  post to #C1: "a\\b"  faked; not checked',
        '    B ○ slack  post to #C1: "a\\c"  faked; not checked',
    ]
    cut = _run([dataclasses.replace(_post("a\\b\n"), flags=(Flag.BODY_TRUNCATED,))])
    assert compare.compare_runs(cut, cut, index).lines()[:2] == [
        '  ? A ○ slack  post to #C1: "a\\b\\n"  faked; not checked',
        '    B ○ slack  post to #C1: "a\\b\\n"  faked; not checked',
    ]


def test_every_write_shape_s_action_is_the_line_the_stored_summary_prints_for_it(home):
    """For every recorded write shape, the actions are the summary's write lines, byte for byte.

    Exchanges come in `seq` order, then tool calls, as the summary prints them."""
    target = "http://127.0.0.1:9"
    # An unclassified write keeps its host as its service and its request as its operation.
    unclassified = _refund(kind="unknown", answered_by="fake-L0", precondition=Precondition())
    unclassified = dataclasses.replace(unclassified, flags=(Flag.UNCLASSIFIED,))
    events: list[Event] = [
        _read("/v1/charges/ch_1"),
        _llm("refund it"),
        _refund(),
        dataclasses.replace(unclassified, service="api.stripe.com", operation="POST /v1/refunds"),
        _refund(answered_by="delegated", target=target, precondition=Precondition()),
        _refund(
            answered_by="delegated",
            target=target,
            precondition=Precondition(),
            response=None,
            flags=(Flag.TARGET_FAILED,),
        ),
        # A body that decoded past the cap: the decision failed and its 502 is recorded.
        dataclasses.replace(
            unclassified,
            service="api.stripe.com",
            operation="",
            flags=(Flag.UNCLASSIFIED, Flag.DECISION_FAILED, Flag.BODY_TRUNCATED),
        ),
        _refund(flags=(Flag.IDEMPOTENT_REPLAY,)),
        _refund(
            flags=(Flag.IDEMPOTENCY_CONFLICT,),
            precondition=Precondition("passed", "idempotency_key_in_use"),
        ),
        _refund(9800, precondition=Precondition("rejected", "amount_too_large")),
        _refund(flags=(Flag.BODY_TRUNCATED, Flag.STREAM_TRUNCATED)),
        _post("hi\nthere\x1b[31m\ud800"),
        _tool(),
        _tool("db.lookup", kind="read", ran="real"),
        _tool("db.archive", ran="real"),
        dataclasses.replace(_tool("db.x\n"), error=ErrorInfo("Boom\x1b", "no")),
    ]
    run, index = _run(events), servicemaps.load()
    summary = summary_lines(RunView(run.record, run.events), index)
    acts = compare.actions(run, index)
    exchanges = [a for a in acts if a.key[0] == compare.EXCHANGE_KEY]
    tools = [a for a in acts if a.key[0] == compare.TOOL_KEY]
    assert [f"  {a.text}" for a in [*exchanges, *tools]] == [
        line for line in summary if line.startswith(("  ○ ", "  ✗ "))
    ]
    assert (len(exchanges), len(tools)) == (9, 2)
    # The decision-failed write's body and the plain refund's were cut.
    assert [i for i, action in enumerate(exchanges) if action.cut] == [4, 7]


def test_align_keeps_every_action_once_in_its_order_and_a_run_is_the_same_as_itself():
    """Property test over seeded random runs drawn from few keys and fields, so writes recur.

    The text is drawn apart from the fields: two actions are the same by their data alone."""
    rng = random.Random(79)

    def action() -> compare.Action:
        key: tuple[str, ...] = (
            compare.EXCHANGE_KEY,
            "stripe",
            rng.choice(["refunds.create", "customers.update"]),
        )
        key = rng.choice([key, (compare.TOOL_KEY, "db.x")])
        fields = (("body.amount", rng.choice(["1", "2"])),)
        return compare.Action(key, rng.choice("ab"), cut=rng.random() < 0.2, fields=fields)

    def side(rows: tuple[compare.Row, ...], which: str) -> list[compare.Action]:
        return [action for row in rows if (action := getattr(row, which)) is not None]

    for _ in range(3000):
        a = [action() for _ in range(rng.randrange(8))]
        b = [action() for _ in range(rng.randrange(8))]
        rows = compare.align(a, b)
        assert [id(x) for x in side(rows, "a")] == [id(x) for x in a]
        assert [id(y) for y in side(rows, "b")] == [id(y) for y in b]
        for row in rows:
            if row.a is None or row.b is None:
                assert row.mark == ("only_b" if row.a is None else "only_a"), row
                continue
            assert row.a.key == row.b.key, row
            if row.a.cut or row.b.cut:
                assert row.mark == "cut", row  # whatever the two texts
            else:
                assert row.mark == ("same" if row.a.fields == row.b.fields else "changed"), row
        # A run against itself pairs each action with itself: `?` when it was cut, else `=`.
        assert [(row.mark, row.a, row.b) for row in compare.align(a, a)] == [
            ("cut" if x.cut else "same", x, x) for x in a
        ]


def _best(
    a: list[compare.Action], b: list[compare.Action]
) -> tuple[tuple[int, int, int], list[tuple[int, int]]]:
    """Return the best in-order pairing's score and its `(i, j)` pairs, by exhaustive search.

    The score is the `same` rows, the pairs, and minus the pairs' index sum, so the best has the
    most `same` rows, then the most pairs, then the soonest. Of pairings as good, from each place
    it pairs if one of them does, else passes over `b[j]` if one does, else over `a[i]`."""

    @functools.cache
    def paired(i: int, j: int) -> tuple[int, int, int]:
        same, pairs, soon = best(i + 1, j + 1)
        return (same + (a[i].data == b[j].data), pairs + 1, soon - i - j)

    @functools.cache
    def best(i: int, j: int) -> tuple[int, int, int]:
        if i == len(a) or j == len(b):
            return (0, 0, 0)
        options = [best(i + 1, j), best(i, j + 1)]
        if a[i].key == b[j].key:
            options.append(paired(i, j))
        return max(options)

    pairs: list[tuple[int, int]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i].key == b[j].key and paired(i, j) == best(i, j):
            pairs.append((i, j))
            i, j = i + 1, j + 1
        elif best(i, j + 1) == best(i, j):
            j += 1
        else:
            i += 1
    return best(0, 0), pairs


@pytest.mark.parametrize("amounts", [3, 20])
def test_align_pairs_the_most_identical_actions_then_the_most_of_one_key_then_the_soonest(amounts):
    """Property test against an exhaustive search over seeded random runs of few writes.

    Half the time B is A with a write or two changed, added or dropped, so the runs often share a
    start or an end, which `align` pairs before its table."""
    rng = random.Random(11)

    def action() -> compare.Action:
        key = (compare.EXCHANGE_KEY, "stripe", rng.choice(["refunds.create", "customers.update"]))
        fields = (("body.amount", str(rng.randrange(amounts))),)
        return compare.Action(key, "", cut=rng.random() < 0.1, fields=fields)

    def edited(a: list[compare.Action]) -> list[compare.Action]:
        b = [dataclasses.replace(x) for x in a]
        for _ in range(rng.randrange(1, 3)):
            n = rng.randrange(len(b) + 1)
            if n == len(b) or rng.random() < 0.4:
                b.insert(n, action())
            elif rng.random() < 0.5:
                b[n] = action()
            else:
                del b[n]
        return b

    for _ in range(2000):
        a = [action() for _ in range(rng.randrange(9))]
        b = edited(a) if rng.random() < 0.5 else [action() for _ in range(rng.randrange(9))]
        rows = compare.align(a, b)
        at_a, at_b = ({id(x): n for n, x in enumerate(side)} for side in (a, b))
        pairs = [
            (at_a[id(r.a)], at_b[id(r.b)]) for r in rows if r.a is not None and r.b is not None
        ]
        same = sum(row.mark == "same" for row in rows)
        score = (same, len(pairs), -sum(i + j for i, j in pairs))
        assert (score, pairs) == _best(a, b), (a, b)


def _refunded(amount: str) -> compare.Action:
    key = (compare.EXCHANGE_KEY, "stripe", "refunds.create")
    return compare.Action(key, amount, fields=(("body.amount", amount),))


def _tool_action(name: str) -> compare.Action:
    return compare.Action((compare.TOOL_KEY, name), name)


def test_of_pairings_as_good_align_takes_the_soonest_pairs_so_a_repeat_is_the_extra_copy():
    """A write one run made twice pairs its first copy, whichever run repeats it.

    Each run starts with a tool the other lacks, so the ties are not at the start. Of pairings
    whose pairs come as soon, `align` leaves B's action unpaired before A's."""
    a = [_tool_action("a"), _refunded("49"), _refunded("49")]
    b = [_tool_action("b"), _refunded("49")]
    assert [(row.mark, row.a, row.b) for row in compare.align(a, b)] == [
        ("only_a", a[0], None),
        ("only_b", None, b[0]),
        ("same", a[1], b[1]),
        ("only_a", a[2], None),
    ]
    assert [(row.mark, row.a, row.b) for row in compare.align(b, a)] == [
        ("only_a", b[0], None),
        ("only_b", None, a[0]),
        ("same", b[1], a[1]),
        ("only_b", None, a[2]),
    ]
    a, b = [_refunded("49"), _refunded("24")], [_refunded("24"), _refunded("49")]
    assert [(row.mark, row.a, row.b) for row in compare.align(a, b)] == [
        ("only_b", None, b[0]),
        ("same", a[0], b[1]),
        ("only_a", a[1], None),
    ]
    # Pairing `a[1]` with `b[0]` and `a[2]` with `b[1]` pairs as many, as soon: a tie pairs at once.
    a = [_refunded("1"), _refunded("2"), _refunded("1")]
    b = [_refunded("2"), _refunded("3"), _refunded("3"), _refunded("2")]
    assert [(row.mark, row.a, row.b) for row in compare.align(a, b)] == [
        ("changed", a[0], b[0]),
        ("only_b", None, b[1]),
        ("only_b", None, b[2]),
        ("same", a[1], b[3]),
        ("only_a", a[2], None),
    ]


@pytest.fixture
def table_sizes(monkeypatch) -> list[tuple[int, int]]:
    """Return the sizes of the runs each table `align` builds is scored over, as it builds them.

    The table costs the product of the two runs' lengths."""
    sizes: list[tuple[int, int]] = []
    steps = compare._steps

    def spy(a, b):
        sizes.append((len(a), len(b)))
        return steps(a, b)

    monkeypatch.setattr(compare, "_steps", spy)
    return sizes


def test_the_identical_actions_both_runs_start_with_pair_before_the_table_is_built(table_sizes):
    """Only what follows a shared start is scored, so a replay matching its recording is cheap."""
    shared = [_refunded("49") for _ in range(300)]
    a = [*shared, _refunded("24")]
    b = [*shared, _tool_action("b"), _refunded("24"), _tool_action("b")]
    marks = ["only_b", "same", "only_b"]
    assert [row.mark for row in compare.align(a, b)] == ["same"] * 300 + marks
    assert table_sizes == [(1, 3)]


def test_an_identical_end_with_every_copy_of_its_writes_pairs_before_the_table_too(table_sizes):
    """A replay that differs at its first write and then matches its recording is cheap too.

    An end holding an action that either run also made before it is scored, since the soonest
    pairing may pair that earlier copy."""
    shared = [_refunded(str(n)) for n in range(300)]
    a, b = [_refunded("x"), *shared], [_tool_action("b"), *shared]
    assert [row.mark for row in compare.align(a, b)] == ["only_a", "only_b"] + ["same"] * 300
    assert table_sizes == [(1, 1)]
    table_sizes.clear()
    repeated = [_refunded("49") for _ in range(300)]
    marks = [
        row.mark
        for row in compare.align([_refunded("x"), *repeated], [_tool_action("b"), *repeated])
    ]
    assert marks == ["only_a", "only_b"] + ["same"] * 300
    assert table_sizes == [(1, 1)]
    table_sizes.clear()
    assert [row.mark for row in compare.align(shared, b)] == ["only_b"] + ["same"] * 300
    assert table_sizes == [(0, 1)]
    table_sizes.clear()
    b = [_refunded("299"), *shared]
    assert [row.mark for row in compare.align(a, b)] == ["changed"] + ["same"] * 300
    assert table_sizes == [(301, 301)]


def test_a_cut_pair_whose_lines_print_alike_though_they_differ_is_told_apart_too():
    """A `?` pair that prints alike though it differs escapes its backslashes, as `~` does."""
    cut = dataclasses.replace(_post("line1\nline2"), flags=(Flag.BODY_TRUNCATED,))
    pair = compare.compare_runs(_run([cut]), _run([_post("line1\\nline2")]), servicemaps.load())
    assert pair.lines()[:2] == [
        '  ? A ○ slack  post to #C1: "line1\\nline2"  faked; not checked',
        '    B ○ slack  post to #C1: "line1\\\\nline2"  faked; not checked',
    ]


def test_a_run_of_hundreds_of_one_write_is_lined_up_write_by_write():
    """250 identical fakes after differing first writes each line up as `=`."""
    many = [_tool() for _ in range(250)]
    comparison = compare.compare_runs(_run([_post("hi"), *many]), _run([_refund(), *many]), None)
    assert comparison.lines() == [
        "  - ○ slack  POST slack.com/api/chat.postMessage  faked; not checked",
        "  + ○ stripe  POST api.stripe.com/v1/refunds  faked; checked against live state: "
        "would succeed",
        *[f"  = {TOOL}"] * 250,
        "",
        "  250 same · 0 changed · 1 only in A · 1 only in B",
    ]


@pytest.mark.parametrize(
    ("a", "b", "spelled_a", "spelled_b"),
    [
        ("pay​out", "payout", "pay\\u200bout", "payout"),
        ("on schedule", "on schedule", "on\\u00a0schedule", "on schedule"),
        ("‮abc", "abc", "\\u202eabc", "abc"),
        ("a\U000e0001b", "ab", "a\\U000e0001b", "ab"),
    ],
)
def test_a_pair_that_differs_by_a_character_no_one_can_see_spells_it(a, b, spelled_a, spelled_b):
    """A pair that prints alike spells invisible characters, such as a zero-width space, as escapes.

    `report.terminal.printable` escapes control characters only."""
    pair = compare.compare_runs(_run([_post(a)]), _run([_post(b)]), servicemaps.load())
    assert pair.lines()[:2] == [
        f'  ~ A ○ slack  post to #C1: "{spelled_a}"  faked; not checked',
        f'    B ○ slack  post to #C1: "{spelled_b}"  faked; not checked',
    ]


def test_compare_takes_a_prefix_only_one_run_starts_with_and_last(home, capfd):
    """Each side may be a unique run-id prefix or `last`; the header names the whole ids."""
    _store(
        home,
        {
            "alpha1": (_record("alpha1"), [_refund()]),
            "beta22": (_record("beta22", started_at=AT + 5, ended_at=AT + 6), [_refund()]),
        },
    )
    assert main(["compare", "alp", "last"]) == 0
    out, err = capfd.readouterr()
    assert err == ""
    assert out.splitlines()[0] == "irimi compare · alpha1 vs beta22"


def test_compare_refuses_a_prefix_more_than_one_run_starts_with(home, capfd):
    _store(home, {"ab1": (_record("ab1"), []), "ab2": (_record("ab2"), [])})
    assert main(["compare", "ab", "ab1"]) == exitcodes.ERROR
    assert capfd.readouterr() == ("", "error: run id ab is ambiguous; it starts ab1, ab2\n")


# ------------------------------------------------------ members and posts that print alike


def _posted(run_id: str, body: dict[str, object]) -> StoredRun:
    request = Request(
        "POST",
        "https",
        "slack.com",
        443,
        "/api/chat.postMessage",
        "",
        (("content-type", "application/json"),),
        json.dumps(body).encode(),
    )
    post = Exchange(
        request,
        Response(200, (), b'{"ok":true}'),
        "slack",
        "chat.postMessage",
        "write",
        "fake-L1",
        run_id,
        started_at=1.0,
        ended_at=2.0,
    )
    return StoredRun(RunRecord.header(run_id), [post])


@pytest.mark.parametrize(
    ("one", "other"),
    [
        ("a\nb", "a\\nb"),  # a newline and a typed one
        ("note", "note\u200b"),  # a zero-width space prints as nothing
        ("a b", "a\u00a0b"),  # a space and a no-break one
    ],
)
def test_members_that_print_alike_are_named_apart_in_a_field_diff(one, other):
    a = _posted("a", {"channel": "C1", "text": "hi", "metadata": {one: 1}})
    b = _posted("b", {"channel": "C1", "text": "hi", "metadata": {other: 1}})
    comparison = compare.compare_runs(a, b, maps_for_stored_runs())
    assert comparison.exit_code == 1
    rows = comparison.lines()
    assert rows[0].startswith('  ~ A ○ slack  post to #C1: "hi"')
    diff = [line.strip() for line in rows[2:] if line.startswith("      ")]
    # As a reader sees each name: what prints as nothing dropped, what prints as a space a space.
    names = {_seen(line.split(": ", 1)[0]) for line in diff}
    assert len(diff) == 2 and len(names) == 2, diff


def _seen(text: str) -> str:
    kept = (char for char in text if unicodedata.category(char) != "Cf")
    return "".join(" " if unicodedata.category(char) == "Zs" else char for char in kept)


def test_a_plain_member_is_named_as_it_is():
    a = _posted("a", {"channel": "C1", "text": "hi", "metadata": {"source": "web"}})
    b = _posted("b", {"channel": "C1", "text": "hi", "metadata": {"source": "cli"}})
    rows = compare.compare_runs(a, b, maps_for_stored_runs()).lines()
    assert rows[2] == '      body.metadata.source: "web" -> "cli"'


def test_a_quoted_member_names_its_escapes():
    a = _posted("a", {"channel": "C1", "text": "hi", "metadata": {"a​": 1}})
    b = _posted("b", {"channel": "C1", "text": "hi", "metadata": {"a​": 2}})
    rows = compare.compare_runs(a, b, maps_for_stored_runs()).lines()
    assert rows[2] == '      body.metadata."a\\u200b": 1 -> 2'


def _posts(run_id: str, *texts: str) -> StoredRun:
    events = [
        event
        for i, text in enumerate(texts)
        for event in _posted(f"{run_id}{i}", {"channel": "C1", "text": text}).events
    ]
    events = [dataclasses.replace(event, run_id=run_id) for event in events]
    return StoredRun(RunRecord.header(run_id), events)


def test_a_post_only_one_run_made_never_prints_like_one_both_made():
    """A post only B made is escaped when it prints like one both made, so it never reads twice.

    B posts a typed `\\n` and then A's newline: the newline lines up `=`, the typed one `+`."""
    a = _posts("a", "a\nb")
    b = _posts("b", "a\\nb", "a\nb")
    rows = compare.compare_runs(a, b, maps_for_stored_runs()).lines()
    assert rows[:2] == [
        '  + ○ slack  post to #C1: "a\\\\nb"  faked; not checked',
        '  = ○ slack  post to #C1: "a\\nb"  faked; not checked',
    ]
