"""`ShadowPolicy`'s decision: forward a read, fake a write, and what a faked write would fire."""

import json
from dataclasses import replace

import pytest

from irimi.core.exchange import Flag, Precondition, Response, is_authored_write
from irimi.core.netaddr import Target
from irimi.decide.overlay import ServiceOverlay
from irimi.decide.policy import Decided, Delegate, Forward, Respond, ShadowPolicy
from irimi.decide.targets import ForwardTo
from irimi.engine import session as engine_session
from irimi.engine.ingress import Admitted
from irimi.engine.session import Received, ShadowSession
from irimi.servicemaps.classify import classify
from tests.support.decisions import (
    SHIPPED,
    answer,
    answer_shipped,
    answer_with,
    ask,
    canned_reader,
    charge_document,
    json_response,
    make_request,
    refund_request,
    shipped_with_targets,
)
from tests.support.doubles import NullStore


@pytest.mark.parametrize("kind", ["read", "llm", "telemetry"])
def test_shadow_policy_forwards_live_kinds(kind):
    cls = replace(classify(make_request(), SHIPPED), kind=kind)
    ans = answer(ShadowPolicy(), make_request(), cls)
    assert ans.answered_by == "live"
    assert ans.response is None
    assert ans.flags == ()


@pytest.mark.parametrize("kind", ["write", "unknown"])
def test_shadow_policy_fakes_a_write_with_an_echo(kind):
    cls = replace(classify(make_request("POST"), SHIPPED), kind=kind)
    ans = answer(ShadowPolicy(), make_request("POST"), cls)
    assert ans.answered_by == "fake-L0"
    assert isinstance(ans.response, Response)
    assert ans.response.status == 200
    assert ("content-type", "application/json") in ans.response.headers
    assert ans.flags == ()
    assert isinstance(json.loads(ans.response.body), dict)


def test_shadow_policy_is_named_shadow_and_decides():
    p = ShadowPolicy()
    assert p.name == "shadow"
    assert callable(p.decide)


# ---------------------------------------------------- would-have-fired


def test_a_faked_refund_lists_the_webhooks_it_would_have_fired():
    """A faked refund lists `refund.created` and `charge.refunded`, from its route's `fires:`."""
    ans = answer_shipped(make_request("POST", path="/v1/refunds"))
    assert ans.answered_by == "fake-L1"
    assert ans.would_fire == ("refund.created", "charge.refunded")


def test_a_faked_customer_update_lists_its_one_event():
    """Each route lists its own events, not the refund's."""
    ans = answer_shipped(make_request("POST", path="/v1/customers/cus_REAL123"))
    assert ans.would_fire == ("customer.updated",)


def test_a_write_on_an_unmapped_host_lists_nothing():
    """A faked write with no route makes no claim about what the service would have sent."""
    ans = answer_shipped(make_request("POST", host="example.invalid", path="/things", body=b"{}"))
    assert ans.answered_by == "fake-L0"
    assert ans.would_fire == ()


def test_a_live_read_lists_nothing():
    """A read is forwarded and performs nothing, so there is nothing that did not fire."""
    ans = answer_shipped(make_request())
    assert ans.answered_by == "live"
    assert ans.would_fire == ()


@pytest.mark.parametrize(
    ("reader", "outcome"),
    [
        (canned_reader(json_response(200, charge_document())), "passed"),
        (
            canned_reader(json_response(429, {"error": {"type": "rate_limit_error"}})),
            "not_evaluable",
        ),
        (None, None),
    ],
    ids=["passed", "not-evaluable", "never-asked"],
)
def test_every_precondition_outcome_but_rejected_lists_the_webhooks(reader, outcome):
    """A write that passed, could not be checked, or was never checked lists its events.

    Only `rejected` lists nothing."""
    ans = answer(
        ShadowPolicy(reader=reader, maps=SHIPPED),
        refund_request(),
        classify(refund_request(), SHIPPED),
    )
    assert ans.precondition == outcome
    assert ans.would_fire == ("refund.created", "charge.refunded")


def test_a_rejected_write_lists_no_webhooks():
    """A write the precondition check rejects would have fired nothing."""
    policy = ShadowPolicy(
        reader=canned_reader(json_response(200, charge_document(refunded_so_far=4900))),
        maps=SHIPPED,
    )
    ans = ask(policy, refund_request())
    assert ans.precondition == "rejected"
    assert ans.rejection_code == "charge_already_refunded"
    assert ans.would_fire == ()


def test_a_replayed_write_lists_no_webhooks():
    """A retry lists no events: they are already on the first write's exchange."""
    policy = ShadowPolicy(reader=canned_reader(json_response(200, charge_document())), maps=SHIPPED)
    first = ask(policy, refund_request())
    second = ask(policy, refund_request())
    assert first.would_fire == ("refund.created", "charge.refunded")
    assert Flag.IDEMPOTENT_REPLAY in second.flags
    assert second.would_fire == ()


def test_an_idempotency_conflict_lists_no_webhooks():
    """A reused key the service would refuse fires nothing, though it is not `rejected`."""
    policy = ShadowPolicy(reader=canned_reader(json_response(200, charge_document())), maps=SHIPPED)
    ask(policy, refund_request(b"charge=ch_REAL&amount=100"))
    ans = ask(policy, refund_request(b"charge=ch_REAL&amount=250"))
    assert Flag.IDEMPOTENCY_CONFLICT in ans.flags
    assert ans.rejection_code == "idempotency_error"
    assert ans.precondition is None
    assert ans.would_fire == ()


def test_a_delegated_write_lists_no_webhooks():
    """A write sent to a target lists nothing: irimi built no answer, so it claims nothing."""
    index = shipped_with_targets(
        [("api.stripe.com", "/v1/refunds", "http://127.0.0.1:3000/refund")]
    )
    ans = answer_with(index, make_request("POST", path="/v1/refunds"))
    assert ans.answered_by == "delegated"
    assert ans.would_fire == ()


# ---------------------------------------------------- the write log


ECHO = Response(200, (("content-type", "application/json"),), b"{}")


@pytest.mark.parametrize(
    ("decision", "kind", "authored"),
    [
        (Respond(ECHO, "fake-L0"), "write", True),
        (Respond(ECHO, "fake-L1"), "unknown", True),
        (Respond(ECHO, "fake-L0"), "read", False),
        (Respond(ECHO, "irimi"), "write", False),
        (Forward(), "write", False),
        (Delegate(ForwardTo(Target.parse("http://127.0.0.1:3000"))), "write", False),
    ],
)
def test_only_a_write_irimi_fakes_itself_enters_the_write_log(decision, kind, authored):
    """A live, target or irimi answer, or an answer to a live kind, is not a faked write."""
    assert Decided(decision).is_authored_write(kind) is authored


class _Keeping:
    """`ShadowPolicy`, keeping each `Decided` it returns for the test to read."""

    name = "shadow"

    def __init__(self, policy):
        self.policy = policy
        self.decided = []

    def decide(self, *args):
        decided = self.policy.decide(*args)
        self.decided.append(decided)
        return decided

    def recorded_tool_call(self, name, args):
        return None

    def observe_read(self, service, body):
        self.policy.observe_read(service, body)


def test_a_decided_answer_enters_the_write_log_exactly_when_it_says_it_will():
    """`Decided.is_authored_write` agrees with the write log the session files the answer in.

    A fresh refund enters it; its retry, a reused key, a read and a rejected refund do not."""
    charge = json_response(200, charge_document())
    policy = _Keeping(ShadowPolicy(reader=canned_reader(charge, charge), maps=SHIPPED))
    session = ShadowSession(policy, NullStore(), ServiceOverlay(), SHIPPED, "run")
    other_key = tuple(
        ("idempotency-key", "idem-2") if name == "idempotency-key" else (name, value)
        for name, value in refund_request().headers
    )
    asked = [
        refund_request(),
        refund_request(),
        refund_request(b"charge=ch_REAL&amount=100"),
        make_request(path="/v1/charges/ch_REAL"),
        replace(refund_request(), headers=other_key),
    ]
    said, filed = [], []
    for request in asked:
        plan = session.plan(Admitted(request, "run", "forward", ("127.0.0.1", 1)))
        decision = plan.decision
        upstream = decision.response if isinstance(decision, Respond) else charge
        exchange = session.complete(plan, Received(upstream)).exchange
        said.append(policy.decided[-1].is_authored_write(plan.classification.kind))
        filed.append(exchange in session.write_log.for_run("run"))
        assert is_authored_write(exchange) == filed[-1]
    assert said == filed == [True, False, False, False, False]
    assert [flag for d in policy.decided for flag in d.flags] == [
        Flag.IDEMPOTENT_REPLAY,
        Flag.IDEMPOTENCY_CONFLICT,
    ]
    rejected = policy.decided[-1].decision
    assert isinstance(rejected, Respond)
    assert rejected.outcome.precondition.outcome == "rejected"


def test_a_write_sent_to_a_target_is_recorded_with_the_precondition_its_decision_carries(
    monkeypatch,
):
    """A target's write on a checked route is recorded `not_evaluable`, as its `Delegate` says."""
    monkeypatch.setattr(engine_session, "_target_refusal", lambda forward, listener: None)
    index = shipped_with_targets(
        [("api.stripe.com", "/v1/refunds", "http://127.0.0.1:3000/refund")]
    )
    policy = ShadowPolicy(reader=canned_reader(), maps=index)
    session = ShadowSession(policy, NullStore(), ServiceOverlay(), index, "run")
    plan = session.plan(Admitted(refund_request(), "run", "forward", ("127.0.0.1", 1)))
    assert isinstance(plan.decision, Delegate)
    answer = json_response(200, {"id": "re_1"})
    exchange = session.complete(plan, Received(answer)).exchange
    assert (exchange.answered_by, exchange.precondition.outcome) == ("delegated", "not_evaluable")


def test_a_forwarded_read_is_recorded_with_no_precondition_and_no_webhooks():
    """A live forward carries no verdict, as its `Forward` says."""
    policy = ShadowPolicy(reader=canned_reader(), maps=SHIPPED)
    session = ShadowSession(policy, NullStore(), ServiceOverlay(), SHIPPED, "run")
    read = make_request(path="/v1/charges/ch_REAL")
    plan = session.plan(Admitted(read, "run", "forward", ("127.0.0.1", 1)))
    assert isinstance(plan.decision, Forward)
    received = Received(json_response(200, charge_document()))
    exchange = session.complete(plan, received).exchange
    assert (exchange.answered_by, exchange.precondition, exchange.would_fire) == (
        "live",
        Precondition(),
        (),
    )
