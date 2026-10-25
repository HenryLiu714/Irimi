"""`ShadowPolicy`'s decision: forward a read, fake a write, and what a faked write would fire."""

import json
from dataclasses import replace

import pytest

from irimi import services
from irimi.core.exchange import Flag, Response
from irimi.decide.policy import DecisionFailed, ShadowPolicy
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


def test_a_rejection_that_raises_carries_the_check_read_it_was_built_from(monkeypatch):
    """A rejection that cannot be built raises `DecisionFailed`, holding irimi's check read.

    The read reached the service, so the session records it with its 502."""
    failure = RuntimeError("the rejection could not be built")

    def fails(classification, body):
        raise failure

    monkeypatch.setattr(services, "fake_rejection", fails)
    policy = ShadowPolicy(
        reader=canned_reader(json_response(200, charge_document(refunded_so_far=4900))),
        maps=SHIPPED,
    )
    with pytest.raises(DecisionFailed) as raised:
        ask(policy, refund_request())
    assert str(raised.value) == "the rejection could not be built"
    assert raised.value.__cause__ is failure
    (read,) = raised.value.issued
    assert (read.issued_by, read.request.method, read.request.path) == (
        "engine",
        "GET",
        "/v1/charges/ch_REAL",
    )


def test_a_cause_that_cannot_be_printed_still_carries_the_check_read(monkeypatch):
    """A cause whose `str` raises is named by its type, and the check read is still carried."""

    class Unprintable(Exception):
        def __str__(self) -> str:
            raise ValueError("no message")

    def fails(classification, body):
        raise Unprintable

    monkeypatch.setattr(services, "fake_rejection", fails)
    policy = ShadowPolicy(
        reader=canned_reader(json_response(200, charge_document(refunded_so_far=4900))),
        maps=SHIPPED,
    )
    with pytest.raises(DecisionFailed) as raised:
        ask(policy, refund_request())
    assert str(raised.value) == "Unprintable"
    assert [read.issued_by for read in raised.value.issued] == ["engine"]


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
