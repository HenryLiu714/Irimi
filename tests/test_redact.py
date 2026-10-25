"""Redaction before anything reaches disk: one or more tests per rule in `irimi.record.redact`.

Tests build exchanges by hand; `tests/e2e/test_trace_roundtrip.py` covers a real run's store.
"""

import dataclasses
import hmac
import json
import logging
import os
import random
import re
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from itertools import pairwise
from typing import Any

import pytest

from irimi.config import files, paths
from irimi.core import secret_shapes, stream_deltas
from irimi.core.exchange import Exchange, Flag, Request, Response
from irimi.decide import targets
from irimi.protocol.trace import JSONValue
from irimi.record import redact
from irimi.record.redact import placeholder, redact_exchange, redact_json
from tests.support import builders
from tests.support.credentials import (
    ANTHROPIC,
    AWS,
    GITHUB,
    GITHUB_PAT,
    LIVE_KEY,
    LIVE_KEY_SHORT,
    OPENAI,
    OPENAI_PROJECT,
    SLACK_APP,
    SLACK_BOT,
    SLACK_WEBHOOKS,
    STRIPE_LIVE,
    STRIPE_RESTRICTED,
    STRIPE_TEST,
    STRIPE_WEBHOOK,
    TEST_KEY,
)
from tests.support.waiting import eventually

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
JSON = ("content-type", "application/json")
FAILED_BODY = redact.REDACTION_FAILED.encode()


def _ph(value: str, key: bytes = KEY) -> str:
    return placeholder(key, value)


def _request(**fields) -> Request:
    """A refund POST to Stripe."""
    return builders.request(**({"method": "POST", "path": "/v1/refunds"} | fields))


def _exchange(request: Request | None = None, response: Response | None = None, **fields):
    """A refund irimi faked, in run `r1`, with no answer unless given one."""
    values = {
        "service": "stripe",
        "operation": "refunds.create",
        "kind": "write",
        "answered_by": "fake-L1",
        "run_id": "r1",
    }
    return builders.exchange(request=request or _request(), response=response, **(values | fields))


def _body(body: bytes, *headers: tuple[str, str]) -> bytes:
    """The request body `body` stores as, sent with `headers`."""
    return redact_exchange(_exchange(_request(headers=headers, body=body)), KEY).request.body


def _response_body(body: bytes, *headers: tuple[str, str]) -> bytes:
    response = Response(status=200, headers=headers, body=body)
    stored = redact_exchange(_exchange(response=response), KEY).response
    assert stored is not None
    return stored.body


# ------------------------------------------------------------------------------ the placeholder


def test_a_placeholder_is_16_hex_digits_of_an_hmac_of_the_value_under_the_key():
    digest = hmac.new(KEY, LIVE_KEY_SHORT.encode(), "sha256").hexdigest()
    assert placeholder(KEY, LIVE_KEY_SHORT) == f"<redacted:{digest[:16]}>"


def test_the_same_secret_gives_the_same_placeholder_and_another_key_a_different_one():
    """A secret's placeholder is stable under one key, so replay can match, and differs by key."""
    auth = f"Bearer {STRIPE_TEST}one"
    ex = _exchange(_request(headers=(("authorization", auth),)))
    first, again = redact_exchange(ex, KEY), redact_exchange(ex, KEY)
    other = redact_exchange(ex, OTHER_KEY)
    assert first.request.headers == again.request.headers == (("authorization", _ph(auth)),)
    assert other.request.headers == (("authorization", _ph(auth, OTHER_KEY)),)
    assert _ph(auth, OTHER_KEY) != _ph(auth)


# ------------------------------------------------------------------------------ rule 1: headers


def test_a_credential_header_is_replaced_whole_on_the_request():
    basic = "Basic c2tfdGVzdF9hYmM6"  # base64 of `TEST_KEY` and a colon, which no shape can see
    ex = _exchange(
        _request(headers=(("Authorization", basic), ("X-Api-Key", "k-123"), ("Accept", "*/*")))
    )
    assert redact_exchange(ex, KEY).request.headers == (
        ("Authorization", _ph(basic)),
        ("X-Api-Key", _ph("k-123")),
        ("Accept", "*/*"),
    )


def test_a_credential_header_is_replaced_on_the_response_and_set_cookie_there_only():
    response = Response(
        status=200,
        headers=(("Set-Cookie", "sid=abc; HttpOnly"), ("x-auth-token", "t"), ("Content-Type", "x")),
        body=b"",
    )
    ex = _exchange(_request(headers=(("set-cookie", "not-a-credential"),)), response)
    stored = redact_exchange(ex, KEY)
    assert stored.response is not None
    assert stored.response.headers == (
        ("Set-Cookie", _ph("sid=abc; HttpOnly")),
        ("x-auth-token", _ph("t")),
        ("Content-Type", "x"),
    )
    assert stored.request.headers == (("set-cookie", "not-a-credential"),)


def test_a_shape_in_a_header_name_is_replaced_on_the_request_and_the_response():
    secret = LIVE_KEY
    response = Response(status=200, headers=((f"X-{secret}", "v"),), body=b"")
    ex = _exchange(_request(headers=((f"x-{secret}", "v"), ("accept", "*/*"))), response)
    stored = redact_exchange(ex, KEY)
    assert stored.request.headers == ((f"x-{_ph(secret)}", "v"), ("accept", "*/*"))
    assert stored.response is not None
    assert stored.response.headers == ((f"X-{_ph(secret)}", "v"),)


def test_a_url_in_a_header_has_its_query_and_fragment_redacted_by_name():
    """A URL header's query and fragment are redacted by name, and a credential-path URL's path.

    An OAuth redirect hands a token back in `Location`, and `Referer` repeats the page's; neither
    token has a shape."""
    location = "https://app.example/cb?state=s1&access_token=at1#id_token=it1&x=1"
    referer = f"{SLACK_WEBHOOKS}T1/B1/S3CR3T?a=1"
    response = Response(status=302, headers=(("Location", location),), body=b"")
    ex = _exchange(_request(headers=(("referer", referer), ("x-plain", "a?token=b"))), response)
    stored = redact_exchange(ex, KEY)
    assert stored.response is not None
    assert stored.response.headers == (
        (
            "Location",
            f"https://app.example/cb?state=s1&access_token={_ph('at1')}#id_token={_ph('it1')}&x=1",
        ),
    )
    assert stored.request.headers == (
        ("referer", f"https://hooks.slack.com/{_ph('/services/T1/B1/S3CR3T')}?a=1"),
        ("x-plain", "a?token=b"),
    )
    plain = "https://app.example/a%7Eb?c=d#e"
    same = redact_exchange(_exchange(_request(headers=(("referer", plain),))), KEY)
    assert same.request.headers == (("referer", plain),)


def test_the_credential_header_rule_is_the_one_delegation_strips_by():
    """`targets` strips exactly the headers `redact` calls credentials."""
    assert callable(redact.is_credential_header)
    assert not hasattr(targets, "is_credential_header")
    assert not hasattr(targets, "CREDENTIAL_MARKERS")
    assert not hasattr(targets, "CREDENTIAL_HEADERS")


# ------------------------------------------------------------------------------ rule 2: secret keys


def test_secret_keys_in_json_are_replaced_at_any_depth_and_token_counts_are_not():
    body = {
        "max_tokens": 1024,
        "usage": {"total_tokens": 7, "token_count": 3},
        "password": 123,
        "a": {"b": {"Client_Secret": "cs_1"}},
        "items": [{"TOKEN": "t-1"}, {"id": 1}],
    }
    stored = _body(json.dumps(body).encode(), JSON)
    expected = {
        "max_tokens": 1024,
        "usage": {"total_tokens": 7, "token_count": 3},
        "password": _ph("123"),
        "a": {"b": {"Client_Secret": _ph("cs_1")}},
        "items": [{"TOKEN": _ph("t-1")}, {"id": 1}],
    }
    assert stored == json.dumps(expected, separators=(",", ":"), ensure_ascii=False).encode()


def test_a_secret_keys_structured_value_is_hidden_by_its_json_with_sorted_keys():
    stored = json.loads(_body(b'{"secret": {"b": 1, "a": [2]}, "token": true}', JSON))
    assert stored == {"secret": _ph('{"a": [2], "b": 1}'), "token": _ph("true")}


def test_an_empty_or_null_secret_is_left_as_it_is():
    """A placeholder would turn "no token was sent" into "a token was sent"."""
    body = b'{"token": null, "password": ""}'
    assert _body(body, JSON) == body
    assert _body(b"token=&amount=1", builders.FORM_HEADER) == b"token=&amount=1"
    ex = _exchange(_request(headers=(("authorization", ""),)))
    assert redact_exchange(ex, KEY).request.headers == (("authorization", ""),)


def test_a_form_field_is_matched_by_its_last_bracket_segment():
    stored = _body(b"card[token]=tok_x&amount=100&expand[]=token", builders.FORM_HEADER)
    assert stored == f"card[token]={_ph('tok_x')}&amount=100&expand[]=token".encode()


def test_an_empty_bracket_segment_names_nothing_so_the_one_before_it_counts():
    """`token[]` is PHP's and Rails' spelling of a list of tokens: its name is `token`, not ``."""
    stored = _body(b"token[]=t1&a[password][]=p1&expand[]=x", builders.FORM_HEADER)
    assert stored == f"token[]={_ph('t1')}&a[password][]={_ph('p1')}&expand[]=x".encode()


def test_a_shape_in_a_form_fields_name_is_replaced():
    stored = _body(f"{LIVE_KEY}=1&x%20{TEST_KEY}=2".encode(), builders.FORM_HEADER)
    assert stored == f"{_ph(LIVE_KEY)}=1&x%20{_ph(TEST_KEY)}=2".encode()


def test_a_json_body_that_only_claims_to_be_a_form_is_walked_as_json():
    """A JSON body sent as a form is walked as JSON, so its `password` value is redacted.

    Read as a form, the whole document is one name with an empty value, and `hunter2` has no shape.
    """
    stored = _body(
        f'{{"password": "hunter2", "note": "{LIVE_KEY}"}}'.encode(), builders.FORM_HEADER
    )
    assert json.loads(stored) == {"password": _ph("hunter2"), "note": _ph(LIVE_KEY)}


def test_query_parameter_names_are_matched_whole_and_case_insensitively():
    ex = _exchange(_request(method="GET", query="API_KEY=abc&limit=3&tokens=9&access_token=x+y"))
    assert redact_exchange(ex, KEY).request.query == (
        f"API_KEY={_ph('abc')}&limit=3&tokens=9&access_token={_ph('x y')}"
    )


# ------------------------------------------------------------------------------ rule 3: shapes

SAMPLES = [
    LIVE_KEY,
    STRIPE_TEST + "abc123",
    STRIPE_RESTRICTED + "abc123",
    STRIPE_WEBHOOK + "abc123",
    SLACK_BOT + "123-456-abc",
    SLACK_APP + "1-A0-abc",
    GITHUB + "a" * 36,
    GITHUB_PAT + "11AB_cd",
    AWS + "ABCDEFGHIJKLMNOP",
    ANTHROPIC + "api03-ab_c-d",
    OPENAI_PROJECT + "a" * 20,
    OPENAI + "a" * 20,
]


def test_the_shapes_are_the_issues_list_exactly():
    assert secret_shapes.SECRET_PATTERNS == (
        r"sk_(live|test)_[A-Za-z0-9]+",
        r"rk_(live|test)_[A-Za-z0-9]+",
        r"whsec_[A-Za-z0-9]+",
        r"xox[abprs]-[A-Za-z0-9-]+",
        r"xapp-[A-Za-z0-9-]+",
        r"gh[pousr]_[A-Za-z0-9]{36,}",
        r"github_pat_[A-Za-z0-9_]+",
        r"AKIA[0-9A-Z]{16}",
        r"sk-ant-[A-Za-z0-9_-]+",
        r"sk-(proj-)?[A-Za-z0-9_-]{20,}",
    )


@pytest.mark.parametrize("secret", SAMPLES)
def test_every_shape_is_replaced_whole_inside_text(secret):
    assert redact_json(f"uses {secret}, then stops", KEY) == f"uses {_ph(secret)}, then stops"


@pytest.mark.parametrize("secret", SAMPLES)
def test_text_cut_outside_secrets_redacts_to_a_prefix_of_the_whole_redacted(secret):
    """Wherever the cut falls, what it keeps, redacted, is a prefix of the whole text redacted.

    So it holds no part of a key, and each key it holds has its whole key's placeholder."""
    text = (
        f"{secret} refused key:\\n{secret}, retry_{secret} as %20{secret} or \\u0020{secret}; "
        f"xx{secret} {'x' * 30}."
    )
    whole = redact_json(text, KEY)
    assert isinstance(whole, str) and whole.count("<redacted:") == 5
    for limit in range(len(text) + 1):
        kept = secret_shapes.cut_outside_secrets(text, limit)
        redacted = redact_json(kept, KEY)
        assert text.startswith(kept) and len(kept) <= limit, limit
        assert isinstance(redacted, str) and whole.startswith(redacted), limit


def test_any_text_cut_outside_secrets_redacts_to_a_prefix_of_the_whole_redacted():
    """No cut of random key-like text keeps part of a key, or a prefix redaction takes for a key.

    The text is built from a shape's pieces, separators and escapes, and cut at every length."""
    pieces = [
        *("sk_live_", "sk_test_", "rk_test_", "whsec_", "xoxb-", "xapp-", "ghp_", "github_pat_"),
        *("AKIA", "sk-ant-", "sk-", "sk-proj-", "proj-", "A", "z", "0", "_", "-", " ", "/", "="),
        *("\\n", "\\u0020", "%20", "\\", "%", "é", "x" * 7, "Q" * 20, "AB12CD34EF56GH78"),
    ]
    chosen = random.Random(179)
    for _ in range(1500):
        text = "".join(chosen.choice(pieces) for _ in range(chosen.randint(1, 30)))
        whole = redact_json(text, KEY)
        assert isinstance(whole, str)
        for limit in range(len(text) + 1):
            redacted = redact_json(secret_shapes.cut_outside_secrets(text, limit), KEY)
            assert isinstance(redacted, str) and whole.startswith(redacted), (text, limit)


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        ("abc defgh", "abc defgh"),  # within the limit: whole
        ("x" * 20, "x" * 9),  # no key across the cut: at the limit, inside a word or not
        (f"abc {STRIPE_LIVE}a1b2", "abc "),  # a key across the cut: before the whole key
        (f"{STRIPE_LIVE}a1b2", ""),  # a key from the start: none of it
        (f"abc {STRIPE_LIVE}a1 more", "abc "),  # the cut inside a key that ends past it
        (f"{STRIPE_LIVE}a / b", f"{STRIPE_LIVE}a"),  # a key that ends at the cut: kept whole
        (f"abcdefghi {STRIPE_LIVE}a", "abcdefghi"),  # a key that starts at the cut: up to it
        ("ask_live_a1b2", "ask_live_"),  # a shape after a letter is no key: at the limit
        (f"x_{STRIPE_LIVE}a1b2", "x_"),  # after `_` it is one
        (f"%20{STRIPE_LIVE}a1", "%20"),  # and after an escape
    ],
)
def test_a_cut_outside_secrets_moves_only_for_a_key_across_it(text, kept):
    """A cut moves back before a key it would cross, and otherwise falls at the limit.

    The SDK cuts before irimi redacts, so its cut must never keep part of a key."""
    assert secret_shapes.cut_outside_secrets(text, 9) == kept


def test_redaction_finds_the_shapes_a_cut_moves_for():
    """`redact` and `cut_outside_secrets` know the same secret shapes."""
    assert redact.SECRET_SHAPE is secret_shapes.SECRET_SHAPE  # type: ignore[attr-defined]


SHORTEST = STRIPE_LIVE + "a"


@pytest.mark.parametrize(
    "text",
    [f'"{SHORTEST}"', f"={SHORTEST}", f"/{SHORTEST}", f"_{SHORTEST}", SHORTEST, f"({SHORTEST})"],
)
def test_a_shape_after_punctuation_or_at_the_start_is_still_a_secret(text):
    assert SHORTEST not in str(redact_json(text, KEY))


# What raw text spells a separator as: a JSON string escape inside an SSE line or a text body, and
# a percent-escape in a path, a header or a form field's name. Each ends in a letter or a digit.
ESCAPES = ["\\n", "\\t", "\\r", "\\b", "\\f", "\\u0020", "\\u00A0", "%20", "%3D", "%2F", "%2c"]


@pytest.mark.parametrize("escape", ESCAPES)
def test_a_shape_after_an_escape_is_still_a_secret(escape):
    text = f"key:{escape}{LIVE_KEY}"
    assert redact_json(text, KEY) == f"key:{escape}{_ph(LIVE_KEY)}"


def test_a_shape_after_an_escape_is_replaced_where_text_is_stored_raw():
    secret = LIVE_KEY
    sse = f'data: {{"partial_json": "{{\\"note\\": \\"key:\\n{secret}'
    response = Response(status=200, headers=(("content-type", "text/event-stream"),), body=b"")
    ex = _exchange(
        _request(path=f"/v1/x/Bearer%20{secret}", headers=(("x-note", f"a%3D{secret}"),)),
        dataclasses.replace(response, body=f"{sse}\n\n".encode()),
    )
    stored = redact_exchange(ex, KEY)
    assert stored.request.path == f"/v1/x/Bearer%20{_ph(secret)}"
    assert stored.request.headers == (("x-note", f"a%3D{_ph(secret)}"),)
    assert stored.response is not None
    assert secret not in stored.response.body.decode()


def test_a_shape_glued_to_a_word_is_part_of_the_word():
    text = "run task_test_runner on risk-assessment-for-customer-accounts"
    assert redact_json(text, KEY) is text
    escaped = "\\ntask_test_runner %20risk-assessment-for-customer-accounts"
    assert redact_json(escaped, KEY) is escaped


def test_a_shape_after_a_json_strings_escaped_letter_is_replaced_wherever_json_is_walked():
    """The walk reads `\\u0041` as `A`, glued to the shape, so the shape is judged as sent.

    A JSON body, an SSE line and an event joined from several `data:` lines all take the
    placeholder. A glued shape that overlaps another shape is one secret with it, and one that
    starts a longer glued shape leaves none of the longer one behind."""
    note, hidden = f'"\\u0041{LIVE_KEY}"', f'"A{_ph(LIVE_KEY)}"'
    assert _body(f'{{"note": {note}}}'.encode(), JSON) == f'{{"note":{hidden}}}'.encode()
    sse = f'data: {{"note": {note}}}\n\ndata: {{\ndata: "note": {note}, "token": "t1"\ndata: }}\n'
    stored = _response_body(sse.encode(), ("content-type", "text/event-stream"))
    expected = f'data: {{"note":{hidden}}}\n\ndata: {{"note":{hidden},"token":"{_ph("t1")}"}}\n'
    assert stored == f"{expected}data:\ndata:\n".encode()
    both = f'["\\u0041{LIVE_KEY_SHORT}", "\\u0041{LIVE_KEY}"]'.encode()
    assert _body(both, JSON) == f'["A{_ph(LIVE_KEY_SHORT)}","A{_ph(LIVE_KEY)}"]'.encode()
    overlapping = f'["{LIVE_KEY_SHORT}\\u0041{LIVE_KEY}"]'.encode()
    assert _body(overlapping, JSON) == f'["{_ph(LIVE_KEY_SHORT + "A" + LIVE_KEY)}"]'.encode()
    twice = f'["\\u0041{LIVE_KEY} \\u0062{LIVE_KEY}"]'.encode()
    assert _body(twice, JSON) == f'["A{_ph(LIVE_KEY)} b{_ph(LIVE_KEY)}"]'.encode()
    keyed = f'{{"\\u0041{LIVE_KEY}": 1}}'.encode()
    assert _body(keyed, JSON) == f'{{"A{_ph(LIVE_KEY)}":1}}'.encode()


def test_only_an_escaped_letter_or_digit_glues_to_the_shape_after_it():
    """Every other escape decodes to a character the shape rule already reads as a separator."""
    for code in range(0x20, 0x7F):
        for spelling in (f"{code:04x}", f"{code:04X}"):
            glued = secret_shapes.shapes_after_escaped_letters(f'"\\u{spelling}{LIVE_KEY}"')
            assert glued == ({LIVE_KEY} if chr(code).isalnum() else set()), spelling


def test_escaped_letters_says_where_each_decoded_string_has_a_letter_its_json_escapes():
    """Offsets count decoded characters: an escape is one, a surrogate pair's two escapes one.

    An escaped backslash before `u0041` escapes no letter, a key counts as any string, and two
    strings that decode alike share their offsets."""
    text = (
        '{"a": "x\\u0041y", "b": "\\\\u0041", "c": "\\ud83d\\ude00\\n\\u0062", '
        '"\\u0064": 1, "e": "xA\\u0079", "f": "\\u00e9"}'
    )
    assert secret_shapes.escaped_letters(text) == {
        "xAy": {1, 2},
        "\U0001f600\nb": {2},
        "d": {0},
    }
    assert secret_shapes.escaped_letters('{"a": "xAy", "b": "\\n\\u00e9"}') == {}
    # A lone surrogate is one character, and so is each half of a pair turned round.
    lone = '["\\ude00\\u0041", "\\ude00\\ude00\\u0042", "\\ud83d\\ud83d\\ude00\\u0043"]'
    assert secret_shapes.escaped_letters(lone) == {
        "\ude00A": {1},
        "\ude00\ude00B": {2},
        "\ud83d\U0001f600C": {2},
    }


def test_shape_spans_after_many_escaped_letters_in_one_word_takes_linear_time():
    """A shape after each escaped letter of one long word would each run to the word's end.

    One that starts inside a shape that already ran there adds nothing, so it is not matched."""
    word = "Axoxa-" * 30_000
    started = time.perf_counter()
    spans = secret_shapes.shape_spans(word, range(0, len(word), 6))
    assert time.perf_counter() - started < 2
    assert spans == [(1, len(word))]


def test_shape_spans_finds_a_shape_after_an_escaped_letter_only_where_it_is_told_one_is():
    glued = "A" + LIVE_KEY + " " + LIVE_KEY
    after = len("A" + LIVE_KEY + " ")
    assert secret_shapes.shape_spans(glued) == [(after, after + len(LIVE_KEY))]
    assert secret_shapes.shape_spans(glued, [0]) == [
        (after, after + len(LIVE_KEY)),
        (1, 1 + len(LIVE_KEY)),
    ]
    assert secret_shapes.shape_spans(glued, [len(glued) - 1]) == [(after, after + len(LIVE_KEY))]


def test_a_shape_is_replaced_in_every_place_text_is_stored():
    secret = LIVE_KEY
    response = Response(
        status=200,
        headers=(("Content-Type", "text/event-stream"),),
        body=f'event: e {secret}\ndata: {{"k": "{secret}"}}\n\n'.encode(),
    )
    ex = _exchange(
        _request(
            path=f"/v1/keys/{secret}",
            query=f"q=a+{secret}",
            headers=(("x-note", f"key {secret}"), JSON),
            body=json.dumps({"a": {"b": {"c": [f"deep {secret}"]}}}).encode(),
        ),
        response,
    )
    stored = redact_exchange(ex, KEY)
    assert stored.request.path == f"/v1/keys/{_ph(secret)}"
    assert stored.request.query == f"q=a+{_ph(secret)}"
    assert stored.request.headers[0] == ("x-note", f"key {_ph(secret)}")
    assert json.loads(stored.request.body) == {"a": {"b": {"c": [f"deep {_ph(secret)}"]}}}
    assert stored.response is not None
    assert (
        stored.response.body
        == f'event: e {_ph(secret)}\ndata: {{"k":"{_ph(secret)}"}}\n\n'.encode()
    )


def test_a_json_body_is_walked_whatever_its_content_type_claims():
    stored = _response_body(b'{"access_token": "at-1"}', ("Content-Type", "text/plain"))
    assert json.loads(stored) == {"access_token": _ph("at-1")}


def test_a_json_body_behind_a_byte_order_mark_is_walked_as_json():
    """`json.loads` refuses a leading U+FEFF as not JSON, so the body was scanned as text."""
    stored = _body(b'\xef\xbb\xbf{"token": "hunter2"}', JSON)
    assert stored == f'\ufeff{{"token":"{_ph("hunter2")}"}}'.encode()


def test_each_line_of_ndjson_and_each_sse_data_line_is_walked_as_json():
    """Each NDJSON line and each SSE `data:` line is walked as JSON, so `hunter2` is redacted."""
    ndjson = b'{"token": "hunter2"}\r\n{"a": 1}\n\n'
    assert _response_body(ndjson, ("content-type", "application/x-ndjson")) == (
        f'{{"token":"{_ph("hunter2")}"}}\r\n{{"a": 1}}\n\n'.encode()
    )
    sse = b'event: e\ndata: {"password": "p1"}\ndata:[{"api_key": "k1"}]\ndata: [not json\n\n'
    assert (
        _response_body(sse, ("content-type", "text/event-stream"))
        == (
            f'event: e\ndata: {{"password":"{_ph("p1")}"}}\n'
            f'data:[{{"api_key":"{_ph("k1")}"}}]\ndata: [not json\n\n'
        ).encode()
    )


def test_an_sse_events_json_over_several_data_lines_is_walked_as_the_document_they_join_into():
    """An event's `data:` lines are joined with LF, as a client joins them, and walked as JSON.

    The walked document goes on the first `data:` line and the others are left empty, so the event
    keeps its lines and a client's join still reads the document."""
    sse = b'event: x\ndata: {\ndata:   "client_secret": "CANARYzzz"\ndata: }\n\ndata: {"a": 1}\n\n'
    stored = _response_body(sse, ("content-type", "text/event-stream"))
    hidden = _ph("CANARYzzz")
    expected = (
        f'event: x\ndata: {{"client_secret":"{hidden}"}}\ndata:\ndata:\n\ndata: {{"a": 1}}\n\n'
    )
    assert stored == expected.encode()
    event = stored.decode().split("\n\n")[0].split("\n")
    joined = "\n".join(line.removeprefix("data:").removeprefix(" ") for line in event[1:])
    assert json.loads(joined) == {"client_secret": hidden}


def test_an_events_data_lines_are_joined_past_its_other_fields_and_keep_their_endings():
    """Other fields between `data:` lines are not data, and a line keeps its CR, LF or CRLF.

    The other fields are scanned for shapes, and the first `data:` line keeps its leading
    whitespace, as a line walked alone does."""
    sse = f'data:[\r\nid: {LIVE_KEY}\rdata: {{"token": "t1"}}]\n\n'.encode()
    stored = _response_body(sse, ("content-type", "text/event-stream"))
    expected = f'data:[{{"token":"{_ph("t1")}"}}]\r\nid: {_ph(LIVE_KEY)}\rdata:\n\n'
    assert stored == expected.encode()
    spaced = b'data:  {\ndata: "token": "t1"}'
    stored = _response_body(spaced, ("content-type", "text/event-stream"))
    assert stored == f'data:  {{"token":"{_ph("t1")}"}}\ndata:'.encode()


def test_an_events_data_lines_keep_their_bytes_unless_joined_they_are_json_holding_a_secret():
    """A join that is JSON with no secret, or not a JSON object or array, is left line by line.

    A JSON string cannot hold the LF the join puts between two lines, and a join that only starts
    as a number is not read as JSON."""
    quiet = b'event: x\ndata: {\ndata:   "text": "hi"\ndata: }\n\n'
    broken = b'data: {"token": "a\ndata: b"}\n\n'
    numbers = b"data: " + b"1" * 5000 + b"\ndata: 2\n\n"
    for sse in (quiet, broken, numbers):
        assert _response_body(sse, ("content-type", "text/event-stream")) == sse


def test_an_event_of_one_data_line_is_not_parsed_joined(monkeypatch):
    """Only an event of several `data:` lines is parsed joined too.

    An event of one is parsed by its line's walk, and once more if it is an object, which can
    hold a piece of a model's streamed text (`stream_deltas`)."""
    parsed: list[str] = []
    loads = json.loads

    def counted(text: str, **kwargs: Any) -> Any:
        parsed.append(text)
        return loads(text, **kwargs)

    monkeypatch.setattr(json, "loads", counted)
    sse = b'event: e\ndata: {"a": 1}\n\ndata: [1]\n\n'
    assert _response_body(sse, ("content-type", "text/event-stream")) == sse
    assert parsed == [sse.decode(), '{"a": 1}', '{"a": 1}', "[1]"]


def test_an_sse_line_ended_by_a_lone_carriage_return_is_walked_as_its_own_line():
    """An SSE line ended by a lone CR is its own line, walked as JSON like one ended by LF."""
    sse = b'data: {"token": "hunter2"}\rdata: {"a": 1}\r\r'
    assert _response_body(sse, ("content-type", "text/event-stream")) == (
        f'data: {{"token":"{_ph("hunter2")}"}}\rdata: {{"a": 1}}\r\r'.encode()
    )


def test_a_json_line_the_walk_cannot_see_whole_fails_the_body_closed():
    body = b'data: {"token": "t1", "token": null}\n\n'
    stored = _response_body(body, ("content-type", "text/event-stream"))
    assert stored == FAILED_BODY
    joined = b'data: {"token": "t1",\ndata: "token": null}\n\n'
    assert _response_body(joined, ("content-type", "text/event-stream")) == FAILED_BODY


def test_a_shape_in_a_json_key_is_replaced_too():
    named = STRIPE_LIVE + "k"
    assert redact_json({named: 1}, KEY) == {_ph(named): 1}


# ------------------------------------------------------------------------------ rule 4: paths


def test_the_whole_path_of_a_credential_path_host_is_replaced():
    path = "/services/T000/B000/XXXXsecret"
    ex = _exchange(_request(host="hooks.slack.com", path=path), service="slack")
    assert redact_exchange(ex, KEY).request.path == "/" + _ph(path)


def test_a_credential_path_host_spelled_with_its_root_dot_is_the_same_host():
    path = "/services/T000/B000/XXXXsecret"
    ex = _exchange(_request(host="hooks.slack.com.", path=path))
    assert redact_exchange(ex, KEY).request.path == "/" + _ph(path)


def test_a_credential_path_is_replaced_wherever_else_the_exchange_carries_it():
    """A credential path is replaced in the 502 for an unreachable target and in echoed headers.

    `/` alone is every URL's path and is left alone."""
    path = "/services/T000/B000/XXXXsecret"
    reason = f"target 'http://127.0.0.1:9/{path[1:]}' could not be reached"
    response = Response(
        status=502,
        headers=(JSON, ("x-echo", f"got {path}")),
        body=json.dumps({"error": {"type": "irimi_target_failed", "message": reason}}).encode(),
    )
    request = _request(host="hooks.slack.com", path=path, headers=(JSON,), body=b'{"text": "hi"}')
    stored = redact_exchange(_exchange(request, response), KEY)
    hidden = "/" + _ph(path)
    assert stored.response is not None
    assert json.loads(stored.response.body)["error"]["message"] == reason.replace(path, hidden)
    assert stored.response.headers[1] == ("x-echo", f"got {hidden}")
    assert stored.request.body == b'{"text": "hi"}'
    root = _exchange(_request(host="hooks.slack.com", path="/"), response)
    root_response = redact_exchange(root, KEY).response
    assert root_response is not None
    assert root_response.body == response.body


def test_a_credential_path_holding_a_shape_is_replaced_whole_wherever_else_it_is_carried():
    """A credential path holding a key shape gets the path's one placeholder wherever it appears.

    The shape rule runs first, so without this the team and bot ids would survive beside it."""
    path = f"/services/T0SHAPE/B0SHAPE/{SLACK_BOT}12-abc"
    reason = f"target 'http://127.0.0.1:9{path}' could not be reached"
    response = Response(
        status=502,
        headers=(JSON, ("x-echo", f"got {path}")),
        body=json.dumps({"error": {"type": "irimi_target_failed", "message": reason}}).encode(),
    )
    request = _request(host="hooks.slack.com", path=path, headers=(("x-note", f"see {path}"),))
    stored = redact_exchange(_exchange(request, response), KEY)
    hidden = "/" + _ph(path)
    assert stored.request.path == hidden
    assert stored.request.headers == (("x-note", f"see {hidden}"),)
    assert stored.response is not None
    assert stored.response.headers[1] == ("x-echo", f"got {hidden}")
    assert json.loads(stored.response.body)["error"]["message"] == reason.replace(path, hidden)


def test_an_operation_named_after_the_path_is_redacted_with_the_path():
    """An unmatched request's `METHOD /path` operation is redacted as its path is."""
    path = "/workflows/T1/A1/123/S3CR3T"
    hook = _exchange(
        _request(host="hooks.slack.com", path=path), service="slack", operation=f"POST {path}"
    )
    assert redact_exchange(hook, KEY).operation == f"POST /{_ph(path)}"
    keyed = _exchange(_request(method="GET", path=f"/v1/keys/{LIVE_KEY_SHORT}"))
    keyed = dataclasses.replace(keyed, operation=f"GET /v1/keys/{LIVE_KEY_SHORT}")
    assert redact_exchange(keyed, KEY).operation == f"GET /v1/keys/{_ph(LIVE_KEY_SHORT)}"
    assert redact_exchange(_exchange(), KEY).operation == "refunds.create"
    named = _exchange(operation=f"keys.{LIVE_KEY_SHORT}")
    assert redact_exchange(named, KEY).operation == f"keys.{_ph(LIVE_KEY_SHORT)}"


def test_the_answer_target_is_redacted_by_the_requests_rules():
    """`Exchange.target` is redacted as the request is: a bare-origin target keeps its path."""
    path = "/services/T000/B000/XXXXsecret"
    hook = _exchange(
        _request(host="hooks.slack.com", path=path),
        service="slack",
        target=f"http://127.0.0.1:3000{path}?token=t1",
    )
    assert (
        redact_exchange(hook, KEY).target == f"http://127.0.0.1:3000/{_ph(path)}?token={_ph('t1')}"
    )
    stripe = _exchange(target=f"http://127.0.0.1:3000/v1/refunds?k={TEST_KEY}")
    assert redact_exchange(stripe, KEY).target == (
        f"http://127.0.0.1:3000/v1/refunds?k={_ph(TEST_KEY)}"
    )
    assert redact_exchange(_exchange(), KEY).target == ""


# ------------------------------------------------------------------------------ rules 5 and 6


def test_a_body_with_nothing_to_redact_comes_back_byte_for_byte():
    body = b'{ "b" : 1,\n  "a": [ "x", "\\u00e9" ], "max_tokens": 5 }'
    assert _body(body, JSON) == body
    form = b"amount=100&metadata%5Bnote%5D=a+b%20c"
    assert _body(form, builders.FORM_HEADER) == form
    text = b"event: ping\ndata: {}\n\n"
    assert _response_body(text, ("Content-Type", "text/event-stream")) == text


def test_a_body_that_is_not_utf8_is_stored_unscanned():
    body = b"\xff\xfe " + LIVE_KEY.encode()
    assert _body(body, ("content-type", "application/octet-stream")) == body


def test_redact_exchange_returns_a_new_exchange_and_copies_every_other_field():
    """`redact_exchange` returns a copy with every other field kept and the original unchanged."""
    original = builders.filled(Exchange)
    before = dataclasses.replace(original)
    stored = redact_exchange(original, KEY)
    assert stored is not original
    assert original == before
    redacted = {"request", "response", "target", "flags"}
    for field in dataclasses.fields(Exchange):
        if field.name not in redacted:
            assert getattr(stored, field.name) == getattr(original, field.name), field.name
    assert (stored.started_at, stored.ended_at) == (original.started_at, original.ended_at)
    assert stored.flags == original.flags


# ------------------------------------------------------------------------------ streamed bodies

SSE = ("content-type", "text/event-stream")
QUIET = b'data: {"text":"hi"}\n'
LOUD = b'data: {"key":"' + LIVE_KEY.encode() + b'"}\n'
LOUD_STORED = b'data: {"key":"' + _ph(LIVE_KEY).encode() + b'"}\n'
LAST = b'data: {"text":"bye"}\n'


def _stream(body: bytes, chunks: tuple[int, ...]) -> Exchange:
    """`redact_exchange`'s copy of a live read whose body streamed as `chunks`."""
    assert sum(chunks) == len(body)
    response = Response(status=200, headers=(SSE,), body=body)
    return redact_exchange(_exchange(response=response, stream_chunks=chunks), KEY)


def test_a_streamed_body_s_chunks_are_recomputed_over_the_redacted_body_line_by_line():
    """A chunk boundary keeps its place in an unchanged line and moves to a changed line's end."""
    sent = QUIET + b"\n" + LOUD + b"\n" + LAST
    chunks = (10, len(QUIET) - 10 + 1 + 15, len(LOUD) - 15 + 1 + 5, len(LAST) - 5)
    stored = _stream(sent, chunks)
    assert stored.response is not None
    assert stored.response.body == QUIET + b"\n" + LOUD_STORED + b"\n" + LAST
    assert stored.stream_chunks == (
        10,
        len(QUIET) - 10 + 1 + len(LOUD_STORED),
        1 + 5,
        len(LAST) - 5,
    )


def test_a_stream_whose_events_json_spans_several_lines_keeps_its_lines_and_chunks():
    """An event walked as one document keeps its line count, so its chunks are carried over by line.

    A boundary in the line that takes the document, or in a line left empty, moves to its end."""
    event = [b"event: x\n", b"data: {\n", b'data:   "client_secret": "s3cret"\n', b"data: }\n"]
    sent = b"".join(event) + b"\n" + LAST
    stored_event = [
        event[0],
        b'data: {"client_secret":"' + _ph("s3cret").encode() + b'"}\n',
        b"data:\n",
        b"data:\n",
    ]
    cuts = (3, len(event[0]) + 4, sum(map(len, event[:3])) + 2, len(sent) - 4)
    chunks = tuple(b - a for a, b in zip([0, *cuts], [*cuts, len(sent)], strict=True))
    stored = _stream(sent, chunks)
    assert stored.response is not None
    assert stored.response.body == b"".join(stored_event) + b"\n" + LAST
    ends = [sum(map(len, stored_event[: i + 1])) for i in range(4)]
    assert stored.stream_chunks == (
        3,
        ends[1] - 3,
        ends[3] - ends[1],
        len(stored.response.body) - 4 - ends[3],
        4,
    )


def test_a_secret_split_across_two_chunks_is_redacted_whole():
    """The joined body is redacted, so a key cut in two by a chunk boundary is redacted whole."""
    cut = LOUD.index(b"abc123")
    stored = _stream(LOUD, (cut, len(LOUD) - cut))
    assert stored.response is not None
    assert stored.response.body == LOUD_STORED
    assert b"sk_live" not in stored.response.body
    assert stored.stream_chunks == (len(LOUD_STORED),)


def test_two_boundaries_that_land_at_the_end_of_one_changed_line_make_one_chunk():
    sent = LOUD + LAST
    stored = _stream(sent, (5, 10, len(LOUD) - 15 + 3, len(LAST) - 3))
    assert stored.stream_chunks == (len(LOUD_STORED), 3, len(LAST) - 3)


def test_a_stream_redaction_left_alone_keeps_its_chunks():
    sent = QUIET + b"\n" + LAST
    chunks = (7, len(sent) - 7 - 2, 2)
    assert _stream(sent, chunks).stream_chunks == chunks


def test_a_stream_whose_lines_do_not_pair_up_after_redaction_is_one_chunk():
    """A one-document JSON body re-serialized compactly can join its lines, so it is one chunk."""
    sent = b'{\n  "key": "' + LIVE_KEY.encode() + b'"\n}\n'
    stored = _stream(sent, (4, len(sent) - 4))
    assert stored.response is not None
    assert stored.response.body == b'{"key":"' + _ph(LIVE_KEY).encode() + b'"}'
    assert stored.stream_chunks == (len(stored.response.body),)


def test_a_stream_that_could_not_be_redacted_is_one_chunk(monkeypatch):
    def boom(*args, **kwargs):
        raise ValueError("parser broke")

    monkeypatch.setattr(redact, "_redact_document", boom)
    stored = _stream(LOUD + LAST, (4, len(LOUD) + len(LAST) - 4))
    assert stored.response is not None and stored.response.body == FAILED_BODY
    assert stored.stream_chunks == (len(FAILED_BODY),)
    assert Flag.REDACTION_FAILED in stored.flags


def test_every_split_of_a_stream_still_splits_its_redacted_body():
    """Every split of a stream gives positive chunks that add up to the stored body."""
    sent = QUIET + LOUD + b"\r\n" + LAST
    for first in range(1, len(sent)):
        for second in range(first + 1, len(sent)):
            chunks = (first, second - first, len(sent) - second)
            stored = _stream(sent, chunks)
            assert stored.response is not None
            assert sum(stored.stream_chunks) == len(stored.response.body), chunks
            assert all(length > 0 for length in stored.stream_chunks), chunks
            if first < len(QUIET):
                assert stored.stream_chunks[0] == first, chunks


def test_a_boundary_between_a_carriage_return_and_its_line_feed_stays_in_that_line():
    """A boundary between CR and LF stays put in an unchanged line, and moves past the LF if not."""
    quiet, loud, loud_stored = (line.replace(b"\n", b"\r\n") for line in (QUIET, LOUD, LOUD_STORED))
    sent = quiet + loud + LAST
    chunks = (len(quiet) - 1, len(loud), len(LAST) + 1)  # after each CR, before its LF
    assert _stream(sent, chunks).stream_chunks == (
        len(quiet) - 1,
        1 + len(loud_stored),
        len(LAST),
    )


def test_rechunk_never_raises_and_still_splits_the_stored_body():
    """Chunks that do not add up to the body store it as one chunk rather than raise."""
    assert redact._rechunk(QUIET + LOUD, QUIET + LOUD_STORED, (1, 999, 5)) == (
        len(QUIET + LOUD_STORED),
    )
    assert redact._rechunk(LOUD, LOUD_STORED, (0, -4, len(LOUD) + 4)) == (len(LOUD_STORED),)
    assert redact._rechunk(LOUD, b"", (len(LOUD),)) == ()


# Every secret shape redaction knows, each a line of its own among lines nothing changes.
_STREAM_SECRETS = (
    LIVE_KEY,
    STRIPE_TEST + "Q9",
    STRIPE_RESTRICTED + "zz9",
    STRIPE_WEBHOOK + "abc",
    SLACK_BOT + "123-abc",
    SLACK_APP + "1-A0-xyz",
    GITHUB + "a" * 36,
    GITHUB_PAT + "11AA_bb",
    AWS + "ABCDEFGHIJKLMNOP",
    ANTHROPIC + "api03-xy_z",
    OPENAI_PROJECT + "q" * 22,
)
# Multi-byte characters, so a boundary can fall inside one, and ones `str.splitlines` ends a line
# at but SSE does not: a remap that split text and bytes differently would pair the wrong lines.
_ODD = ("é", "日本", "\U0001f600", " ", " ", "\x85", "\x0b", "\x0c", "\x1c")


def _random_stream(rng) -> bytes:
    lines = []
    for _ in range(rng.randrange(1, 7)):
        secret, odd = rng.choice(_STREAM_SECRETS), rng.choice(_ODD)
        line = rng.choice(
            (
                f'data: {{"text":"{odd} {secret}"}}',  # JSON a shape changes
                f'data: {{"token":"{odd}"}}',  # JSON its key changes
                f'data: {{"text":"key:\\n{secret}"}}',  # a shape after a JSON escape
                f"data: {odd} {secret} as text",  # text a shape changes
                f'data: {{"text":"{odd} quiet"}}',  # nothing changes
                f"event: {odd}",
                # an event of its own whose JSON spans lines: only joined is it one document
                f'\r\ndata: {{\ndata: "token": "hunter2",\rdata: "text": "{secret}"\r\ndata: }}\n',
                # two of a model's deltas, each an event of its own, that send a key in pieces
                f'\r\ndata: {{"choices":[{{"delta":{{"content":" {secret[:5]}"}}}}]}}\n\n'
                f'data: {{"choices":[{{"delta":{{"content":"{secret[5:]} "}}}}]}}\n',
                "",
            )
        )
        lines.append(line + rng.choice(("\n", "\r", "\r\n")))
    text = "".join(lines)
    return (text.rstrip("\r\n") if rng.random() < 0.3 else text).encode()


def test_any_split_of_any_stream_is_carried_over_to_its_redacted_body():
    """The stream-chunk rule holds boundary by boundary over seeded random streams and cuts.

    Cuts fall inside a secret, a character or a CRLF, and one byte from either end."""
    rng = random.Random(71)
    for _ in range(1000):
        sent = _random_stream(rng)
        if not sent:  # a stream that sent no body has no chunks to carry over
            continue
        cuts = sorted(rng.sample(range(1, len(sent)), min(len(sent) - 1, rng.randrange(6))))
        chunks = tuple(b - a for a, b in zip([0, *cuts], [*cuts, len(sent)], strict=True))
        stored = _stream(sent, chunks)
        assert stored.response is not None
        body, got = stored.response.body, stored.stream_chunks
        case = (sent, chunks, body, got)
        assert all(length > 0 for length in got) and sum(got) == len(body), case
        assert not any(secret.encode() in body for secret in _STREAM_SECRETS), case
        assert not any(secret[5:].encode() in body for secret in _STREAM_SECRETS), case
        assert b"hunter2" not in body, case
        old, new = sent.splitlines(keepends=True), body.splitlines(keepends=True)
        assert len(old) == len(new), case
        old_starts = [sum(map(len, old[:i])) for i in range(len(old))]
        new_starts = [sum(map(len, new[:i])) for i in range(len(new))]
        expected = set()
        for boundary in (sum(chunks[: i + 1]) for i in range(len(chunks) - 1)):
            i = max(i for i, start in enumerate(old_starts) if start < boundary)
            if old[i] == new[i]:
                expected.add(new_starts[i] + boundary - old_starts[i])
            else:
                expected.add(new_starts[i] + len(new[i]))
        expected.discard(len(body))
        assert {sum(got[: i + 1]) for i in range(len(got) - 1)} == expected, case


def test_a_streamed_body_redaction_leaves_alone_keeps_its_chunks_whatever_its_content_type():
    """`_rechunk` follows the body, not the content type."""
    for content_type in ("text/event-stream", "application/x-ndjson", "text/plain"):
        response = Response(status=200, headers=(("content-type", content_type),), body=QUIET)
        ex = _exchange(response=response, stream_chunks=(3, len(QUIET) - 3))
        assert redact_exchange(ex, KEY).stream_chunks == (3, len(QUIET) - 3)
        loud = Response(status=200, headers=(("content-type", content_type),), body=LOUD + LAST)
        ex = _exchange(response=loud, stream_chunks=(3, len(LOUD) + len(LAST) - 3))
        assert redact_exchange(ex, KEY).stream_chunks == (len(LOUD_STORED), len(LAST))


# ------------------------------------------------------------------------------ a secret in pieces


def _text_delta(text: str, index: int = 0) -> dict[str, Any]:
    """An Anthropic event carrying a piece of content block `index`'s text."""
    delta = {"type": "text_delta", "text": text}
    return {"type": "content_block_delta", "index": index, "delta": delta}


def _chat_delta(text: str, choice: int = 0) -> dict[str, Any]:
    """An OpenAI chat event carrying a piece of choice `choice`'s content."""
    return {"choices": [{"index": choice, "delta": {"content": text}}]}


def _tool_call_delta(text: str, call: int = 0) -> dict[str, Any]:
    """An OpenAI chat event carrying a piece of tool call `call`'s arguments."""
    piece = {"index": call, "function": {"arguments": text}}
    return {"choices": [{"index": 0, "delta": {"tool_calls": [piece]}}]}


def _responses_delta(text: str, item: str = "msg_1", kind: str = "output_text") -> dict[str, Any]:
    """An OpenAI Responses event carrying a piece of item `item`'s text or arguments."""
    return {"type": f"response.{kind}.delta", "item_id": item, "output_index": 0, "delta": text}


def _model_stream(events: list[dict[str, Any]], compact: tuple[int, ...] = ()) -> bytes:
    """`events` as SSE, as a model API sends them: each event named by its type, if it has one.

    The events at `compact` are in the compact JSON redaction stores a changed document in."""
    return "".join(
        (f"event: {event['type']}\n" if "type" in event else "")
        + "data: "
        + (json.dumps(event, separators=(",", ":")) if i in compact else json.dumps(event))
        + "\n\n"
        for i, event in enumerate(events)
    ).encode()


def test_a_secret_a_model_streams_in_pieces_is_stored_as_its_placeholder_in_the_first_piece():
    """A key split across a stream's deltas is hidden whole, as its placeholder in the first piece.

    Its text is cut from the other pieces it crosses. Only the events it crosses change, each in
    its own line, so the stream still reads as the model's text with the placeholder in it."""
    start = {"type": "message_start", "message": {"id": "msg_1", "content": []}}
    stop = {"type": "message_stop"}
    sent = ["The key is sk_l", "ive_ab", "c1", "23. Keep it."]
    stored = [f"The key is {_ph(LIVE_KEY)}", "", "", ". Keep it."]
    assert _response_body(_model_stream([start, *map(_text_delta, sent), stop]), SSE) == (
        _model_stream([start, *map(_text_delta, stored), stop], compact=(1, 2, 3, 4))
    )


# An event carrying a piece of streamed text, made from the piece.
_Piece = Callable[[str], dict[str, Any]]
# A piece of streamed text in each shape a model sends one in.
_PIECES: dict[str, _Piece] = {
    "anthropic text": _text_delta,
    "anthropic tool input": lambda text: {
        "type": "content_block_delta",
        "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": text},
    },
    "openai chat": _chat_delta,
    "openai chat tool call": _tool_call_delta,
    "openai responses text": _responses_delta,
    "openai responses arguments": lambda text: _responses_delta(
        text, "fc_1", "function_call_arguments"
    ),
}


@pytest.mark.parametrize("shape", _PIECES)
def test_a_secret_in_pieces_is_hidden_whole_in_each_shape_a_model_streams_text_in(shape):
    """Text and tool arguments alike: the tool call's JSON still parses once joined."""
    piece = _PIECES[shape]
    sent = ['{"q": "', LIVE_KEY[:4], LIVE_KEY[4:9], LIVE_KEY[9:] + '"}']
    stored = ['{"q": "', _ph(LIVE_KEY), "", '"}']
    assert _response_body(_model_stream([piece(text) for text in sent]), SSE) == (
        _model_stream([piece(text) for text in stored], compact=(1, 2, 3))
    )


# Two texts that one stream can carry side by side.
_TWO_TEXTS: dict[str, tuple[_Piece, _Piece]] = {
    "content blocks": (_text_delta, lambda text: _text_delta(text, 1)),
    "choices": (_chat_delta, lambda text: _chat_delta(text, 1)),
    "tool calls": (_tool_call_delta, lambda text: _tool_call_delta(text, 1)),
    "content and a tool call": (_chat_delta, _tool_call_delta),
    "items": (_responses_delta, lambda text: _responses_delta(text, "msg_2")),
    "text and arguments": (
        _responses_delta,
        lambda text: _responses_delta(text, kind="function_call_arguments"),
    ),
    "providers": (_text_delta, _chat_delta),
}


@pytest.mark.parametrize("texts", _TWO_TEXTS)
def test_each_text_s_pieces_are_joined_apart_from_another_s_and_past_its_events(texts):
    """Pieces are joined per content block, choice, tool call, item and provider, in order.

    A key no one text holds is no secret, and one text's key is found past the other text's
    events between its pieces."""
    one, other = _TWO_TEXTS[texts]
    apart = _model_stream([one("x sk_live_"), other("abc123 y"), one(" z")])
    assert _response_body(apart, SSE) == apart
    sent = _model_stream([one("x sk_live_"), other("q"), one("abc123 y")])
    stored = [one(f"x {_ph(LIVE_KEY)}"), other("q"), one(" y")]
    assert _response_body(sent, SSE) == _model_stream(stored, compact=(0, 2))


def test_a_stream_no_secret_crosses_is_redacted_event_by_event():
    """A stream whose pieces no key crosses is stored as any SSE is, event by event.

    A quiet one keeps its bytes, and a key whole in one piece is hidden by its event's walk, even
    one glued to the piece before."""
    quiet = _model_stream([_text_delta("sk_live"), _text_delta("_ x"), _text_delta("abc123")])
    assert _response_body(quiet, SSE) == quiet
    sent = [_text_delta(f"see {LIVE_KEY} "), _text_delta("a"), _text_delta(LIVE_KEY)]
    stored = [_text_delta(f"see {_ph(LIVE_KEY)} "), _text_delta("a"), _text_delta(_ph(LIVE_KEY))]
    assert _response_body(_model_stream(sent), SSE) == _model_stream(stored, compact=(0, 2))


def test_a_key_a_piece_shows_only_the_start_of_is_hidden_whole():
    """A piece that ends partway through a key matches as a shorter key; the whole key is hidden.

    So is a key whose last character alone is in the next piece."""
    for cut in (10, len(LIVE_KEY) - 1):
        sent = [_text_delta("x " + LIVE_KEY[:cut]), _text_delta(LIVE_KEY[cut:] + " y")]
        stored = _response_body(_model_stream(sent), SSE)
        assert stored == _model_stream(
            [_text_delta(f"x {_ph(LIVE_KEY)}"), _text_delta(" y")], compact=(0, 1)
        )
        assert _ph(LIVE_KEY[:cut]).encode() not in stored


def test_an_event_a_secret_crosses_is_redacted_whole_its_other_fields_and_lines_too():
    """The events a key crosses are still walked as JSON and their other lines scanned.

    So the piece's own shapes, shapes after an escaped letter in it and in another field, a secret
    key's value and a shape on another line of the event are hidden as in any other event."""
    first = (
        '{"type":"content_block_delta","index":0,"token":"t1","note":"\\u0041' + TEST_KEY + '",'
        '"delta":{"type":"text_delta","text":"\\u0041rk_live_zz ' + LIVE_KEY[:9] + '"}}'
    )
    sent = f"event: content_block_delta\nid: {TEST_KEY}\ndata: {first}\n\n".encode()
    sent += _model_stream([_text_delta(LIVE_KEY[9:])])
    walked = _text_delta(f"A{_ph(STRIPE_RESTRICTED + 'zz')} {_ph(LIVE_KEY)}")
    walked = {
        "type": walked["type"],
        "index": 0,
        "token": _ph("t1"),
        "note": "A" + _ph(TEST_KEY),
        "delta": walked["delta"],
    }
    expected = f"event: content_block_delta\nid: {_ph(TEST_KEY)}\n".encode()
    expected += _model_stream([walked], compact=(0,)).removeprefix(b"event: content_block_delta\n")
    expected += _model_stream([_text_delta("")], compact=(0,))
    assert _response_body(sent, SSE) == expected


def test_keys_back_to_back_in_pieces_each_go_in_their_own_first_piece():
    """Each key a stream sends in pieces takes its own placeholder, in the piece it starts in.

    A piece the first key ends in keeps what follows it, up to where the next key starts. An
    empty piece between two of a key's pieces is left as it was sent."""
    sent = ["a sk_live_", "", "abc ", "sk_live_", "zz9 b"]
    stored = [f"a {_ph(LIVE_KEY_SHORT)}", "", " ", _ph(STRIPE_LIVE + "zz9"), " b"]
    assert _response_body(_model_stream(list(map(_chat_delta, sent))), SSE) == (
        _model_stream(list(map(_chat_delta, stored)), compact=(0, 2, 3, 4))
    )


def test_an_event_that_holds_pieces_of_two_texts_takes_both_new_texts():
    """One event can carry a piece of each of several texts, as OpenAI's choices do."""

    def both(first: str, second: str) -> dict[str, Any]:
        choices = [_chat_delta(first)["choices"][0], _chat_delta(second, 1)["choices"][0]]
        return {"choices": choices}

    sent = [both("x sk_live_", "y rk_live_"), both("abc123", "zz9")]
    hidden = (_ph(LIVE_KEY), _ph(STRIPE_RESTRICTED + "zz9"))
    stored = [both(f"x {hidden[0]}", f"y {hidden[1]}"), both("", "")]
    assert _response_body(_model_stream(sent), SSE) == _model_stream(stored, compact=(0, 1))


def test_a_shape_after_an_escaped_letter_that_runs_into_a_split_key_is_hidden_with_it():
    """A shape after an escaped letter that overlaps a key split across pieces is hidden with it.

    The two are one secret, so neither leaves the other's tail behind."""
    glued = ANTHROPIC + "ab_" + STRIPE_LIVE
    first = '{"choices":[{"index":0,"delta":{"content":"\\u0041' + glued + '"}}]}'
    sent = f"data: {first}\n\n".encode() + _model_stream([_chat_delta("abc123 y")])
    stored = [_chat_delta("A" + _ph(glued + "abc123")), _chat_delta(" y")]
    assert _response_body(sent, SSE) == _model_stream(stored, compact=(0, 1))


def _content_events(raws: list[str]) -> bytes:
    """An OpenAI chat stream whose pieces of content are `raws`, each spelled as raw JSON."""
    return "".join(
        f'data: {{"choices":[{{"index":0,"delta":{{"content":"{raw}"}}}}]}}\n\n' for raw in raws
    ).encode()


def _stored_text(body: bytes) -> str:
    """The content an OpenAI chat stream's stored events join into, read without `stream_deltas`."""
    events = [json.loads(line[6:]) for line in body.splitlines() if line.startswith(b"data: ")]
    return "".join(event["choices"][0]["delta"]["content"] for event in events)


# A raw JSON string's characters, each as it is spelled: an escape is one, a surrogate pair's two.
_RAW_CHARACTER = re.compile(r"\\ud8[0-9a-f]{2}\\ud[c-f][0-9a-f]{2}|\\u[0-9A-Fa-f]{4}|\\.|.")


@pytest.mark.parametrize(
    "before",
    ["", "x ", "(", "%20", "a\\\\n", "\\n", "\\u0041", "q \\u0037", "\\u00e9", "\\ud83d\\ude00"],
)
@pytest.mark.parametrize("after", ["", " y", "y", "Z9", "-"])
def test_a_text_sent_in_two_pieces_is_stored_as_it_is_sent_whole_wherever_it_is_cut(before, after):
    """Wherever a stream cuts its text, the stored pieces join into what one piece is stored as.

    So no piece keeps a key's tail, even where what lets the key start (a separator, a `%20`, an
    escaped letter) is in the piece before, and a key whole in one piece is stored as any is."""
    raw = [*_RAW_CHARACTER.findall(before), *LIVE_KEY, *_RAW_CHARACTER.findall(after)]
    whole = _stored_text(_response_body(_content_events(["".join(raw)]), SSE))
    assert LIVE_KEY not in whole
    for cut in range(1, len(raw)):
        sent = _content_events(["".join(raw[:cut]), "".join(raw[cut:])])
        assert _stored_text(_response_body(sent, SSE)) == whole, cut


def test_a_key_after_an_escaped_letter_is_hidden_whole_wherever_the_stream_cuts_it():
    """The shape rule lets a key follow a letter its JSON escapes, in the pieces it is sent in too.

    The key goes, as one placeholder, in the piece it starts in, after the escaped letter."""
    sent = ["Key: ", "x \\u0041", LIVE_KEY[:9], LIVE_KEY[9:] + " y"]
    stored = ["Key: ", "x \\u0041", _ph(LIVE_KEY), " y"]
    assert _response_body(_content_events(sent), SSE) == _content_events(stored)
    sent = ["\\u0041" + LIVE_KEY[:9], LIVE_KEY[9:] + " y"]
    stored = ["A" + _ph(LIVE_KEY), " y"]
    assert _response_body(_content_events(sent), SSE) == _content_events(stored)


def test_a_key_a_piece_shows_alone_is_hidden_in_a_piece_a_split_key_touches_too():
    """A piece's own keys are hidden in it as its event's walk hides them, beside a split key.

    Here the piece's first key reads glued to the piece before once joined, so only the piece's
    own shapes find it."""
    sent = ["q", f"{LIVE_KEY} sk_live_", "zz9 b"]
    stored = ["q", f"{_ph(LIVE_KEY)} {_ph(STRIPE_LIVE + 'zz9')}", " b"]
    assert _response_body(_content_events(sent), SSE) == _content_events(stored)


def test_a_glued_shape_another_field_of_its_event_spells_is_hidden_in_a_piece_a_key_touches():
    """A shape an escape glues anywhere in an event is hidden in a piece a split key rewrites.

    The event's walk hides it in every string of the event, and so does the rewrite."""
    glued = STRIPE_LIVE + "X1"
    first = (
        '{"type":"content_block_delta","index":0,"note":"\\u0041' + glued + '",'
        '"delta":{"type":"text_delta","text":"B' + glued + ' and sk_live_"}}'
    )
    sent = f"data: {first}\n\n".encode() + _model_stream([_text_delta("abc9 ok")])
    walked = _text_delta(f"B{_ph(glued)} and {_ph(STRIPE_LIVE + 'abc9')}")
    walked = {
        "type": walked["type"],
        "index": 0,
        "note": "A" + _ph(glued),
        "delta": walked["delta"],
    }
    expected = b"data: " + json.dumps(walked, separators=(",", ":")).encode() + b"\n\n"
    expected += _model_stream([_text_delta(" ok")], compact=(0,))
    assert _response_body(sent, SSE) == expected


def test_a_placeholder_does_not_make_the_text_after_it_a_key():
    """A key the joined text holds is hidden as a JSON body hides it, and the walk ends there.

    The text after the key is glued to it as sent, so it is no key, whichever piece it is in."""
    glued = AWS + "ABCDEFGHIJKLMNOP" + LIVE_KEY
    as_json = json.loads(_body(json.dumps([glued]).encode(), JSON))[0]
    assert as_json == _ph(AWS + "ABCDEFGHIJKLMNOP") + LIVE_KEY
    for cut in (0, 5, 22):
        sent = _model_stream([_chat_delta(glued[:cut]), _chat_delta(glued[cut:])])
        assert _stored_text(_response_body(sent, SSE)) == as_json, cut


def test_a_piece_in_an_event_of_several_data_lines_is_joined_with_the_rest_of_its_text():
    """An event whose `data:` lines join into a delta is a piece of its text too.

    It is rewritten as such an event is: the document on its first `data:` line, the others left
    empty."""
    sent = b'data: {"choices": [{"index": 0,\ndata: "delta": {"content": "x sk_live_"}}]}\n\n'
    sent += _model_stream([_chat_delta("abc123")])
    walked = _model_stream([_chat_delta(f"x {_ph(LIVE_KEY)}")], compact=(0,))
    expected = walked.replace(b"\n\n", b"\ndata:\n\n")
    assert _response_body(sent, SSE) == expected + _model_stream([_chat_delta("")], compact=(0,))


def test_a_secret_in_pieces_of_a_shape_irimi_does_not_know_is_redacted_event_by_event():
    """Pieces in a shape `stream_deltas` does not know are redacted as any SSE is.

    So a key that a thinking block, or another provider, sends across events is stored in
    pieces."""
    thinking = [
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": t},
        }
        for t in ("a sk_live_", "abc123")
    ]
    gemini = [
        {"candidates": [{"content": {"parts": [{"text": t}]}}]} for t in ("a sk_live_", "abc123")
    ]
    for events in (thinking, gemini):
        sent = _model_stream(events)
        assert _response_body(sent, SSE) == sent


def test_a_stream_a_secret_crosses_keeps_its_lines_and_carries_its_chunks_over():
    """Each event a key crosses keeps its lines, so its chunks carry over line by line.

    A boundary in a line the key changed moves to its end, and one in any other line stays."""
    sent = _model_stream([_text_delta("a sk_live_"), _text_delta("abc123 b"), _text_delta("c")])
    body = _model_stream(
        [_text_delta(f"a {_ph(LIVE_KEY)}"), _text_delta(" b"), _text_delta("c")], compact=(0, 1)
    )
    old, new = sent.splitlines(keepends=True), body.splitlines(keepends=True)
    assert len(old) == len(new) == 9

    def start(lines: list[bytes], i: int) -> int:
        return sum(map(len, lines[:i]))

    cuts = [start(old, 1) + 9, start(old, 4) + 3, start(old, 7) + 5]
    stored = _stream(sent, tuple(b - a for a, b in pairwise([0, *cuts, len(sent)])))
    assert stored.response is not None and stored.response.body == body
    moved = [start(new, 2), start(new, 5), start(new, 7) + 5]
    assert stored.stream_chunks == tuple(b - a for a, b in pairwise([0, *moved, len(body)]))


def test_an_event_a_secret_crosses_that_repeats_a_key_fails_the_body_closed():
    """The event is walked as any JSON is, so a repeated key fails the body closed."""
    sent = (
        b'data: {"id": 1, "id": 2, "choices": [{"index": 0, "delta": {"content": "sk_live_"}}]}\n\n'
    )
    sent += _model_stream([_chat_delta("abc123")])
    stored = _stream(sent, (len(sent),))
    assert stored.response is not None and stored.response.body == FAILED_BODY
    assert Flag.REDACTION_FAILED in stored.flags


def test_a_stream_whose_pieces_cannot_be_read_fails_closed(monkeypatch):
    def boom(event):
        raise ValueError("shapes broke")

    monkeypatch.setattr(stream_deltas, "deltas", boom)
    sent = _model_stream([_text_delta("quiet")])
    stored = _stream(sent, (3, len(sent) - 3))
    assert stored.response is not None and stored.response.body == FAILED_BODY
    assert stored.stream_chunks == (len(FAILED_BODY),)
    assert Flag.REDACTION_FAILED in stored.flags


# ------------------------------------------------------------------------------ rule 7: fail closed


def test_a_parser_that_raises_stores_neither_body_and_flags_the_exchange(monkeypatch):
    request = _request(headers=(JSON,), body=b'{"amount": 100}')
    response = Response(status=200, headers=(JSON,), body=b'{"id": "re_1"}')
    ex = _exchange(request, response, flags=())

    def boom(*args, **kwargs):
        raise RuntimeError("parser broke")

    monkeypatch.setattr(redact.json, "loads", boom)  # type: ignore[attr-defined]
    stored = redact_exchange(ex, KEY)
    assert stored.response is not None
    assert (stored.request.body, stored.response.body) == (FAILED_BODY, FAILED_BODY)
    assert stored.flags == (Flag.REDACTION_FAILED,)
    assert stored.request.headers == request.headers
    again = redact_exchange(dataclasses.replace(ex, flags=stored.flags), KEY)
    assert again.flags.count(Flag.REDACTION_FAILED) == 1


@pytest.mark.parametrize(
    "body",
    [
        b'{"token": "tok_one", "token": null}',
        b'{"a": [{"password": "hunter2", "password": ""}]}',
        b'{"token": "tok_two", "n": ' + b"1" * 5000 + b"}",
    ],
    ids=["a-repeated-key", "a-repeated-key-deeper", "an-integer-past-the-digit-limit"],
)
def test_json_the_walk_cannot_see_whole_fails_closed_rather_than_scanned_as_text(body):
    """A repeated key or an over-long integer fails closed rather than being scanned as text.

    `json.loads` keeps a repeated key's last value and refuses a long integer."""
    stored = redact_exchange(_exchange(_request(headers=(JSON,), body=body)), KEY)
    assert stored.request.body == FAILED_BODY
    assert stored.flags == (Flag.REDACTION_FAILED,)


def test_a_body_too_deep_to_redact_fails_closed_and_the_log_names_no_value(caplog):
    """A body too deep to walk is not stored, whether `json.loads` or the walk raises."""
    body = b"[" * 100_000 + f'"{LIVE_KEY_SHORT}"'.encode() + b"]" * 100_000
    with caplog.at_level(logging.WARNING, logger="irimi.record.redact"):
        stored = redact_exchange(_exchange(_request(headers=(JSON,), body=body)), KEY)
    assert stored.request.body == FAILED_BODY
    assert Flag.REDACTION_FAILED in stored.flags
    assert "the request body" in caplog.text
    assert "sk_live" not in caplog.text


def test_a_header_that_cannot_be_hashed_fails_closed_alone(caplog):
    """A header with a lone surrogate fails closed alone, and the log names only the error type."""
    headers = (("authorization", "Bearer \udcff"), ("accept", "*/*"))
    with caplog.at_level(logging.WARNING, logger="irimi.record.redact"):
        stored = redact_exchange(_exchange(_request(headers=headers)), KEY)
    assert stored.request.headers == (
        ("authorization", redact.REDACTION_FAILED),
        ("accept", "*/*"),
    )
    assert stored.flags == (Flag.REDACTION_FAILED,)
    assert "UnicodeEncodeError" in caplog.text
    assert "\udcff" not in caplog.text
    assert "\\udcff" not in caplog.text  # the exception's message spells it this way


def test_a_path_that_cannot_be_hashed_fails_closed_and_still_starts_with_a_slash():
    ex = _exchange(_request(host="hooks.slack.com", path="/services/\udcff"))
    stored = redact_exchange(ex, KEY)
    assert stored.request.path == "/" + redact.REDACTION_FAILED
    assert stored.flags == (Flag.REDACTION_FAILED,)


def test_a_lone_surrogate_in_a_body_that_changed_fails_that_body_alone():
    """`json.loads` accepts `"\\ud800"`, and the re-serialized body cannot be encoded as UTF-8."""
    request = _request(headers=(JSON,), body=b'{"token": "t1", "note": "\\ud800"}')
    response = Response(status=200, headers=(JSON,), body=b'{"id": "re_1"}')
    stored = redact_exchange(_exchange(request, response), KEY)
    assert stored.request.body == FAILED_BODY
    assert stored.response is not None
    assert stored.response.body == b'{"id": "re_1"}'
    assert stored.flags == (Flag.REDACTION_FAILED,)


# ------------------------------------------------------------------------------ redact_json


def test_redact_json_hides_trigger_and_tool_arguments():
    args: dict[str, JSONValue] = {
        "argv": ["agent.py", "--key", TEST_KEY],
        "config": {"API_KEY": "v", "n": 2},
    }
    assert redact_json(args, KEY) == {
        "argv": ["agent.py", "--key", _ph(TEST_KEY)],
        "config": {"API_KEY": _ph("v"), "n": 2},
    }
    assert args["config"] == {"API_KEY": "v", "n": 2}
    untouched: dict[str, JSONValue] = {"a": [1, 2.5, None, True, "x"]}
    assert redact_json(untouched, KEY) is untouched


def test_redact_json_fails_closed_on_a_value_that_is_not_json():
    """A tuple is not JSON, and `json.dumps` would still write its secret as an array."""
    assert redact_json((LIVE_KEY_SHORT,), KEY) == redact.REDACTION_FAILED  # type: ignore[arg-type]
    assert redact_json({"a": {"b"}}, KEY) == redact.REDACTION_FAILED  # type: ignore[dict-item]


def test_redact_json_fails_closed_on_a_value_too_deep_to_walk():
    deep: list = []
    for _ in range(100_000):
        deep = [deep]
    assert redact_json(deep, KEY) == redact.REDACTION_FAILED


# ------------------------------------------------------------------------------ the key


def test_load_key_creates_a_0600_key_of_32_bytes_once(tmp_path):
    home = tmp_path / "home"
    key = redact.load_key(home)
    path = home / paths.REDACT_KEY_NAME
    assert len(key) == 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert redact.load_key(home) == key
    assert path.read_bytes() == key
    assert sorted(p.name for p in home.iterdir()) == [paths.REDACT_KEY_NAME]


def test_concurrent_load_key_calls_return_one_key(tmp_path):
    home = tmp_path / "home"
    barrier = threading.Barrier(8)
    keys: list[bytes] = []

    def load() -> None:
        barrier.wait()
        keys.append(redact.load_key(home))

    threads = [threading.Thread(target=load) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(keys) == 8
    assert set(keys) == {(home / paths.REDACT_KEY_NAME).read_bytes()}
    assert sorted(p.name for p in home.iterdir()) == [paths.REDACT_KEY_NAME]


def test_a_process_that_loses_the_race_reads_the_winners_key(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    winner = b"w" * 32
    real_link = os.link

    def link_after_the_winner(src, dst):
        (home / paths.REDACT_KEY_NAME).write_bytes(winner)
        real_link(src, dst)

    monkeypatch.setattr(redact.os, "link", link_after_the_winner)  # type: ignore[attr-defined]
    assert redact.load_key(home) == winner
    assert sorted(p.name for p in home.iterdir()) == [paths.REDACT_KEY_NAME]


def test_a_key_file_irimi_did_not_write_is_refused(tmp_path):
    (tmp_path / paths.REDACT_KEY_NAME).write_bytes(b"short")
    with pytest.raises(redact.RedactKeyError, match="holds 5 bytes, not 32"):
        redact.load_key(tmp_path)


def test_a_key_path_that_is_not_a_regular_file_is_refused(tmp_path):
    """A directory or a dangling symlink at the key path is refused with a message."""
    for name, make in (
        ("dir", lambda p: p.mkdir()),
        ("dangling", lambda p: p.symlink_to(tmp_path / "missing")),
    ):
        home = tmp_path / name
        home.mkdir()
        make(home / paths.REDACT_KEY_NAME)
        with pytest.raises(redact.RedactKeyError, match="not a regular file"):
            redact.load_key(home)


def test_a_symlinked_key_is_followed_so_two_installs_can_share_one(tmp_path):
    """A symlinked key, as a Kubernetes Secret volume mounts one, is read and never replaced."""
    shared = tmp_path / "secret" / "redact.key"
    shared.parent.mkdir()
    shared.write_bytes(b"k" * 32)
    home = tmp_path / "home"
    home.mkdir()
    (home / paths.REDACT_KEY_NAME).symlink_to(shared)
    assert redact.load_key(home) == b"k" * 32
    assert shared.read_bytes() == b"k" * 32


def test_load_key_creates_a_missing_home_0700(tmp_path):
    """`load_key` makes a missing home 0700, and leaves an existing home's mode alone."""
    old = os.umask(0o022)
    try:
        home = tmp_path / "a" / "home"
        redact.load_key(home)
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        mine = tmp_path / "mine"
        mine.mkdir(mode=0o755)
        redact.load_key(mine)
        assert stat.S_IMODE(mine.stat().st_mode) == 0o755
    finally:
        os.umask(old)


# Waits for the test's go file, then loads the key once and prints it. A separate interpreter per
# racer, because `O_CREAT | O_EXCL` and `os.link` are there for another PROCESS: threads share one.
KEY_RACER = """
import sys, time
from pathlib import Path
from irimi.record import redact

home, go, ready = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
ready.touch()
while not go.exists():
    time.sleep(0.001)
print(redact.load_key(home).hex())
"""


def test_load_key_raced_by_separate_processes_gives_each_the_one_0600_key(tmp_path):
    """Eight processes racing to create the key all read the winner's: 32 bytes, mode 0600.

    No temporary file is left behind."""
    home = tmp_path / "fresh-home"
    go = tmp_path / "go"
    ready = [tmp_path / f"ready-{i}" for i in range(8)]
    racers = [
        subprocess.Popen(
            [sys.executable, "-c", KEY_RACER, str(home), str(go), str(r)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for r in ready
    ]
    try:
        eventually(
            lambda: all(r.exists() for r in ready),
            timeout=20,
            interval=0.005,
            message="a racer never started",
        )
        go.touch()
        outs = [racer.communicate(timeout=20) for racer in racers]
    finally:
        for racer in racers:
            racer.kill()
    assert [racer.returncode for racer in racers] == [0] * 8, [err for _, err in outs]
    (key,) = {bytes.fromhex(out.decode().strip()) for out, _ in outs}
    assert len(key) == redact.KEY_BYTES
    path = home / paths.REDACT_KEY_NAME
    assert path.read_bytes() == key
    assert stat.S_IMODE(path.stat().st_mode) == files.FILE_MODE
    assert [p.name for p in home.iterdir()] == [paths.REDACT_KEY_NAME]
