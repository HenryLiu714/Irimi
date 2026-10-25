"""The engine forwards reads live and fakes writes, through the forward proxy."""

import asyncio
import http.client
import json
import socket
from pathlib import Path
from unittest import mock

import httpx
import pytest
import requests
from urllib3.connection import HTTPConnection

from irimi.config import ca, paths
from irimi.core.exchange import Flag, Response
from irimi.decide.overlay import NoOverlay, Overlaid
from irimi.decide.policy import Decided, Respond, ShadowPolicy
from irimi.engine import EngineConfig, EngineStartError, mitm
from irimi.engine.mitm import MitmEngine
from tests.support.doubles import NullStore
from tests.support.engine import bare_flow, engine_config, start_engine, via_proxy
from tests.support.maps import SLACK_MAP, map_index


def test_a_get_is_forwarded_live(engine, upstream):
    eng, seen = engine
    status, data = via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/hello")
    assert (status, data) == (200, b"hello from upstream")
    assert len(seen) == 1
    ex = seen[0]
    assert ex.answered_by == "live"
    assert ex.kind == "read"
    assert ex.service == "127.0.0.1"
    assert ex.operation == "GET /hello"
    assert ex.run_id == "t3st"
    assert ex.flags == ()
    assert ex.door == "forward"
    assert ex.request.port == upstream  # a loopback upstream on another port is not the listener
    assert ex.response.status == 200


def test_a_post_is_faked_with_an_echo(engine, upstream):
    eng, seen = engine
    status, data = via_proxy(
        eng.listen_port(), "POST", f"http://127.0.0.1:{upstream}/things", body=b'{"a":1}'
    )
    assert status == 200
    body = json.loads(data)
    assert body["a"] == 1  # the echo reflects the request's own fields
    assert sorted(body) == ["a"]  # unmapped: nothing minted, and no other service's fields
    ex = seen[0]
    assert ex.answered_by == "fake-L0"
    assert ex.kind == "unknown"
    assert "unclassified" in ex.flags


def test_mapped_write_is_named_and_faked(tmp_path, monkeypatch, upstream):
    """A mapped write is classified by its route from the maps on EngineConfig, not by its verb."""
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch))
    eng, seen, stop = start_engine(cfg)
    try:
        status, data = via_proxy(
            eng.listen_port(), "POST", f"http://127.0.0.1:{upstream}/things", body=b'{"a":1}'
        )
    finally:
        stop()
    assert status == 200
    assert json.loads(data)["a"] == 1  # the upstream's do_POST would have been a 500
    ex = seen[0]
    assert (ex.service, ex.operation, ex.kind) == ("demo", "things.create", "write")
    assert ex.answered_by == "fake-L0"
    assert ex.flags == ()


def test_mapped_read_is_named_and_forwarded(tmp_path, monkeypatch, upstream):
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch))
    eng, seen, stop = start_engine(cfg)
    try:
        status, data = via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/hello")
    finally:
        stop()
    assert (status, data) == (200, b"hello from upstream")
    ex = seen[0]
    assert (ex.service, ex.operation, ex.kind) == ("demo", "things.list", "read")
    assert ex.answered_by == "live"
    assert ex.flags == ()


def test_a_slack_read_raises_the_ts_watermark(tmp_path, monkeypatch, upstream):
    """A Slack read raises the `ts` clock, so a minted `ts` sorts after messages already read."""
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, doc=SLACK_MAP))
    eng, seen, stop = start_engine(cfg)
    try:
        status, _ = via_proxy(
            eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/slack-history"
        )
    finally:
        stop()
    assert status == 200
    assert (seen[0].service, seen[0].kind) == ("slack", "read")
    whole, _, fraction = eng.policy.slack_ts.mint().partition(".")
    assert (int(whole), int(fraction)) > (1_999_999_999, 500)


def test_an_upstream_error_is_flagged(engine, upstream):
    eng, seen = engine
    status, _ = via_proxy(eng.listen_port(), "GET", "http://127.0.0.1:1/x")
    assert status == 502
    assert seen[0].response is None
    assert "upstream-error" in seen[0].flags


def test_mitmproxys_ca_bundle_is_written_from_irimis_ca(engine, upstream):
    bundle = paths.mitm_dir() / "mitmproxy-ca.pem"
    assert bundle.is_file()
    assert ca.ca_paths().cert.read_bytes() in bundle.read_bytes()


# `rot13` is an encoding mitmproxy raises TypeError for rather than ValueError.
@pytest.mark.parametrize("content_encoding", ["gzip", "rot13"])
def test_undecodable_request_body_is_still_faked(engine, upstream, content_encoding):
    # A strict body decode raising inside the hook would make mitmproxy forward the write.
    eng, seen = engine
    status, data = via_proxy(
        eng.listen_port(),
        "POST",
        f"http://127.0.0.1:{upstream}/things",
        body=b'{"not":"gzip"}',
        extra_headers={"content-encoding": content_encoding},
    )
    assert status == 200  # the upstream answers every POST with 500, so it was not reached
    assert json.loads(data)["not"] == "gzip"  # reflected from the body we could not decode
    assert [ex.answered_by for ex in seen] == ["fake-L0"]
    assert seen[0].request.body == b'{"not":"gzip"}'


def test_undecodable_upstream_body_is_still_recorded(engine, upstream):
    eng, seen = engine
    status, data = via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/badgzip")
    assert (status, data) == (200, b"not-gzip")
    assert len(seen) == 1
    assert seen[0].answered_by == "live"
    assert seen[0].response.body == b"not-gzip"


@pytest.mark.parametrize("content_encoding", ["rot13", "utf-8"])
def test_an_upstream_body_in_an_encoding_that_is_not_a_decoding_is_still_recorded(
    engine, upstream, content_encoding
):
    """A body in a text codec (`rot13`, `utf-8`) is recorded as it came, like an undecodable one.

    mitmproxy raises TypeError for `rot13`, and `utf-8` decodes to a str, which is no body."""
    eng, seen = engine
    url = f"http://127.0.0.1:{upstream}/encoded/{content_encoding}"
    status, data = via_proxy(eng.listen_port(), "GET", url)
    assert (status, data) == (200, b"not-" + content_encoding.encode())
    (ex,) = seen
    assert (ex.answered_by, ex.flags) == ("live", ())
    assert ex.response is not None and ex.response.body == data


def test_an_overlays_answer_reaches_the_client(tmp_path, monkeypatch, upstream):
    class _Overlay:
        def __call__(
            self, write_log, classification, read_request, upstream_response, translated_from=None
        ):
            return Overlaid(Response(200, (("content-type", "text/plain"),), b"OVERLAID"))

        def rewrite(self, write_log, classification, read_request):
            return None

    eng, seen, stop = start_engine(engine_config(tmp_path, monkeypatch), overlay=_Overlay())
    try:
        # The overlay is asked only once there is a write to show.
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{upstream}/things", body=b"{}")
        status, data = via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/hello")
    finally:
        stop()
    assert (status, data) == (200, b"OVERLAID")
    assert seen[-1].response.body == b"OVERLAID"


@pytest.mark.parametrize("content_encoding", ["rot13", "utf-8"])
def test_an_overlaid_read_in_an_encoding_mitmproxy_cannot_apply_still_reaches_the_client(
    tmp_path, monkeypatch, upstream, content_encoding
):
    """An overlaid body goes out as the overlay built it, whatever `content-encoding` it keeps.

    mitmproxy would re-encode it per that header, and raises TypeError for a text codec."""

    class _Overlay:
        def __call__(
            self, write_log, classification, read_request, upstream_response, translated_from=None
        ):
            body = upstream_response.body + b"-OVERLAID"
            return Overlaid(Response(200, upstream_response.headers, body))

        def rewrite(self, write_log, classification, read_request):
            return None

    eng, seen, stop = start_engine(engine_config(tmp_path, monkeypatch), overlay=_Overlay())
    url = f"http://127.0.0.1:{upstream}/encoded/{content_encoding}"
    try:
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{upstream}/things", body=b"{}")
        status, data = via_proxy(eng.listen_port(), "GET", url)
    finally:
        stop()
    assert (status, data) == (200, b"not-" + content_encoding.encode() + b"-OVERLAID")
    assert len(seen) == 2 and seen[-1].response is not None
    assert (seen[-1].answered_by, seen[-1].response.body) == ("overlay", data)


def test_repeated_headers_survive_a_local_answer(tmp_path, monkeypatch, upstream):
    class _Overlay:
        def __call__(
            self, write_log, classification, read_request, upstream_response, translated_from=None
        ):
            return Overlaid(Response(200, (("set-cookie", "a=1"), ("set-cookie", "b=2")), b""))

        def rewrite(self, write_log, classification, read_request):
            return None

    eng, _seen, stop = start_engine(engine_config(tmp_path, monkeypatch), overlay=_Overlay())
    try:
        # The overlay is asked only once there is a write to show.
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{upstream}/things", body=b"{}")
        conn = http.client.HTTPConnection("127.0.0.1", eng.listen_port(), timeout=10)
        conn.request("GET", f"http://127.0.0.1:{upstream}/hello", headers={"host": "127.0.0.1"})
        resp = conn.getresponse()
        resp.read()
        cookies = resp.headers.get_all("set-cookie")
        conn.close()
    finally:
        stop()
    assert cookies == ["a=1", "b=2"]


# Every header a connection keeps to itself, in the spellings a service may send.
HOP_BY_HOP = (
    ("Connection", "Upgrade, close"),
    ("Keep-Alive", "timeout=5"),
    ("proxy-connection", "close"),
    ("te", "trailers"),
    ("Trailer", "X-Checksum"),
    ("transfer-encoding", "chunked"),
    ("Upgrade", "h2c"),
)


def _answering(first):
    """Return a policy that answers `/first` with `first`, and any other path with `{}`."""

    class _Answers(ShadowPolicy):
        def decide(self, request, classification, write_log=(), run_id="", target=None):
            if request.path == "/first":
                return Decided(Respond(first, "recording"))
            return Decided(Respond(Response(200, (), b"{}"), "recording"))

    return _Answers()


def _on_one_connection(tmp_path, monkeypatch, first, method="GET"):
    """Return the raw answer to `method /first`, the one to a GET after it, and what was recorded.

    Both requests go in one raw-socket write. The policy answers `/first` with `first` and the GET
    with `{}`, so the connection must stay open, and `first` end where it says, for `{}` to come."""
    eng, seen, stop = start_engine(engine_config(tmp_path, monkeypatch), policy=_answering(first))
    sent = "".join(
        f"{verb} http://127.0.0.1:9/{path} HTTP/1.1\r\nhost: 127.0.0.1:9\r\n\r\n"
        for verb, path in ((method, "first"), ("GET", "after"))
    )
    try:
        with socket.create_connection(("127.0.0.1", eng.listen_port()), timeout=10) as sock:
            sock.sendall(sent.encode())
            received = b""
            while not received.endswith(b"{}"):  # the GET's body is the last thing on the wire
                chunk = sock.recv(65536)
                assert chunk, f"the connection closed after {received!r}"
                received += chunk
    finally:
        stop()
    head, after = received.split(b"\r\n\r\n", 1)
    return head, after, seen


@pytest.mark.parametrize("framed", [(), (("transfer-encoding", "chunked"),)])
@pytest.mark.parametrize(("method", "status"), [("GET", 204), ("GET", 304), ("HEAD", 200)])
def test_an_answer_that_ends_at_its_head_sends_no_content_and_keeps_the_connection_usable(
    tmp_path, monkeypatch, method, status, framed
):
    """A policy's 204, 304 or answer to HEAD has no content, Content-Length or Transfer-Encoding.

    Bytes after it would be read as the next response (RFC 9112 6.3), a chunked one's last chunk
    included, so the GET sent next on the same connection must get its own answer. Both are
    recorded as sent."""
    first = Response(status, framed, b"stray")
    head, after, seen = _on_one_connection(tmp_path, monkeypatch, first, method)
    assert head.startswith(f"HTTP/1.1 {status} ".encode())
    assert b"\r\nirimi-answered-by: recording" in head.lower()
    assert b"content-length" not in head.lower()
    assert b"transfer-encoding" not in head.lower()
    assert after.startswith(b"HTTP/1.1 200 ")
    recorded = [(ex.response.status, ex.response.body) for ex in seen if ex.response is not None]
    assert recorded == [(status, b""), (200, b"{}")]
    assert seen[0].response is not None and seen[0].response.header("content-length") is None


@pytest.mark.parametrize(("status", "length"), [(200, "42"), (404, "42"), (204, None), (304, None)])
def test_an_answer_to_head_keeps_the_length_it_names_and_the_next_answer_is_read_whole(
    tmp_path, monkeypatch, status, length
):
    """An answer to HEAD may say how long its GET's content is (RFC 9110 8.6), and still has none.

    A 204 must not say, and a 304 is not asked to."""
    first = Response(status, (("content-length", "42"),), b"")
    head, after, seen = _on_one_connection(tmp_path, monkeypatch, first, "HEAD")
    assert head.startswith(f"HTTP/1.1 {status} ".encode())
    named = [line for line in head.lower().split(b"\r\n") if line.startswith(b"content-length")]
    assert named == ([] if length is None else [f"content-length: {length}".encode()])
    assert after.startswith(b"HTTP/1.1 200 ")
    assert seen[0].response is not None
    assert (seen[0].response.header("content-length"), seen[0].response.body) == (length, b"")


def test_a_policy_s_connection_close_does_not_end_the_agent_s_connection(tmp_path, monkeypatch):
    """A policy's answer goes out without the hop-by-hop headers it holds, framed by its length.

    Its `Connection: close` would otherwise end the connection before the GET sent after it."""
    first = Response(200, (*HOP_BY_HOP, ("etag", '"v1"')), b"stray")
    head, after, seen = _on_one_connection(tmp_path, monkeypatch, first)
    names = [line.split(b":", 1)[0].lower() for line in head.split(b"\r\n")[1:]]
    assert names == [b"etag", b"irimi-answered-by", b"content-length"]
    assert after.startswith(b"stray" + b"HTTP/1.1 200 ")
    assert seen[0].response is not None and seen[0].response.body == b"stray"


FORGED_VALUE = ("etag", '"v1"\r\nSet-Cookie: session=forged')
FORGED_NAME = ("set-cookie: session=forged; etag", '"v1"')


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (FORGED_VALUE, "the 'etag' header holds a CR, LF or NUL"),
        (FORGED_NAME, "the header name 'set-cookie: session=forged; etag' is not a token"),
    ],
)
def test_an_answer_with_a_header_that_is_not_one_line_is_refused_as_irimi_s_502(
    tmp_path, monkeypatch, header, reason
):
    """A header holding CRLF, or a name holding a colon, would add a header of its own."""
    first = Response(200, (header,), b"stray")
    head, after, seen = _on_one_connection(tmp_path, monkeypatch, first)
    assert head.startswith(b"HTTP/1.1 502 ")
    assert b"set-cookie" not in head.lower()
    assert b"\r\nirimi-answered-by: irimi" in head.lower()
    error = json.loads(after.split(b"HTTP/1.1 200 ", 1)[0])["error"]
    assert error == {
        "type": "irimi_decision_failed",
        "message": f"irimi could not decide how to answer this request: {reason}",
    }
    assert seen[0].response is not None and seen[0].response.status == 502
    assert Flag.DECISION_FAILED in seen[0].flags


def _with_httpx(port, method):
    """Return httpx's answer to `method /first`, the GET after it, and if one connection did."""
    with httpx.Client(proxy=f"http://127.0.0.1:{port}", timeout=10) as client:
        first = client.request(method, "http://127.0.0.1:9/first")
        after = client.get("http://127.0.0.1:9/after")
        one = first.extensions["network_stream"] is after.extensions["network_stream"]
        return first.status_code, first.headers, after.content, one


def _with_requests(port, method):
    """Return requests' answer to `method /first`, the GET after it, and if one connection did."""
    # urllib3 reconnects a pooled connection the proxy closed in place, so only `connect` sees it.
    connect = HTTPConnection.connect
    with (
        mock.patch.object(HTTPConnection, "connect", autospec=True, side_effect=connect) as dialled,
        requests.Session() as session,
    ):
        session.proxies = {"http": f"http://127.0.0.1:{port}"}
        first = session.request(method, "http://127.0.0.1:9/first", timeout=10)
        after = session.get("http://127.0.0.1:9/after", timeout=10)
        return first.status_code, first.headers, after.content, dialled.call_count == 1


@pytest.mark.parametrize("client", [_with_httpx, _with_requests])
@pytest.mark.parametrize(
    ("method", "first", "status", "length"),
    [
        ("HEAD", Response(200, (("content-length", "42"),), b""), 200, "42"),
        (
            "HEAD",
            Response(200, (("content-length", "42"), ("content-length", "43")), b""),
            200,
            None,
        ),
        ("GET", Response(204, HOP_BY_HOP, b"stray"), 204, None),
        ("GET", Response(200, HOP_BY_HOP, b"stray"), 200, "5"),
        ("GET", Response(200, (FORGED_VALUE,), b"{}"), 502, "149"),
        ("GET", Response(200, (FORGED_NAME,), b"{}"), 502, "175"),
        ("HEAD", Response(200, (FORGED_NAME,), b""), 502, None),
    ],
)
def test_real_clients_read_a_rebuilt_answer_and_the_next_on_one_connection(
    tmp_path, monkeypatch, client, method, first, status, length
):
    """httpx and requests parse each answer irimi builds, with no header it did not mean to send.

    The GET after it is read off the same connection."""
    eng, _, stop = start_engine(engine_config(tmp_path, monkeypatch), policy=_answering(first))
    try:
        got, headers, after, one_connection = client(eng.listen_port(), method)
    finally:
        stop()
    assert (got, headers.get("content-length"), after, one_connection) == (
        status,
        length,
        b"{}",
        True,
    )
    assert "set-cookie" not in headers


@pytest.mark.parametrize("encoding", ["identity", "rot13"])
@pytest.mark.parametrize(
    ("method", "status", "sent", "length"),
    [
        ("GET", 100, b"", None),
        ("GET", 199, b"", None),
        ("GET", 204, b"", None),
        ("GET", 304, b"", None),
        ("HEAD", 100, b"", None),
        ("HEAD", 200, b"", "42"),
        ("HEAD", 204, b"", None),
        ("HEAD", 304, b"", None),
        ("HEAD", 403, b"", "42"),
        ("GET", 200, b"stray", "5"),
        ("GET", 203, b"stray", "5"),
        ("GET", 303, b"stray", "5"),
        ("POST", 403, b"stray", "5"),
    ],
)
def test_only_an_answer_that_ends_at_its_head_is_built_without_content(
    method, status, sent, length, encoding
):
    """A 1xx, 204 or 304, or any answer to HEAD, is built bare; the rest keep body and length.

    An answer to HEAD keeps the length it names, unless a GET's answer would have no content; any
    other answer gets its body's. `rot13` is an encoding mitmproxy cannot apply, so it takes the
    other way `make` is called."""
    headers = (("content-encoding", encoding), ("content-length", "42"))
    built = mitm._to_mitm_response(Response(status, headers, b"stray"), method)
    assert built.raw_content == sent
    assert built.headers.get("content-length") == length


@pytest.mark.parametrize(
    ("method", "status", "body"),
    [("GET", 200, b"stray"), ("POST", 403, b"stray"), ("GET", 204, b""), ("HEAD", 200, b"")],
)
def test_a_rebuilt_answer_is_built_without_hop_by_hop_headers(method, status, body):
    """A Transfer-Encoding included: mitmproxy would end a chunked 204 with a last chunk."""
    response = Response(status, (*HOP_BY_HOP, ("etag", '"v1"')), b"stray")
    built = mitm._to_mitm_response(response, method)
    framing = [("content-length", str(len(body)))] if body else []
    assert built.headers.fields == tuple(
        (k.encode(), v.encode()) for k, v in [("etag", '"v1"'), *framing]
    )


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("etag", '"v1"\r\nSet-Cookie: session=forged'),
        ("etag", '"v1"\nSet-Cookie: session=forged'),
        ("etag", '"v1"\r'),
        ("etag", '"v1"\0'),
    ],
)
def test_a_header_that_is_not_one_line_is_never_built(method, name, value):
    """mitmproxy writes a header as it is, so a CR or LF would start another (RFC 9110 5.5)."""
    with pytest.raises(ValueError, match="header holds a CR, LF or NUL"):
        mitm._to_mitm_response(Response(200, ((name, value),), b"{}"), method)


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize(
    "name",
    [
        "set-cookie: session=forged; etag",
        "etag\r\nSet-Cookie",
        "x note",
        " etag",
        "",
        "etag\0",
        "x/y",
    ],
)
def test_a_header_name_that_is_not_a_token_is_never_built(method, name):
    """A `:` would end the name early, so a stored name could add a header of its own."""
    with pytest.raises(ValueError, match="is not a token"):
        mitm._to_mitm_response(Response(200, ((name, "1"),), b"{}"), method)


def test_the_whitespace_before_a_header_name_s_colon_is_dropped():
    """mitmproxy keeps it in the name it read, and RFC 9112 5.1 tells a proxy to drop it."""
    headers = (("x-note \t", "a"), ("Connection ", "close"))
    built = mitm._to_mitm_response(Response(200, headers, b"{}"), "GET")
    assert built.headers.fields == ((b"x-note", b"a"), (b"content-length", b"2"))


@pytest.mark.parametrize(
    ("named", "sent"),
    [
        (("42",), "42"),
        (("42", "42"), "42"),
        (("42, 42",), "42"),
        (("42", "43"), None),
        (("42, 43",), None),
        (("abc",), None),
        (("-1",), None),
        (("",), None),
        (("4\xc2\xb2",), None),  # `4²` in UTF-8, as mitmproxy reads it: a digit to `isdigit`
    ],
)
def test_an_answer_to_head_names_one_length_or_none(named, sent):
    """httpx, requests and aiohttp refuse an answer whose lengths disagree, even to HEAD.

    aiohttp refuses a repeated one too, so one that agrees is sent once."""
    headers = (*(("content-length", n) for n in named), ("etag", '"v1"'))
    built = mitm._to_mitm_response(Response(200, headers, b""), "HEAD")
    assert built.headers.get_all("content-length") == ([] if sent is None else [sent])
    assert built.headers.get("etag") == '"v1"'


def test_a_header_value_may_hold_a_tab():
    built = mitm._to_mitm_response(Response(200, (("x-note", "a\tb"),), b"{}"), "GET")
    assert built.headers.get("x-note") == "a\tb"


@pytest.mark.parametrize("fold", ["\r\n ", "\r\n\t", "\r\n  \t"])
def test_a_folded_value_mitmproxy_read_is_rebuilt_unfolded(fold):
    """mitmproxy keeps a service's obsolete line folding in the value it read (RFC 9112 5.2)."""
    built = mitm._to_mitm_response(Response(200, (("x-note", f"a{fold}b"),), b"{}"), "GET")
    assert built.headers.get("x-note") == "a b"


@pytest.mark.parametrize("value", ["a\r\n b", "a\0b", "a\rb"])
def test_a_live_answer_is_sent_with_the_header_values_the_service_sent(value):
    """Only the stamp is written onto a delegated answer whose body nothing changed, as it came.

    A value mitmproxy read is sent again as a live forward sends it, never refused."""
    from mitmproxy.test import tutils

    flow = bare_flow("GET", "/v1/charges")
    flow.response = tutils.tresp(content=b"{}")
    upstream = Response(200, (("x-note", value),), b"{}")
    out = Response(200, (("x-note", value), ("irimi-answered-by", "delegated")), upstream.body)
    mitm._send(flow, out, upstream)
    assert flow.response.headers.fields == (
        (b"x-note", value.encode()),
        (b"irimi-answered-by", b"delegated"),
    )


@pytest.mark.parametrize(("method", "sent"), [("HEAD", b""), ("GET", b'{"overlaid": true}')])
def test_a_rebuilt_live_answer_to_head_is_sent_without_content(method, sent):
    """An overlaid read is rebuilt, and in answer to HEAD it ends at its head like any other."""
    from mitmproxy.test import tutils

    flow = bare_flow(method, "/v1/charges")
    flow.response = tutils.tresp(content=b"")
    upstream = Response(200, (("content-type", "application/json"),), b"")
    out = Response(200, upstream.headers, b'{"overlaid": true}')
    mitm._send(flow, out, upstream)
    assert flow.response.raw_content == sent
    assert flow.response.headers.get("content-length") == (str(len(sent)) if sent else None)


def test_port_in_use_raises_engine_start_error(tmp_path, monkeypatch):
    """A taken port is reported in irimi's words, naming `--port` and never mitmproxy's `--mode`."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    cfg = engine_config(tmp_path, monkeypatch, port=port)
    eng = MitmEngine(cfg, ShadowPolicy(), NullStore(), NoOverlay())
    said = (
        f"port {port} on 127.0.0.1 is in use; pick another with --port, or --port 0 for any "
        "free port"
    )

    async def go():
        task = asyncio.ensure_future(eng.run())
        with pytest.raises(EngineStartError) as refused:
            await asyncio.wait_for(eng.wait_ready(), 15)
        assert str(refused.value) == said
        with pytest.raises(EngineStartError):
            await asyncio.wait_for(task, 15)

    try:
        asyncio.run(go())
    finally:
        sock.close()
    assert eng.listen_port() is None


def test_shutdown_before_run_makes_run_return(tmp_path, monkeypatch):
    eng = MitmEngine(engine_config(tmp_path, monkeypatch), ShadowPolicy(), NullStore(), NoOverlay())

    async def go():
        task = asyncio.ensure_future(eng.run())
        eng.shutdown()
        await asyncio.wait_for(task, 15)
        with pytest.raises(EngineStartError, match="stopped before"):
            await eng.wait_ready()

    asyncio.run(go())


def test_the_engine_never_closes_the_store_even_when_setup_fails(tmp_path, monkeypatch):
    """The engine never closes the store, which the composition root opens and closes."""
    closed = []

    class _Store:
        def record(self, ex):
            pass

        def close(self):
            closed.append(True)

    cfg = engine_config(tmp_path, monkeypatch)
    cfg.ca.key.unlink()  # bundle write fails before mitmproxy starts
    eng = MitmEngine(cfg, ShadowPolicy(), _Store(), NoOverlay())  # type: ignore[arg-type]
    with pytest.raises(FileNotFoundError):
        asyncio.run(eng.run())
    assert closed == []


def test_faked_write_reflects_a_form_body_and_is_flagged(engine, upstream):
    """The echo of a form-encoded write, as stripe-python posts it, reaches the client."""
    eng, seen = engine
    status, data = via_proxy(
        eng.listen_port(),
        "POST",
        f"http://127.0.0.1:{upstream}/things",
        body=b"amount=4900&charge=ch_test",
        extra_headers={"content-type": "application/x-www-form-urlencoded"},
    )
    assert status == 200
    body = json.loads(data)
    assert body["amount"] == 4900
    assert body["charge"] == "ch_test"
    assert "created" not in body
    ex = seen[0]
    assert ex.answered_by == "fake-L0"


def test_live_read_carries_no_fidelity_flag(engine, upstream):
    eng, seen = engine
    via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/hello")
    assert seen[0].answered_by == "live"
    assert seen[0].flags == ()


@pytest.mark.parametrize(
    ("cause", "said"),
    [
        (
            OSError(13, "http(s) proxy failed to listen on 127.0.0.1:1 with [Errno 13] denied"),
            "could not listen on 127.0.0.1:1: permission denied",
        ),
        (
            OSError("http(s) proxy failed to listen: [Errno None] no route"),
            "could not listen on 127.0.0.1:1",
        ),
        (None, "could not listen on 127.0.0.1:1"),
        (RuntimeError("loop closed"), "could not listen on 127.0.0.1:1: loop closed"),
    ],
)
def test_a_listener_that_did_not_bind_is_told_in_irimi_s_words(
    cause: BaseException | None, said: str
) -> None:
    """mitmproxy's strerror is its own sentence; only the OS's reason for the errno is irimi's."""
    from irimi.engine.mitm import _start_failure

    config = EngineConfig(
        run_id="t3st", ca=ca.ca_paths(), confdir=Path("."), listen_host="127.0.0.1", listen_port=1
    )
    assert _start_failure(config, cause) == said
