"""Server-sent events and other streamed answers reach the client as they arrive."""

import http.client
import threading
import time

import pytest

from irimi.core.exchange import Flag, Response
from irimi.decide.overlay import Overlaid
from irimi.protocol.headers import ANSWERED_BY_HEADER
from tests.support.engine import (
    THREE_CHUNKS,
    engine_config,
    open_stream,
    start_engine,
    stream_server,
    via_proxy,
)
from tests.support.maps import READ_STREAM_MAP, STREAM_MAP, map_index
from tests.support.servers import stop_server
from tests.support.upstreams import SSE_FIRST, SSE_SECOND, StreamUpstream, serve

# STREAM_MAP's route as a read: `style: rpc` lets a POST be one.
RPC_READ_STREAM_MAP = STREAM_MAP.replace("hosts:", "style: rpc\nhosts:").replace(
    "kind: llm", "kind: read"
)


@pytest.mark.parametrize(
    ("content_type", "expected"),
    [
        ("text/event-stream", True),
        ("text/event-stream; charset=utf-8", True),
        ("Text/Event-Stream", True),
        ("application/json", False),
        ("", False),
    ],
)
def test_only_an_event_stream_content_type_is_streamed(content_type, expected):
    from irimi.engine.mitm import _is_event_stream

    assert _is_event_stream(content_type) is expected


def test_a_server_sent_event_response_reaches_the_client_in_chunks(tmp_path, monkeypatch):
    """A server-sent event stream reaches the client chunk by chunk, not buffered.

    The upstream holds the second chunk until the first is read, and the client's timeout is far
    shorter than its wait, so buffering fails the test rather than slowing it."""
    srv = serve(StreamUpstream)
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, STREAM_MAP))
    eng, seen, stop = start_engine(cfg)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", eng.listen_port(), timeout=5)
        url = f"http://127.0.0.1:{srv}/v1/chat/completions"
        conn.request(
            "POST",
            url,
            body=b"{}",
            headers={
                "host": f"127.0.0.1:{srv}",
                "content-type": "application/json",
            },
        )
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("content-type") == "text/event-stream"
        first = resp.read(len(SSE_FIRST))  # times out at 5 s if the proxy buffered the body
        assert first == SSE_FIRST
        srv.gate.set()
        assert resp.read() == SSE_SECOND
        conn.close()
    finally:
        srv.gate.set()
        stop()
        srv.stop()
    assert len(seen) == 1
    ex = seen[0]
    assert (ex.service, ex.operation, ex.kind) == ("llmhost", "chat.completions.create", "llm")
    assert ex.answered_by == "live"
    assert ex.flags == ()
    # mitmproxy never assembles a streamed body; the exchange records the chunks the agent was
    # sent, joined, and how long each was.
    assert ex.response.status == 200
    assert ex.response.body == SSE_FIRST + SSE_SECOND
    assert ex.stream_chunks == (len(SSE_FIRST), len(SSE_SECOND))


def test_a_streamed_response_ends_when_its_stream_does_not_when_its_headers_leave(
    tmp_path, monkeypatch
):
    """A streamed exchange's `ended_at` covers the whole stream, not only its headers.

    mitmproxy runs the `response` hook once the last chunk has gone."""
    srv = serve(StreamUpstream)
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, STREAM_MAP))
    eng, seen, stop = start_engine(cfg)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", eng.listen_port(), timeout=5)
        authority = f"127.0.0.1:{srv}"
        conn.request(
            "POST",
            f"http://{authority}/v1/chat/completions",
            body=b"{}",
            headers={"host": authority, "content-type": "application/json"},
        )
        resp = conn.getresponse()
        assert resp.read(len(SSE_FIRST)) == SSE_FIRST
        first_chunk_at = time.time()
        time.sleep(0.05)  # a gap the exchange's span has to cover if it covers the stream
        released_at = time.time()
        srv.gate.set()
        assert resp.read() == SSE_SECOND
        conn.close()
    finally:
        srv.gate.set()
        stop()
        srv.stop()
    (ex,) = seen
    assert ex.response is not None and ex.response.body == SSE_FIRST + SSE_SECOND
    assert 0 < ex.started_at <= first_chunk_at < released_at <= ex.ended_at


class _RewritingOverlay:
    """An overlay that returns a new Response, unlike `NoOverlay`, at the fidelity it is given."""

    def __init__(self, fidelity) -> None:
        self.fidelity = fidelity
        self.shown: list[bytes] = []

    def __call__(
        self, write_log, classification, read_request, upstream_response, translated_from=None
    ):
        self.shown.append(upstream_response.body)
        return Overlaid(
            Response(
                status=200,
                headers=(("content-type", "application/json"),),
                body=b'{"overlaid": true}',
            ),
            self.fidelity,
        )

    def rewrite(self, write_log, classification, read_request):
        return None


@pytest.mark.parametrize(
    ("said", "recorded"), [(None, None), ("full", "partial"), ("partial", "partial")]
)
def test_a_streamed_read_reaches_the_client_unchanged_whatever_the_overlay_says(
    tmp_path, monkeypatch, said, recorded
):
    """A streamed read's chunks reach the client unchanged, and the overlay never edits them.

    The overlay is shown the recorded stream, so a read the run has a write for is `partial`."""
    srv = serve(StreamUpstream)
    cfg = engine_config(
        tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, READ_STREAM_MAP)
    )
    overlay = _RewritingOverlay(said)
    eng, seen, stop = start_engine(cfg, overlay=overlay)
    try:
        # A faked write first: with an empty write log the overlay is never asked at all.
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{srv}/w", body=b"{}")
        conn = http.client.HTTPConnection("127.0.0.1", eng.listen_port(), timeout=5)
        url = f"http://127.0.0.1:{srv}/v1/chat/completions"
        conn.request("GET", url, headers={"host": f"127.0.0.1:{srv}"})
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.getheader("content-type") == "text/event-stream"
        assert resp.getheader(ANSWERED_BY_HEADER) is None
        assert resp.read(len(SSE_FIRST)) == SSE_FIRST
        srv.gate.set()
        assert resp.read() == SSE_SECOND
        conn.close()
    finally:
        srv.gate.set()
        stop()
        srv.stop()
    assert overlay.shown == [SSE_FIRST + SSE_SECOND]
    _, ex = seen
    assert (ex.kind, ex.answered_by, ex.overlay) == ("read", "live", recorded)
    assert ex.response is not None and ex.response.body == SSE_FIRST + SSE_SECOND


@pytest.mark.parametrize(("said", "recorded"), [(None, None), ("full", "partial")])
def test_a_streamed_read_that_breaks_is_recorded_partial_when_it_would_show_a_write(
    tmp_path, monkeypatch, said, recorded
):
    """A streamed read reset mid-stream keeps what arrived, and the overlay never edits it.

    It is `partial` when the run has a write it would have shown, as a whole stream is."""
    gate = threading.Event()
    srv = stream_server(THREE_CHUNKS[:1], [gate], reset=True)
    cfg = engine_config(
        tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, RPC_READ_STREAM_MAP)
    )
    overlay = _RewritingOverlay(said)
    eng, seen, stop = start_engine(cfg, overlay=overlay)
    try:
        # A faked write first, or the overlay is never asked at all.
        port = srv.server_address[1]
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{port}/w", body=b"{}")
        conn, resp = open_stream(eng, srv)
        assert resp.read(len(THREE_CHUNKS[0])) == THREE_CHUNKS[0]
        gate.set()
        with pytest.raises(http.client.IncompleteRead):
            resp.read()
        conn.close()
    finally:
        gate.set()
        stop()
        stop_server(srv)
    assert overlay.shown == [THREE_CHUNKS[0]]
    _, ex = seen
    assert (ex.kind, ex.answered_by, ex.overlay) == ("read", "live", recorded)
    assert ex.flags == (Flag.UPSTREAM_ERROR, Flag.STREAM_TRUNCATED)
    assert ex.response is not None and ex.response.body == THREE_CHUNKS[0]


def test_an_llm_stream_after_a_faked_write_is_never_shown_to_the_overlay(tmp_path, monkeypatch):
    """Only a read is shown to the overlay: a model's answer reads nothing the run wrote."""
    srv = stream_server(THREE_CHUNKS)
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, STREAM_MAP))
    overlay = _RewritingOverlay("full")
    eng, seen, stop = start_engine(cfg, overlay=overlay)
    try:
        port = srv.server_address[1]
        via_proxy(eng.listen_port(), "POST", f"http://127.0.0.1:{port}/w", body=b"{}")
        conn, resp = open_stream(eng, srv)
        assert resp.read() == b"".join(THREE_CHUNKS)
        conn.close()
    finally:
        stop()
        stop_server(srv)
    assert overlay.shown == []
    write, ex = seen
    assert write.answered_by.startswith("fake-")
    assert (ex.kind, ex.answered_by, ex.overlay) == ("llm", "live", None)


def test_a_json_response_is_still_buffered_and_recorded(tmp_path, monkeypatch, upstream):
    """A live JSON read is buffered and recorded whole, since streaming keys on the content type."""
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch))
    eng, seen, stop = start_engine(cfg)
    try:
        status, data = via_proxy(eng.listen_port(), "GET", f"http://127.0.0.1:{upstream}/hello")
    finally:
        stop()
    assert (status, data) == (200, b"hello from upstream")
    assert seen[0].response.body == b"hello from upstream"
