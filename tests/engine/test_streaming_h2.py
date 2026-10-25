"""A streamed answer over HTTP/2 on both sides of the proxy, recorded one DATA frame per chunk.

Both ends use `h2`, which mitmproxy already installs."""

import socket
import ssl
import threading
from pathlib import Path
from typing import cast

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, StreamReset

from irimi.core.exchange import Flag
from tests.support.engine import THREE_CHUNKS, engine_config, leaf_cert_for_loopback, start_engine
from tests.support.maps import STREAM_MAP, map_index
from tests.support.waiting import eventually


def _h2_stream_server(tls_leaf: Path, chunks, gates, alpn: list, *, hang_up=False):
    """Return an HTTP/2-only HTTPS upstream that streams `chunks` as SSE, one DATA frame each.

    Each chunk after the first waits for `gates[i - 1]`. With `hang_up`, the stream never ends:
    once `gates[len(chunks) - 1]` is set the connection closes. The agreed ALPN goes into
    `alpn`, and the caller closes the returned listener."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tls_leaf)
    ctx.set_alpn_protocols(["h2"])
    listener = socket.create_server(("127.0.0.1", 0))

    def serve() -> None:
        raw, _ = listener.accept()
        with ctx.wrap_socket(raw, server_side=True) as sock:
            alpn.append(sock.selected_alpn_protocol())
            conn = H2Connection(H2Configuration(client_side=False))
            conn.initiate_connection()
            sock.sendall(conn.data_to_send())
            while data := sock.recv(65535):
                for event in conn.receive_data(data):
                    if not isinstance(event, RequestReceived):
                        continue
                    headers = [(":status", "200"), ("content-type", "text/event-stream")]
                    conn.send_headers(event.stream_id, headers)
                    for i, chunk in enumerate(chunks):
                        if i:
                            gates[i - 1].wait(timeout=20)
                        last = i == len(chunks) - 1
                        conn.send_data(event.stream_id, chunk, end_stream=last and not hang_up)
                        sock.sendall(conn.data_to_send())
                    if hang_up:
                        gates[len(chunks) - 1].wait(timeout=20)
                        return
                sock.sendall(conn.data_to_send())

    threading.Thread(target=serve, daemon=True).start()
    return listener


def _h2_through_the_proxy(cfg, proxy_port: int, upstream_port: int, gates, *, hang_up_after=0):
    """POST the chat route over HTTP/2 in a CONNECT tunnel; return ALPN, status and DATA frames.

    It trusts irimi's CA and sets `gates[i]` once chunk `i` has arrived. With `hang_up_after`, it
    closes the connection once that many chunks have arrived; a reset stream ends it too."""
    authority = f"127.0.0.1:{upstream_port}"
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    reply = b""
    while b"\r\n\r\n" not in reply:
        reply += sock.recv(4096)
    assert reply.startswith(b"HTTP/1.1 200"), reply
    ctx = ssl.create_default_context(cafile=str(cfg.ca.cert))
    ctx.set_alpn_protocols(["h2"])
    status, frames = None, []
    with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as tls:
        conn = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        conn.initiate_connection()
        request = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", authority),
            (":path", "/v1/chat/completions"),
            ("content-type", "application/json"),
        ]
        conn.send_headers(1, request)
        conn.send_data(1, b"{}", end_stream=True)
        tls.sendall(conn.data_to_send())
        ended = False
        while not ended:
            data = tls.recv(65535)
            assert data, "the proxy closed the connection before the stream ended"
            for event in conn.receive_data(data):
                if isinstance(event, ResponseReceived):
                    # `header_encoding="utf-8"` hands the headers back as str, not h2's typed bytes.
                    status = cast(dict[str, str], dict(event.headers))[":status"]
                elif isinstance(event, DataReceived):
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    if not event.data:  # mitmproxy ends the stream with an empty DATA frame
                        continue
                    frames.append(event.data)
                    if len(frames) <= len(gates):
                        gates[len(frames) - 1].set()
                    if len(frames) == hang_up_after:
                        return tls.selected_alpn_protocol(), status, frames
                elif isinstance(event, (StreamEnded, StreamReset)):
                    ended = True
            tls.sendall(conn.data_to_send())
        return tls.selected_alpn_protocol(), status, frames


def test_a_stream_over_http2_on_both_sides_is_recorded_as_its_chunks(tmp_path, monkeypatch):
    """Each chunk reaches the agent before the next is sent, and the exchange holds every chunk."""
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, STREAM_MAP))
    gates = [threading.Event(), threading.Event()]
    upstream_alpn: list = []
    listener = _h2_stream_server(
        leaf_cert_for_loopback(cfg.ca, tmp_path / "leaf.pem"), THREE_CHUNKS, gates, upstream_alpn
    )
    eng, seen, stop = start_engine(cfg, trust_upstream_ca=cfg.ca.cert)
    try:
        port = eng.listen_port()
        assert port is not None
        agent_alpn, status, frames = _h2_through_the_proxy(
            cfg, port, listener.getsockname()[1], gates
        )
    finally:
        for gate in gates:
            gate.set()
        stop()
        listener.close()
    assert (agent_alpn, upstream_alpn) == ("h2", ["h2"])
    assert (status, frames) == ("200", THREE_CHUNKS)
    (ex,) = seen
    assert (ex.request.scheme, ex.kind, ex.answered_by, ex.flags) == ("https", "llm", "live", ())
    assert ex.response is not None and ex.response.body == b"".join(THREE_CHUNKS)
    assert ex.stream_chunks == tuple(len(chunk) for chunk in THREE_CHUNKS)


def _broken_h2_stream(tmp_path, monkeypatch, *, agent_hangs_up):
    """Stream one chunk over HTTP/2 that the agent or the upstream then hangs up on.

    Return the frames the agent got and the exchanges recorded."""
    cfg = engine_config(tmp_path, monkeypatch, maps=map_index(tmp_path, monkeypatch, STREAM_MAP))
    gate = threading.Event()
    listener = _h2_stream_server(
        leaf_cert_for_loopback(cfg.ca, tmp_path / "leaf.pem"),
        THREE_CHUNKS[:1],
        [gate],
        [],
        hang_up=True,
    )
    eng, seen, stop = start_engine(cfg, trust_upstream_ca=cfg.ca.cert)
    try:
        port = eng.listen_port()
        assert port is not None
        if agent_hangs_up:  # the upstream holds its connection open until the test ends
            _, _, frames = _h2_through_the_proxy(
                cfg, port, listener.getsockname()[1], [], hang_up_after=1
            )
        else:
            _, _, frames = _h2_through_the_proxy(cfg, port, listener.getsockname()[1], [gate])
        eventually(lambda: seen, message="the broken stream was never recorded")
    finally:
        gate.set()
        stop()
        listener.close()
    return frames, seen


def test_an_agent_that_hangs_up_mid_stream_over_http2_is_flagged_and_the_upstream_is_not_blamed(
    tmp_path, monkeypatch
):
    """Over HTTP/2 both hang-ups read `peer closed connection`; the closed side tells them apart."""
    frames, seen = _broken_h2_stream(tmp_path, monkeypatch, agent_hangs_up=True)
    assert frames == THREE_CHUNKS[:1]
    (ex,) = seen
    assert ex.flags == (Flag.AGENT_DISCONNECTED, Flag.STREAM_TRUNCATED)
    assert ex.response is not None and ex.response.body == THREE_CHUNKS[0]


def test_an_upstream_that_hangs_up_mid_stream_over_http2_is_an_upstream_error(
    tmp_path, monkeypatch
):
    """The same close from the upstream's side keeps `upstream-error`."""
    frames, seen = _broken_h2_stream(tmp_path, monkeypatch, agent_hangs_up=False)
    assert frames == THREE_CHUNKS[:1]
    (ex,) = seen
    assert ex.flags == (Flag.UPSTREAM_ERROR, Flag.STREAM_TRUNCATED)
    assert ex.response is not None and ex.response.body == THREE_CHUNKS[0]
