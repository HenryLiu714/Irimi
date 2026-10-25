"""Bounded decoding of a body's `Content-Encoding`.

A few KB of gzip, br or zstd can decode to gigabytes. Each codec here runs incrementally and stops
at MAX_DECODED_BODY. Never raises (fail-closed hook rule): hooks decode every recorded body here.
"""

import io
import re
import zlib
from collections.abc import Callable
from dataclasses import dataclass

import brotli
import zstandard

from irimi.core.limits import MAX_DECODED_BODY

_IDENTITY_ENCODINGS = frozenset({"identity", "none"})
# As many codings as urllib3 undoes on one body; past that, an agent's client cannot read it either.
_MAX_CODINGS = 5


@dataclass(frozen=True)
class Decoded:
    body: bytes
    cut: bool  # stopped at MAX_DECODED_BODY, or ended early: `body` is the start of it, not all


def decode_body(body: bytes, content_encoding: str) -> Decoded | None:
    """Return `body` decoded up to MAX_DECODED_BODY, or None when it cannot be decoded.

    Stacked codings (`gzip, br`) are undone last first, `aws-chunked` before any, each output
    stopping at the cap. Never raises; holds at most three times the cap beside `body`. Other
    encodings than `_DECODERS` and the identities return None, since mitmproxy's codec fallback is
    unbounded.
    """
    names = (name.strip().lower() for name in content_encoding.split(","))
    codings = [name for name in names if name and name not in _IDENTITY_ENCODINGS]
    if len(codings) > _MAX_CODINGS or any(name not in _DECODERS for name in codings):
        return None
    # S3 strips `aws-chunked` wherever the list names it, since it frames the upload and codes
    # nothing; AWS documents `aws-chunked,gzip` and boto3 sends `gzip,aws-chunked`.
    framing = [name for name in codings if name == _AWS_CHUNKED]
    undone = framing + [name for name in reversed(codings) if name != _AWS_CHUNKED]
    cut = False
    for name in undone:
        if cut:  # the start of an inner coding's stream is not the start of the body
            return Decoded(b"", True)
        if not body:  # brotli would refuse an empty body; mitmproxy's decoders accept it
            break
        try:
            body, cut = _DECODERS[name](body, MAX_DECODED_BODY)
        except Exception:
            return None
    return Decoded(body, cut)


def _inflate(body: bytes, limit: int, wbits: int) -> tuple[bytes, bool]:
    """Return up to `limit` inflated bytes and whether more remain; refuse a stream cut short."""
    inflater = zlib.decompressobj(wbits)
    out = inflater.decompress(body, limit)
    if len(out) == limit and not inflater.eof and inflater.decompress(inflater.unconsumed_tail, 1):
        return out, True
    # Only a short tail is left inside, so flushing it stays bounded.
    out += inflater.flush()
    if not inflater.eof:
        raise zlib.error("incomplete or truncated stream")
    return out[:limit], len(out) > limit


_GZIP_WBITS = 32 + zlib.MAX_WBITS  # gzip or zlib, detected
_GZIP_MAGIC = b"\x1f\x8b"
_NOT_ZERO = re.compile(rb"[^\x00]")
# Input goes to zlib in steps: a member's unread input is copied when it ends, so many members
# fed whole would copy the body once per member.
_GZIP_STEP = 4 * 1024


def _gzip(body: bytes, limit: int) -> tuple[bytes, bool]:
    """Decode every gzip member; a last member that ends early keeps its start, said to be cut.

    Zeros between members are skipped, as Python's gzip skips them, and bytes after the last
    member that start none are ignored, as urllib3 ignores them.
    """
    view = memoryview(body)
    # `getvalue` hands over BytesIO's buffer uncopied; `bytes(bytearray)` would copy the cap.
    out = io.BytesIO()
    size = 0
    inflater = zlib.decompressobj(_GZIP_WBITS)
    at = 0
    while at < len(body):
        step = view[at : at + _GZIP_STEP]
        # One byte past the room tells a cut from a fit, and zlib reads a limit of 0 as none.
        size += out.write(inflater.decompress(step, limit - size + 1))
        if size > limit:
            out.truncate(limit)
            return out.getvalue(), True
        if not inflater.eof:
            at += len(step)
            continue
        found = _NOT_ZERO.search(body, at + len(step) - len(inflater.unused_data))
        if found is None or not body.startswith(_GZIP_MAGIC, found.start()):
            break
        at = found.start()
        inflater = zlib.decompressobj(_GZIP_WBITS)
    return out.getvalue(), not inflater.eof


def _deflate(body: bytes, limit: int) -> tuple[bytes, bool]:
    """Decode deflate with a zlib header (RFC 9110) or without one, as some servers send it."""
    try:
        return _inflate(body, limit, zlib.MAX_WBITS)
    except zlib.error:
        return _inflate(body, limit, -zlib.MAX_WBITS)


# brotli's `output_buffer_limit` can overshoot by one block; small steps bound the overshoot.
_BROTLI_STEP = 1024 * 1024


def _brotli(body: bytes, limit: int) -> tuple[bytes, bool]:
    """Decode br, refusing a stream that ends early."""
    decompressor = brotli.Decompressor()
    parts: list[bytes] = []
    size = 0
    data = body
    while size <= limit and not decompressor.is_finished():
        # Input goes in on the first call only; later calls drain output (brotli 1.2's contract).
        part: bytes = decompressor.process(data, output_buffer_limit=_BROTLI_STEP)
        data = b""
        if not part:
            break
        parts.append(part)
        size += len(part)
    if not decompressor.is_finished() and size <= limit:
        raise brotli.error("incomplete or truncated stream")
    if size > limit:  # cut the last part, not the joined whole: a third copy of the cap
        parts[-1] = parts[-1][: len(parts[-1]) - (size - limit)]
    return b"".join(parts), size > limit


def _zstd(body: bytes, limit: int) -> tuple[bytes, bool]:
    """Decode zstd in one read of `limit + 1`; a second read misses a stream cut inside a block."""
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body), read_across_frames=True)
    out: bytes = reader.read(limit + 1)
    if len(out) > limit:
        return out[:limit], True
    return out, False


_AWS_CHUNKED = "aws-chunked"
_CHUNK_LINE = re.compile(rb"([0-9A-Fa-f]{1,16})(?:;[^\r\n]*)?\r\n")


def _aws_chunked(body: bytes, limit: int) -> tuple[bytes, bool]:
    """Undo S3's `aws-chunked` framing: sized chunks up to an empty one, its trailers dropped.

    boto3 frames S3 uploads this way by default, so an S3 write could not be faked otherwise.
    """
    out = bytearray()
    at = 0
    while True:
        line = _CHUNK_LINE.match(body, at)
        if line is None:
            raise ValueError("not an aws-chunked chunk")
        size, at = int(line.group(1), 16), line.end()
        if not size:
            return bytes(out), False
        if len(out) + size > limit:
            out += body[at : at + limit - len(out)]
            return bytes(out), True
        if not body.startswith(b"\r\n", at + size):
            raise ValueError("an aws-chunked chunk ends early")
        out += body[at : at + size]
        at += size + 2


_DECODERS: dict[str, Callable[[bytes, int], tuple[bytes, bool]]] = {
    "gzip": _gzip,
    "x-gzip": _gzip,  # RFC 9110 has a recipient read it as gzip
    "deflate": _deflate,
    "deflateraw": _deflate,
    "br": _brotli,
    "zstd": _zstd,
    _AWS_CHUNKED: _aws_chunked,
}
