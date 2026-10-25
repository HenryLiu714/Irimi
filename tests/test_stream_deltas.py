"""Where each provider's streamed events hold a piece of text: `irimi.core.stream_deltas`."""

import copy
import json
import random
from typing import Any

import pytest

from irimi.core.stream_deltas import Delta, deltas, set_text

# One event of each shape a model streams text in, and the pieces `deltas` finds in it.
SHAPES = {
    "anthropic text": (
        {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "hi"}},
        [Delta(("anthropic", 1), ("delta", "text"), "hi")],
    ),
    "anthropic tool input": (
        {
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": '{"a": '},
        },
        [Delta(("anthropic", 2), ("delta", "partial_json"), '{"a": ')],
    ),
    "openai chat": (
        {
            "object": "chat.completion.chunk",
            "choices": [
                {"index": 0, "delta": {"content": "one"}},
                {
                    "index": 1,
                    "delta": {
                        "content": "two",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "function": {"name": "f", "arguments": ""},
                            },
                            {"index": 3, "function": {"arguments": '{"b'}},
                        ],
                    },
                },
            ],
        },
        [
            Delta(("chat", 0), ("choices", 0, "delta", "content"), "one"),
            Delta(("chat", 1), ("choices", 1, "delta", "content"), "two"),
            Delta(
                ("chat", 1, 0),
                ("choices", 1, "delta", "tool_calls", 0, "function", "arguments"),
                "",
            ),
            Delta(
                ("chat", 1, 3),
                ("choices", 1, "delta", "tool_calls", 1, "function", "arguments"),
                '{"b',
            ),
        ],
    ),
    "openai responses text": (
        {
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": "hel",
        },
        [Delta(("response.output_text.delta", "msg_1", 0, 0), ("delta",), "hel")],
    ),
    "openai responses arguments": (
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "fc_1",
            "output_index": 1,
            "delta": '{"q":',
        },
        [Delta(("response.function_call_arguments.delta", "fc_1", 1, None), ("delta",), '{"q":')],
    ),
}


@pytest.mark.parametrize("shape", SHAPES)
def test_each_shape_a_model_streams_text_in_gives_its_pieces_with_their_streams(shape):
    """A piece's text id names the text it is part of: a block, a choice, a tool call, an item."""
    event, expected = SHAPES[shape]
    assert deltas(event) == expected


@pytest.mark.parametrize("shape", SHAPES)
def test_set_text_puts_a_text_where_its_piece_was_and_nowhere_else(shape):
    event, found = SHAPES[shape]
    for delta in found:
        changed = copy.deepcopy(event)
        set_text(changed, delta.path, "NEW")
        assert [d.text for d in deltas(changed)] == ["NEW" if d is delta else d.text for d in found]
        set_text(changed, delta.path, delta.text)
        assert changed == event


@pytest.mark.parametrize(
    "event",
    [
        # Other events of the same streams, which carry no text.
        {"type": "message_start", "message": {"content": [], "id": "msg_1"}},
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
        {"choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]},
        {"type": "response.output_text.done", "text": "whole"},
        # Delta shapes it does not know.
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": "x"},
        },
        {"candidates": [{"content": {"parts": [{"text": "x"}]}}]},
        # Shapes gone wrong.
        {"type": "content_block_delta", "delta": "text"},
        {"type": "content_block_delta", "delta": {"type": ["text_delta"], "text": "x"}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": 1}},
        {"choices": {"0": {"delta": {"content": "x"}}}},
        {"choices": ["x", None, {"delta": "x"}, {"delta": {"content": None, "tool_calls": {}}}]},
        {"choices": [{"delta": {"tool_calls": [None, {"function": "x"}, {"function": {}}]}}]},
        {"type": "response.output_text.delta", "delta": ["x"]},
        {"type": ["response.output_text.delta"], "delta": "x"},
        [{"type": "content_block_delta"}],
        "text",
        None,
    ],
)
def test_an_event_that_holds_no_known_piece_gives_none(event):
    assert deltas(event) == []


def test_an_index_that_is_not_a_string_or_an_integer_tells_no_text_apart():
    """Pieces whose texts cannot be told apart join into one, which hides more across them."""
    for odd in (None, [0], {"a": 1}, 1.5, float("inf"), float("nan")):
        event: dict[str, Any] = {"type": "content_block_delta", "index": odd}
        event["delta"] = {"type": "text_delta", "text": "x"}
        assert deltas(event) == [Delta(("anthropic", None), ("delta", "text"), "x")]


def test_a_whole_float_index_is_the_integer_a_client_reads_it_as():
    event: dict[str, Any] = {"type": "content_block_delta", "index": 1.0}
    event["delta"] = {"type": "text_delta", "text": "x"}
    [delta] = deltas(event)
    assert delta.text_id == ("anthropic", 1) and type(delta.text_id[1]) is int


# What a mutated event's parts may become: JSON of every type, some of it shaped like a piece.
_ODD: tuple[Any, ...] = (
    None,
    True,
    0,
    1.5,
    "",
    "x",
    [],
    {},
    ["x"],
    {"text": "x"},
    {"type": "text_delta"},
)


def _mutated(rng: random.Random, value):
    """`value` with some of its parts dropped or swapped for `_ODD` values."""
    if rng.random() < 0.15:
        return rng.choice(_ODD)
    if isinstance(value, dict):
        return {k: _mutated(rng, v) for k, v in value.items() if rng.random() > 0.1}
    if isinstance(value, list):
        return [_mutated(rng, v) for v in value if rng.random() > 0.1]
    return value


def test_deltas_never_raises_and_every_path_it_gives_holds_its_text():
    """Over events of every shape with parts dropped or swapped, as a broken stream sends them."""
    rng = random.Random(92)
    events = [event for event, _ in SHAPES.values()]
    found = 0
    for _ in range(5000):
        event = _mutated(rng, rng.choice(events))
        for delta in deltas(event):
            found += 1
            changed = json.loads(json.dumps(event))
            set_text(changed, delta.path, delta.text + "!")
            assert delta.text + "!" in [d.text for d in deltas(changed)]
    assert found > 1000
