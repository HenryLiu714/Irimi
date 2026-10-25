"""Where a model's streamed answer puts each piece of its text in one SSE event's JSON.

A model streams its text and a tool call's arguments as small deltas, one per event, so a value it
sends across several is whole only in the text the deltas join into.
- `deltas` finds the pieces of Anthropic Messages, OpenAI chat completions and OpenAI Responses
  streams, and nothing in any other JSON. It never raises.
- A piece's `path` leads to it in the event `deltas` found it in, for `set_text`.
"""

from typing import Any, NamedTuple

# The Anthropic delta types read, each with its field. Thinking and citations deltas are not.
_ANTHROPIC_FIELDS = {"text_delta": "text", "input_json_delta": "partial_json"}
# The OpenAI Responses deltas read. Reasoning, refusal and other tools' deltas are not.
_RESPONSES_TYPES = ("response.output_text.delta", "response.function_call_arguments.delta")


class Delta(NamedTuple):
    """A piece of streamed text: the text it is part of (`text_id`) and where its event holds it."""

    text_id: tuple[object, ...]
    path: tuple[str | int, ...]
    text: str


def deltas(event: object) -> list[Delta]:
    """Return the pieces of streamed text in `event`, one SSE event's parsed JSON, in order."""
    if not isinstance(event, dict):
        return []
    kind = event.get("type")
    if kind == "content_block_delta":
        return _anthropic(event)
    if kind in _RESPONSES_TYPES:
        return _openai_responses(event, kind)
    return _openai_chat(event)


def set_text(event: Any, path: tuple[str | int, ...], text: str) -> None:
    """Put `text` at `path` in `event`, a path `deltas` returned for it."""
    for step in path[:-1]:
        event = event[step]
    event[path[-1]] = text


def _anthropic(event: dict[str, Any]) -> list[Delta]:
    """Return a `content_block_delta`'s piece of its content block's text."""
    delta = event.get("delta")
    kind = delta.get("type") if isinstance(delta, dict) else None
    field = _ANTHROPIC_FIELDS.get(kind) if isinstance(kind, str) else None
    if field is None or not isinstance(delta, dict) or not isinstance(delta.get(field), str):
        return []
    return [Delta(("anthropic", _id(event.get("index"))), ("delta", field), delta[field])]


def _openai_responses(event: dict[str, Any], kind: str) -> list[Delta]:
    """Return a Responses text or arguments delta's piece of its output item's text."""
    if not isinstance(event.get("delta"), str):
        return []
    place = tuple(_id(event.get(name)) for name in ("item_id", "output_index", "content_index"))
    return [Delta((kind, *place), ("delta",), event["delta"])]


def _openai_chat(event: dict[str, Any]) -> list[Delta]:
    """Return each choice's piece of its content, and of each of its tool calls' arguments."""
    choices = event.get("choices")
    found = []
    for i, choice in enumerate(choices if isinstance(choices, list) else []):
        delta = choice.get("delta") if isinstance(choice, dict) else None
        if not isinstance(delta, dict):
            continue
        text_id = ("chat", _id(choice.get("index")))
        if isinstance(delta.get("content"), str):
            found.append(Delta(text_id, ("choices", i, "delta", "content"), delta["content"]))
        calls = delta.get("tool_calls")
        for j, call in enumerate(calls if isinstance(calls, list) else []):
            function = call.get("function") if isinstance(call, dict) else None
            if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                path = ("choices", i, "delta", "tool_calls", j, "function", "arguments")
                found.append(Delta((*text_id, _id(call.get("index"))), path, function["arguments"]))
    return found


def _id(value: object) -> object:
    """Return an index or id as part of a text's id; any other value tells no text apart.

    Texts that cannot be told apart join into one, which can hide more across them; each piece's
    own shapes are still hidden by its event's walk."""
    return value if isinstance(value, str | int) else None
