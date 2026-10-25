"""The profile W6's `account_profile` read tool returns, in a module only that tool imports.

A replay asks the recording before the tool's body runs, when this module is not imported yet,
so it cannot rebuild the recorded profile, as with a client library a tool imports lazily."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    id: str
    industry: str | None
    views: int | None
