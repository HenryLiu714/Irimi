"""The profile W6's two `account_profile` read tools return, in a module only they import.

A replay asks the recording before the tool's body runs, when this module is not imported yet,
so it cannot rebuild the recorded profile, as with a client library a tool imports lazily."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    id: str
    industry: str | None
    views: int | None
