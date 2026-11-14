"""Shared wording and step numbering for explanatory GUI text."""
from __future__ import annotations

import re


_PARTICIPANTS = (
    ("trang", "Trang", "Sender"),
    ("thuy|thủy", "Thủy", "Receiver"),
    ("phuong|phương", "Phương", "Attacker"),
    ("linh", "Linh", "Third Party"),
)
_STEP_PREFIX = re.compile(r"^\s*(?:\[\d+\]|\d+\.)\s*")


def participant_text(text: str) -> str:
    """Format names in narrative text; leave paths and machine identifiers intact."""
    for aliases, name, role in _PARTICIPANTS:
        pattern = rf"(?<![\w/\\.])(?:{aliases})(?![\w/\\]|\.[\w])(?:\s*\(\s*{role}\s*\))?"

        def replace(match: re.Match[str]) -> str:
            if name == "Phương" and (
                re.search(r"\bbình\s+$", text[:match.start()], re.IGNORECASE)
                or re.match(r"\s+(?:pháp|trình|hướng|án|tiện)\b", text[match.end():], re.IGNORECASE)
            ):
                return match.group()
            return role

        text = re.sub(pattern, replace, text, flags=re.IGNORECASE)
    return text


def is_numbered_step(title: str, level: str) -> bool:
    # Some scenarios mark an action as a heading for emphasis.
    return level != "head" or _STEP_PREFIX.match(title) is not None


def step_title(index: int, title: str, level: str) -> str:
    numbered = is_numbered_step(title, level)
    title = participant_text(_STEP_PREFIX.sub("", title).strip())
    return f"{index}. {title}" if numbered else title
