"""Result types returned by :class:`promptscope.Engine`."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Span:
    start: int
    end: int

    @classmethod
    def _from(cls, d: Dict[str, Any]) -> "Span":
        return cls(d["start"], d["end"])


@dataclass(frozen=True)
class Match:
    """One rule hit. ``start``/``end`` are *byte* offsets into the UTF-8
    encoding of the original input (half-open)."""

    rule_id: str
    category: str
    weight: float
    start: int
    end: int
    via: List[str] = field(default_factory=list)

    @classmethod
    def _from(cls, d: Dict[str, Any]) -> "Match":
        return cls(d["rule_id"], d["category"], d["weight"], d["start"], d["end"], d.get("via") or [])


def _matches(d: Dict[str, Any]) -> List[Match]:
    return [Match._from(m) for m in d.get("matches") or []]


@dataclass(frozen=True)
class ScanResult:
    is_safe: bool
    risk_score: float
    matches: List[Match] = field(default_factory=list)

    @classmethod
    def _from(cls, d: Dict[str, Any]) -> "ScanResult":
        return cls(d["is_safe"], d["risk_score"], _matches(d))


@dataclass(frozen=True)
class SanitizeResult:
    sanitized_text: str
    has_injection: bool
    risk_score: float
    blocked: bool
    removed: List[Span] = field(default_factory=list)
    matches: List[Match] = field(default_factory=list)

    @classmethod
    def _from(cls, d: Dict[str, Any]) -> "SanitizeResult":
        return cls(
            d.get("sanitized_text", ""),
            d["has_injection"],
            d["risk_score"],
            d["blocked"],
            [Span._from(s) for s in d.get("removed") or []],
            _matches(d),
        )


@dataclass(frozen=True)
class OutputResult:
    is_leaked: bool
    leak_confidence: float
    matched_prompts: List[str] = field(default_factory=list)
    matched_canaries: List[str] = field(default_factory=list)
    matches: List[Match] = field(default_factory=list)

    @classmethod
    def _from(cls, d: Dict[str, Any]) -> "OutputResult":
        return cls(
            d["is_leaked"],
            d["leak_confidence"],
            d.get("matched_prompts") or [],
            d.get("matched_canaries") or [],
            _matches(d),
        )


class PromptscopeError(Exception):
    """Raised when the engine reports an error.

    ``code`` is one of ``input_too_large``, ``invalid_rules``, ``no_rules``,
    ``invalid_handle``, ``invalid_argument`` or ``internal``. For scan calls,
    ``result`` holds the verdict the engine returned alongside the error: the
    unsafe verdict by default, the safe one with ``fail_open=True``.
    """

    def __init__(self, code: str, message: str, result: Optional[Any] = None):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message
        self.result = result


class InputTooLargeError(PromptscopeError):
    pass


class InvalidRulesError(PromptscopeError):
    pass
