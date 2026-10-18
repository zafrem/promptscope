import json
import threading
from typing import Any, Callable, Dict, Optional, Union

from . import _native
from .types import (
    InputTooLargeError,
    InvalidRulesError,
    OutputResult,
    PromptscopeError,
    SanitizeResult,
    ScanResult,
)

_ERRORS = {
    "input_too_large": InputTooLargeError,
    "invalid_rules": InvalidRulesError,
}


def _unwrap(env: Dict[str, Any], build: Optional[Callable[[Dict[str, Any]], Any]] = None) -> Any:
    if env.get("ok"):
        result = env.get("result")
        return build(result) if build and result is not None else result
    result = env.get("result")
    if build and result is not None:
        result = build(result)
    cls = _ERRORS.get(env.get("error", ""), PromptscopeError)
    raise cls(env.get("error", "internal"), env.get("message", ""), result)


class Engine:
    """Prompt-injection and leakage scanner backed by the Go engine.

    An Engine is safe to share between threads; the native calls release the
    GIL. Use it as a context manager or call :meth:`close` to free it early.

    Scan methods raise :class:`PromptscopeError` when the engine reports an
    error (for example ``input_too_large``). The exception's ``result`` holds
    the engine's verdict, which is the *unsafe* one unless ``fail_open=True``.
    """

    def __init__(
        self,
        *,
        prompt_threshold: Optional[float] = None,
        context_threshold: Optional[float] = None,
        leak_threshold: Optional[float] = None,
        sanitize_mode: str = "filter",
        fail_open: bool = False,
        max_input_bytes: Optional[int] = None,
        max_decode_depth: Optional[int] = None,
        max_expansion: Optional[int] = None,
        min_encoded_bytes: Optional[int] = None,
    ) -> None:
        limits = {
            "max_input_bytes": max_input_bytes,
            "max_decode_depth": max_decode_depth,
            "max_expansion": max_expansion,
            "min_encoded_bytes": min_encoded_bytes,
        }
        config = {
            "prompt_threshold": prompt_threshold,
            "context_threshold": context_threshold,
            "leak_threshold": leak_threshold,
            "sanitize_mode": sanitize_mode,
            "fail_open": fail_open,
            "limits": {k: v for k, v in limits.items() if v is not None},
        }
        config = {k: v for k, v in config.items() if v is not None}
        self._lock = threading.Lock()
        self._handle = _unwrap(_native.call("ps_engine_new", json.dumps(config)))["handle"]

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            handle, self._handle = self._handle, 0
        if handle:
            _native.lib().ps_engine_free(handle)

    def __enter__(self) -> "Engine":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _h(self) -> int:
        if not self._handle:
            raise PromptscopeError("invalid_handle", "engine is closed")
        return self._handle

    # -- scanning ----------------------------------------------------------

    def scan_prompt(self, prompt: str) -> ScanResult:
        return _unwrap(_native.call("ps_scan_prompt", self._h(), prompt), ScanResult._from)

    def sanitize_context(self, chunk: str) -> SanitizeResult:
        return _unwrap(_native.call("ps_sanitize_context", self._h(), chunk), SanitizeResult._from)

    def scan_output(self, response: str) -> OutputResult:
        return _unwrap(_native.call("ps_scan_output", self._h(), response), OutputResult._from)

    # -- configuration -----------------------------------------------------

    def register_prompt(self, prompt_id: str, system_prompt: str) -> None:
        """Fingerprint a system prompt so :meth:`scan_output` can detect it leaking."""
        _unwrap(_native.call("ps_register_prompt", self._h(), prompt_id, system_prompt))

    def register_canary(self, canary_id: str, token: str) -> None:
        """Register a decoy token that must never appear in model output."""
        _unwrap(_native.call("ps_register_canary", self._h(), canary_id, token))

    def load_rules(self, rules: Union[str, Dict[str, Any]], *, merge_baseline: bool = True) -> str:
        """Install a JSON rule set (a dict or JSON text) and return its version.

        With ``merge_baseline`` the rules are layered over the built-in baseline
        pack (a rule with the same ID replaces the baseline rule); otherwise
        they replace every rule.
        """
        text = rules if isinstance(rules, str) else json.dumps(rules)
        env = _native.call("ps_load_rules", self._h(), text, 1 if merge_baseline else 0)
        return _unwrap(env)["version"]

    @property
    def rules_version(self) -> str:
        return _unwrap(_native.call("ps_rules_version", self._h()))["version"]
