"""Loads the promptscope C library and wraps its JSON-envelope calls."""

import ctypes
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

ABI_VERSION = 1

_LIB_NAMES = {
    "win32": ("promptscope.dll",),
    "darwin": ("libpromptscope.dylib",),
}.get(sys.platform, ("libpromptscope.so",))


def _find_library() -> str:
    override = os.environ.get("PROMPTSCOPE_LIB")
    if override:
        return override
    native = Path(__file__).resolve().parent / "_native"
    for name in _LIB_NAMES:
        candidate = native / name
        if candidate.exists():
            return str(candidate)
    raise OSError(
        "promptscope native library not found in %s. Install a platform wheel, "
        "build it with `make lib`, or set PROMPTSCOPE_LIB." % native
    )


def _load() -> ctypes.CDLL:
    lib = ctypes.CDLL(_find_library())
    u64, vp, sz, ci = ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int
    sig = {
        "ps_abi_version": ([], ci),
        "ps_engine_new": ([vp, sz], vp),
        "ps_engine_free": ([u64], None),
        "ps_load_rules": ([u64, vp, sz, ci], vp),
        "ps_rules_version": ([u64], vp),
        "ps_register_prompt": ([u64, vp, sz, vp, sz], vp),
        "ps_register_canary": ([u64, vp, sz, vp, sz], vp),
        "ps_scan_prompt": ([u64, vp, sz], vp),
        "ps_sanitize_context": ([u64, vp, sz], vp),
        "ps_scan_output": ([u64, vp, sz], vp),
        "ps_free": ([vp], None),
    }
    for name, (argtypes, restype) in sig.items():
        fn = getattr(lib, name)
        fn.argtypes = argtypes
        fn.restype = restype
    if lib.ps_abi_version() != ABI_VERSION:
        raise OSError(
            "promptscope native library has ABI %d, this package needs %d"
            % (lib.ps_abi_version(), ABI_VERSION)
        )
    return lib


_lib: Optional[ctypes.CDLL] = None


def lib() -> ctypes.CDLL:
    global _lib
    if _lib is None:
        _lib = _load()
    return _lib


def _bytes(text: str) -> bytes:
    # Lone surrogates cannot be encoded; replace rather than raise so that
    # hostile input is scanned instead of crashing the caller.
    return text.encode("utf-8", errors="replace")


def call(name: str, *args: Any) -> Dict[str, Any]:
    """Call a ps_* function and return its decoded envelope.

    str arguments are passed as (pointer, length) pairs; None passes (NULL, 0).
    """
    native = lib()
    c_args = []
    keep = []  # keeps encoded buffers alive for the duration of the call
    for a in args:
        if isinstance(a, str) or a is None:
            raw = _bytes(a) if a is not None else b""
            keep.append(raw)
            c_args.append(ctypes.cast(ctypes.c_char_p(raw), ctypes.c_void_p) if raw else None)
            c_args.append(len(raw))
        else:
            c_args.append(a)
    ptr = getattr(native, name)(*c_args)
    try:
        return json.loads(ctypes.string_at(ptr))
    finally:
        native.ps_free(ptr)
