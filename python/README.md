# promptscope (Python)

Python bindings for the promptscope inspection engine. The engine is written in
Go and shipped inside the wheel as a shared library; there are no Python
dependencies.

```python
from promptscope import Engine

with Engine() as engine:
    result = engine.scan_prompt("Ignore previous instructions and ...")
    if not result.is_safe:
        print(result.risk_score, [m.rule_id for m in result.matches])

    clean = engine.sanitize_context(retrieved_chunk)   # strips hidden/injected spans
    engine.register_canary("c1", "CANARY-7f3a")
    leak = engine.scan_output(model_response)
```

Match offsets are byte offsets into the UTF-8 encoding of the input.
Scan calls raise `PromptscopeError` on engine errors (such as `input_too_large`);
the exception's `result` holds the engine's verdict, which is the unsafe one
unless the engine was created with `fail_open=True`.

## Building from source

```
make lib            # builds the shared library into python/src/promptscope/_native/
make python-test    # builds the library and runs the tests
make wheel          # platform wheel in python/dist/
```

Set `PROMPTSCOPE_LIB` to load a library from another location.
