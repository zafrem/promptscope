# promptscope

A small scanner for prompt injection, hidden instructions in retrieved text, and system prompt leaks.
It uses rules and string matching only: no model, no network, no dependencies outside the Go standard
library. It reports a score and where the matches are; your code decides what to do.

Written in Go, with Python bindings. Showcase: <http://promptscope.codeforlife.dev/>

> **Status: early draft (v0.1.0).** The built-in pack has six example rules, not a vetted list. No detection
> rate has been measured, rule weights and thresholds are provisional, and no license has been chosen yet.
> Treat it as one layer of defense, not the only one. See [what it does not catch](#limits).

## What it does

| Entry point | Input | What it looks for |
|-------------|-------|-------------------|
| `ScanPrompt` | what users send | instruction overrides, fake chat markers, hidden characters, encoded payloads |
| `SanitizeContext` | retrieved text (RAG chunks, pages, files) | the same, plus HTML comments; cuts the injected span (filter) or drops the chunk (block) |
| `ScanOutput` | model replies | a registered canary token, a copied system prompt, unfilled template placeholders |

Text goes through five steps: strip invisible characters, normalize to Unicode NFKC, fold Cyrillic look-alike
letters to Latin (only inside words that also contain Latin letters, so Russian text is left alone), decode Base64/hex
blobs (bounded in depth and size, accepted only if the result reads as text), then match rules. Every match
carries byte offsets into your original input. The risk score combines rule weights with noisy-OR:
`1 - Π(1 - weight)`, each rule counted once.

## Go

```go
import "github.com/zafrem/promptscope"

eng, err := promptscope.New(promptscope.Config{}, promptscope.BaselineRules())
res, err := eng.ScanPrompt(userInput)
if !res.IsSafe {
    // res.RiskScore, res.Matches[i].RuleID, .Start, .End
}

eng.RegisterCanary("c1", "CANARY-7f3a")
eng.RegisterPrompt("sys", systemPrompt)
out, err := eng.ScanOutput(modelReply)
```

An `Engine` is safe for concurrent use. A scan that fails (input over `Limits.MaxInputBytes`, no rules
loaded) returns an error together with the *unsafe* verdict, unless `Config.FailOpen` is set.

## Python

Not on PyPI yet. Build from source; the wheel bundles the engine as a shared library.

```
make lib
pip install ./python
```

```python
from promptscope import Engine

with Engine() as engine:
    r = engine.scan_prompt(user_input)
    if not r.is_safe:
        print(r.risk_score, [m.rule_id for m in r.matches])
    clean = engine.sanitize_context(chunk).sanitized_text
```

See [`python/README.md`](python/README.md). Match offsets there are byte offsets into the UTF-8 encoding.

## Rules

Rules are JSON, validated against [`schema/rules.schema.json`](schema/rules.schema.json). Three kinds:
case-insensitive `literal` phrases, `regex` (Go RE2, so no runaway backtracking), and `charclass` code-point
ranges. Each rule has a weight, a category, and the entry points it applies to.

The built-in baseline pack is [`rules/baseline.json`](rules/baseline.json). Your own packs load at runtime
and layer over it; a rule with the same ID replaces the baseline one, and `"enabled": false` switches it off:

```go
rs, _ := promptscope.LoadRulesFile("my-rules.json")
merged, _ := promptscope.MergeRules(promptscope.BaselineRules(), rs)
eng.Reload(merged) // atomic; in-flight scans finish on the old set
```

### Optional pack: `english-only`

For applications whose users are expected to write English, [`rules/english-only.json`](rules/english-only.json)
flags Hangul (`SCR-001`), Hiragana/Katakana (`SCR-002`) and Han ideographs (`SCR-003`) in **prompts**, category
`unexpected_script`. `SCR-004`/`SCR-005` are low-weight markers for characters used only in Simplified or only
in Traditional Chinese, so the report can tell the two apart; text with only shared characters reports
`SCR-003` alone. It is not in the baseline because it would flag every non-English user, and it is a policy
signal, not an attack signature. Details:

- Each script rule weighs 0.6, above the default prompt threshold of 0.5, so one match makes the prompt unsafe.
  Scores compound, so Japanese (kana plus kanji) scores higher than Chinese. Override weights with your own pack.
- It applies to prompts only. Retrieved context and model output may legitimately be multilingual, and filter
  mode would delete them. Re-declare a rule with `applies_to` including `context` to change that.
- Scripts are found after NFKC and decoding, so half-width katakana and Base64-wrapped text are caught.
- It looks at scripts, not languages: it cannot tell Chinese from Japanese kanji or Korean hanja.

```go
rs, _ := promptscope.MergeRules(promptscope.BaselineRules(), promptscope.EnglishOnlyRules())
```

Through the C API and Python, pass `packs=["english-only"]` when creating the engine; `load_rules` keeps it.

### Optional packs: `lang-ko`, `lang-ja`, `lang-zh-hans`, `lang-zh-hant`

The baseline only has English phrases. Each of these adds two instruction-override rules for one language,
counterparts of `OVR-001` (listed phrases, weight 0.85) and `OVR-002` (a looser pattern, weight 0.8): `KOR-`,
`JPN-`, `CHS-` and `CHT-` followed by 001 and 002. Load only the languages your app sees, so you pay for no
more rules than you need and no more false positives than you accept. Simplified and Traditional are separate
packs because the characters differ; a sentence written with shared characters matches both.

```go
rs, _ := promptscope.BuiltinPack("lang-ko")
merged, _ := promptscope.MergeRules(promptscope.BaselineRules(), rs)
```

In Python, `Engine(packs=["lang-ko", "lang-ja"])`. They are phrase rules, so they share the limits of every
phrase rule: rewordings, spaced-out text and a sentence that talks about the phrase ("do not ignore previous
instructions") are not handled correctly. `go run ./experiments/langpacks` in the forge repo lists the misses.
For an English-only app, `english-only` is the stronger control.

## Limits

Paraphrases, other languages, look-alike letters from alphabets other than Cyrillic (for example Greek),
Cyrillic words made only of look-alikes, and letters split by punctuation all get through the baseline rules, and detecting instructions that are only phrased as plain
statements in third-party text is not built. The site shows recorded examples. A low score is not proof
that an input is safe.

## Layout

```
*.go            the engine (package promptscope)
internal/       vendored golang.org/x/text norm + transform (BSD; see internal/norm/LICENSE)
capi/           C ABI (c-shared library, JSON envelopes), used by the Python package
python/         Python package (ctypes) and tests
rules/          embedded baseline pack and the optional english-only and lang-* packs
schema/         JSON Schema and an example rule set
docs/           SRS and the section 4 design proposal
```

## Develop

```
make test          # go vet + go test -race
make python-test   # builds the shared library and runs pytest
make wheel         # platform wheel in python/dist/
```

Latency target: median under 1 ms for 1,000 characters. On a 2 GHz dual-core Celeron with the six baseline
rules, a scan took about 0.6 ms for ASCII text and just under 1.0 ms for non-ASCII text
(`go test -bench .`). Larger rule sets will cost more.

## Not finished

- Decoding limits (`MaxDecodeDepth`, `MaxExpansion`) are enforced; homoglyph folding covers Cyrillic letters inside words that also have Latin letters (rule `HMG-001` flags such a word); Greek and other scripts are not folded.
- No rule yet for instruction-like statements embedded in third-party text (FR-2.2 in the SRS).
- Python wheels have only been built and tested on Linux x86_64.
- No license has been chosen.
