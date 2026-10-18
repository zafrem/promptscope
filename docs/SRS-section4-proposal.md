# Section 4 (revised proposal): Go Interface & Data Model

Status: **draft for review**. Replaces section 4 of `SRS.md`. Resolves review items 1, 2, 3, 5, 6, 7.

## 4.0 Design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Rules are **JSON** (not YAML) | Go stdlib has `encoding/json` but no YAML; keeps NFR-2. A YAML-to-JSON step can live in forge tooling. |
| D2 | Match offsets are **byte offsets into the original input** | Normalization changes offsets; the engine keeps an offset map so callers can highlight or redact the text they sent. |
| D3 | Score = **noisy-OR** of matched rule weights, `1 - Π(1 - wᵢ)` | Monotonic, bounded to [0,1], and many weak signals accumulate without exceeding 1. |
| D4 | Engine is built from `Config` + `RuleSet`; scanning methods are stateless | Satisfies NFR-3. Hot-reload swaps an immutable `*RuleSet` via `atomic.Pointer`. |
| D5 | System prompts are **registered** on the engine, not passed per call | The n-gram fingerprint is precomputed once instead of rebuilt on every `ScanOutput`. |
| D6 | Fail-closed by default: an error means the caller must treat the input as unsafe | `Config.FailOpen` flips this; the choice is explicit. |
| D7 | Decoding is bounded by `Limits` | Prevents decompression-bomb-style DoS and protects NFR-1. |

## 4.1 Configuration

```go
package promptscope

// Config is immutable after New.
type Config struct {
    // Thresholds are in [0,1].
    PromptThreshold   float64 // ScanPrompt: IsSafe = RiskScore < PromptThreshold. Default 0.5
    ContextThreshold  float64 // SanitizeContext: Block drops the chunk at/above this. Default 0.7
    LeakThreshold     float64 // ScanOutput: IsLeaked = LeakConfidence >= LeakThreshold. Default 0.6

    SanitizeMode SanitizeMode // ModeFilter (default) or ModeBlock
    Limits       Limits
    FailOpen     bool // default false (D6)
}

type SanitizeMode int

const (
    ModeFilter SanitizeMode = iota // strip only malicious spans
    ModeBlock                      // drop the whole chunk at/above ContextThreshold
)

// Limits bound the work done per call (D7). Zero values select defaults.
type Limits struct {
    MaxInputBytes   int // default 64 KiB; larger input returns ErrInputTooLarge
    MaxDecodeDepth  int // nested Base64/hex layers; default 3
    MaxExpansion    int // decoded bytes may not exceed N x input; default 4
    MinEncodedBytes int // shortest blob considered for Base64/hex decoding; default 24
}
```

## 4.2 Results

```go
// Match is one rule hit. Start/End are byte offsets into the ORIGINAL input (D2),
// half-open [Start, End).
type Match struct {
    RuleID   string   `json:"rule_id"`
    Category Category `json:"category"`
    Weight   float64  `json:"weight"`
    Start    int      `json:"start"`
    End      int      `json:"end"`
    // Via records the transforms applied before this match was found,
    // e.g. ["base64"], ["hex","nfkc"]. Empty for a direct match.
    Via []string `json:"via,omitempty"`
}

type Category string

const (
    CatInstructionOverride Category = "instruction_override" // FR-1.1
    CatDelimiterEscape     Category = "delimiter_escape"     // FR-1.2
    CatObfuscation         Category = "obfuscation"          // FR-1.3
    CatInvisibleChar       Category = "invisible_char"       // FR-2.1
    CatBoundaryViolation   Category = "boundary_violation"   // FR-2.2
    CatTemplateBleed       Category = "template_bleed"       // FR-3.3
)

// ScanResult is the verdict for ScanPrompt.
type ScanResult struct {
    IsSafe    bool    `json:"is_safe"`
    RiskScore float64 `json:"risk_score"` // 0.0 to 1.0, noisy-OR of Matches (D3)
    Matches   []Match `json:"matches,omitempty"`
}

// SanitizeResult is the verdict for SanitizeContext.
type SanitizeResult struct {
    SanitizedText string  `json:"sanitized_text"` // empty when Blocked
    HasInjection  bool    `json:"has_injection"`
    RiskScore     float64 `json:"risk_score"`
    Blocked       bool    `json:"blocked"` // true if ModeBlock dropped the chunk
    // Removed lists spans taken out in ModeFilter, or the whole chunk span when Blocked.
    // Offsets are into the original input.
    Removed []Span  `json:"removed,omitempty"`
    Matches []Match `json:"matches,omitempty"`
}

type Span struct {
    Start int `json:"start"`
    End   int `json:"end"`
}

// OutputResult is the verdict for ScanOutput.
type OutputResult struct {
    IsLeaked       bool    `json:"is_leaked"`
    LeakConfidence float64 `json:"leak_confidence"` // 0.0 to 1.0
    // MatchedPrompts holds IDs of registered system prompts whose fingerprint matched.
    MatchedPrompts  []string `json:"matched_prompts,omitempty"`
    MatchedCanaries []string `json:"matched_canaries,omitempty"` // canary IDs, never the token values
    Matches         []Match  `json:"matches,omitempty"`          // template-bleed hits
}
```

Privacy note: results carry rule IDs and offsets, **not** copies of user text. This replaces `DetectedTokens` from the original draft. Callers who need the text can slice the input with the offsets.

## 4.3 Engine

```go
// Engine is safe for concurrent use (NFR-3).
type Engine interface {
    ScanPrompt(prompt string) (ScanResult, error)
    SanitizeContext(chunk string) (SanitizeResult, error)
    ScanOutput(response string) (OutputResult, error)

    // RegisterPrompt precomputes the n-gram fingerprint for FR-3.1 (D5).
    // id is returned in OutputResult.MatchedPrompts. Re-registering an id replaces it.
    RegisterPrompt(id, systemPrompt string) error
    // RegisterCanary adds an exact-match decoy token for FR-3.2.
    RegisterCanary(id, token string) error

    // Reload atomically swaps the rule set (NFR-4). In-flight scans finish on the old set.
    Reload(rules *RuleSet) error
    RulesVersion() string
}

func New(cfg Config, rules *RuleSet) (Engine, error)
func LoadRules(r io.Reader) (*RuleSet, error)   // parses + validates JSON per 4.5
func LoadRulesFile(path string) (*RuleSet, error)

var (
    ErrInputTooLarge = errors.New("promptscope: input exceeds Limits.MaxInputBytes")
    ErrInvalidRules  = errors.New("promptscope: invalid rule set")
    ErrNoRules       = errors.New("promptscope: no rules loaded")
)
```

### Error semantics (D6)

- Scan methods return a non-nil error only for `ErrInputTooLarge` or `ErrNoRules`.
- By default the accompanying result is the *unsafe* verdict (`IsSafe=false` / `Blocked=true` / `IsLeaked=true`), so a caller that ignores the error still fails closed.
- With `Config.FailOpen`, the result is the safe verdict and the error is still returned.
- `Reload` with an invalid set returns `ErrInvalidRules` and keeps the old set.
- Decode-limit hits are **not** errors; the decoded layer is skipped and the match list gets an `obfuscation` match, since an overflowing encoded blob is itself suspicious.

## 4.4 Processing pipeline (ScanPrompt / SanitizeContext)

1. Reject input over `MaxInputBytes`.
2. Strip invisibles (ZWSP/ZWNJ/ZWJ, bidi controls, BOM), recording an offset map.
3. NFKC-normalize (requires vendored `norm` tables, see open question Q1).
4. Run matchers on the normalized text.
5. For each candidate Base64/hex blob of at least `MinEncodedBytes`: decode, accept only if the output is mostly printable UTF-8, and re-enter at step 2 with depth+1, up to `MaxDecodeDepth` and `MaxExpansion`.
6. Map match offsets back to the original input through the offset map.
7. Combine weights (D3) and compare to the threshold.

## 4.5 Rule schema

The JSON Schema is in `schema/rules.schema.json`; a worked example is in `schema/example-rules.json`.

Rule fields:

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Stable unique ID, `^[A-Z]{2,6}-[0-9]{3,4}$` (e.g. `OVR-001`). Appears in results. |
| `category` | yes | One of the `Category` values. |
| `applies_to` | yes | Subset of `["prompt","context","output"]`: which entry points use the rule. |
| `kind` | yes | `literal` (case-insensitive phrase set, Aho-Corasick), `regex` (RE2, so linear time), or `charclass` (code-point ranges). |
| `patterns` | yes | Strings for the given kind. For `charclass`: `"U+200B-U+200D"` style ranges. |
| `weight` | yes | 0 < w <= 1, contribution to noisy-OR. |
| `action` | no | For context scans in Filter mode: `strip_match` (default), `strip_line`, or `strip_block`. |
| `enabled` | no | Default true. |
| `description` | no | Human text for maintainers. |

Using Go's `regexp` (RE2) rules out catastrophic backtracking, which matters for rules loaded at runtime.

## 4.6 Rule packs and merging (open-core split)

The engine is public; the strongest detection data is not. Rules are therefore delivered as **packs**:

- **Baseline pack:** a small, public rule set embedded in the Go module with `go:embed` (`rules/baseline.json`). It makes the engine useful out of the box and doubles as the reference for the schema.
- **Private packs:** produced by `promptscope-forge`, loaded at runtime from a file or an `io.Reader`. They are never committed to this repo or embedded in the module.

```go
func BaselineRules() *RuleSet                     // embedded public pack
func MergeRules(sets ...*RuleSet) (*RuleSet, error) // later sets override earlier ones by rule ID
```

Merge rules:
- A rule ID present in a later set replaces the earlier one. `"enabled": false` in a later set disables a baseline rule.
- The merged `RulesVersion()` is the comma-joined list of pack versions.
- `Reload` takes the merged result, so a private pack can be updated at runtime without a release (NFR-4).

Schema addition: the top-level object gains an optional `pack` string (a name such as `baseline` or `forge-2026-10`), reported alongside the version.

## 4.7 Repositories and distribution

| Repo | Visibility | Contains | Published as |
|------|------------|----------|--------------|
| `promptscope` | public | Go engine (repo root, package `promptscope`), C API (`capi/`), Python wrapper (`python/`), schema, baseline pack, docs | Go module (`github.com/zafrem/promptscope`) and PyPI wheels |
| `promptscope-forge` | **private** | Curated vocabulary and dictionaries, attack/benign corpora, rule-authoring and export tooling, benchmark harness | Not published. Produces private rule packs (JSON) |

- **Go:** consumers `go get` the module; the engine is pure Go and stdlib-only, apart from the vendored `norm` tables (Q1). The module root must hold `go.mod`, so the Go packages live at the repo root, not under a subdirectory.
- **Python:** CI builds `capi/` into a shared library per platform (manylinux x86_64/aarch64, macOS x86_64/arm64, Windows x86_64), and each is packaged in a wheel that loads the library with `ctypes`/`cffi`. This avoids a Python build toolchain on the user's machine. A source distribution is not needed.
- **Dependency direction:** forge depends on promptscope (it imports the module and uses the submodule for the schema and the engine in tests). promptscope never depends on forge.
- **Release flow:** forge exports a pack, then validates it against `schema/rules.schema.json` and runs the corpus through the engine; the pack is then handed to deployments, not to this repo.
- **What is public:** the engine, the schema, the baseline pack, and the wrapper code. Anything shipped in the module or a wheel should be treated as public, including the baseline rules.

## 4.8 Open questions

- **Q1.** NFKC needs `golang.org/x/text/unicode/norm`, which is not stdlib. Options: vendor that package (BSD-licensed, pure Go, so it satisfies the "vendored pure-Go" wording of NFR-2), or generate compact tables ourselves. I recommend vendoring.
- **Q2.** Is homoglyph/confusable folding in scope for v1? NFKC does not fold Cyrillic "а" to Latin "a".
- **Q3. (Resolved)** The Python wrapper binds to a cgo shared library built in CI and bundled in platform wheels (see 4.7). `Engine` therefore needs a C-compatible surface (`capi/`), which is a thin layer over the Go API.
- **Q4.** Do you want a p99 latency target alongside the median in NFR-1?
