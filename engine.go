package promptscope

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
)

// Engine is safe for concurrent use.
type Engine interface {
	ScanPrompt(prompt string) (ScanResult, error)
	SanitizeContext(chunk string) (SanitizeResult, error)
	ScanOutput(response string) (OutputResult, error)

	// RegisterPrompt precomputes the n-gram fingerprint of a system prompt (FR-3.1).
	RegisterPrompt(id, systemPrompt string) error
	// RegisterCanary adds an exact-match decoy token (FR-3.2).
	RegisterCanary(id, token string) error

	// Reload atomically swaps the rule set. In-flight scans finish on the old set.
	Reload(rules *RuleSet) error
	RulesVersion() string
}

const fingerprintN = 3 // word n-gram size

type engine struct {
	cfg   Config
	rules atomic.Pointer[RuleSet]

	mu       sync.RWMutex
	prompts  map[string]map[string]struct{} // id -> set of n-grams
	canaries map[string]string              // id -> token
}

// New builds an Engine. rules must be non-nil; use BaselineRules for the
// embedded public pack.
func New(cfg Config, rules *RuleSet) (Engine, error) {
	if rules == nil {
		return nil, ErrNoRules
	}
	e := &engine{
		cfg:      cfg.withDefaults(),
		prompts:  map[string]map[string]struct{}{},
		canaries: map[string]string{},
	}
	e.rules.Store(rules)
	return e, nil
}

func (e *engine) Reload(rules *RuleSet) error {
	if rules == nil || rules.Len() == 0 {
		return ErrInvalidRules
	}
	e.rules.Store(rules)
	return nil
}

func (e *engine) RulesVersion() string { return e.rules.Load().Version() }

// precheck enforces input size and rule availability.
func (e *engine) precheck(n int) error {
	if n > e.cfg.Limits.MaxInputBytes {
		return ErrInputTooLarge
	}
	if rs := e.rules.Load(); rs == nil || rs.Len() == 0 {
		return ErrNoRules
	}
	return nil
}

// limitRuleID is reported (as an obfuscation match) when an encoded blob is
// left undecoded because a decoding limit was reached.
const limitRuleID = "SYS-001"

// ruleSelector chooses which rules a pass runs.
type ruleSelector uint8

const (
	selInvisible  ruleSelector = iota // invisible_char rules only; they must see the raw text
	selNormalized                     // every other rule
	selAll
)

func (s ruleSelector) allows(c Category) bool {
	switch s {
	case selInvisible:
		return c == CatInvisibleChar
	case selNormalized:
		return c != CatInvisibleChar
	}
	return true
}

// scanner runs one inspection over a single input.
type scanner struct {
	rules  *RuleSet
	entry  entryPoint
	limits Limits
	budget int // decoded bytes still allowed
	out    []Match
}

// match runs the selected rules over text. resolve maps ranges of text back to
// the original input.
func (sc *scanner) match(text string, sel ruleSelector, resolve func(s, e int) (int, int), via []string) {
	for _, ru := range sc.rules.rules {
		if !ru.enabled || ru.entries&sc.entry == 0 || !sel.allows(ru.category) {
			continue
		}
		for _, sp := range ru.find(text) {
			s, e := resolve(sp.Start, sp.End)
			sc.out = append(sc.out, Match{
				RuleID: ru.id, Category: ru.category, Weight: ru.weight,
				Start: s, End: e, Via: via,
			})
		}
	}
}

// scanDecoded looks for encoded blobs in text, decodes them and scans the
// result recursively. Matches inside a blob are reported against the blob's
// range in the original input.
func (sc *scanner) scanDecoded(text string, resolve func(s, e int) (int, int), depth int, via []string) {
	for _, blob := range findEncoded(text, sc.limits.MinEncodedBytes) {
		bs, be := resolve(blob.span.Start, blob.span.End)
		cost := len(blob.text)
		if depth >= sc.limits.MaxDecodeDepth || cost > sc.budget {
			sc.out = append(sc.out, Match{
				RuleID: limitRuleID, Category: CatObfuscation, Weight: 0.5,
				Start: bs, End: be, Via: append(via[:len(via):len(via)], blob.kind),
			})
			continue
		}
		sc.budget -= cost
		childVia := append(via[:len(via):len(via)], blob.kind)
		fixed := func(int, int) (int, int) { return bs, be }
		inner := normalize(blob.text).text
		sc.match(inner, selNormalized, fixed, childVia)
		sc.scanDecoded(inner, fixed, depth+1, childVia)
	}
}

// collect returns all matches of rules that apply to the entry point, ordered
// by position. With normalizeInput set, the text goes through the
// normalization stage (invisible characters stripped, NFKC applied, encoded
// blobs decoded) before the non-invisible rules run.
func (e *engine) collect(text string, entry entryPoint, normalizeInput bool) []Match {
	sc := &scanner{
		rules: e.rules.Load(), entry: entry, limits: e.cfg.Limits,
		budget: e.cfg.Limits.MaxExpansion * len(text),
	}
	if !normalizeInput {
		sc.match(text, selAll, func(s, e int) (int, int) { return s, e }, nil)
	} else {
		sc.match(text, selInvisible, func(s, e int) (int, int) { return s, e }, nil)
		n := normalize(text)
		sc.match(n.text, selNormalized, n.resolve, nil)
		sc.scanDecoded(n.text, n.resolve, 0, nil)
	}
	out := sc.out
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// score combines matches with noisy-OR, counting each rule once at its
// highest weight so that repeats of one rule do not compound.
func score(matches []Match) float64 {
	best := map[string]float64{}
	for _, m := range matches {
		if m.Weight > best[m.RuleID] {
			best[m.RuleID] = m.Weight
		}
	}
	miss := 1.0
	for _, w := range best {
		miss *= 1 - w
	}
	return 1 - miss
}

func (e *engine) ScanPrompt(prompt string) (ScanResult, error) {
	if err := e.precheck(len(prompt)); err != nil {
		return ScanResult{IsSafe: e.cfg.FailOpen, RiskScore: failScore(e.cfg.FailOpen)}, err
	}
	matches := e.collect(prompt, entryPrompt, true)
	s := score(matches)
	return ScanResult{IsSafe: s < e.cfg.PromptThreshold, RiskScore: s, Matches: matches}, nil
}

func (e *engine) SanitizeContext(chunk string) (SanitizeResult, error) {
	if err := e.precheck(len(chunk)); err != nil {
		if e.cfg.FailOpen {
			return SanitizeResult{SanitizedText: chunk}, err
		}
		return SanitizeResult{Blocked: true, HasInjection: true, RiskScore: 1,
			Removed: []Span{{0, len(chunk)}}}, err
	}
	matches := e.collect(chunk, entryContext, true)
	s := score(matches)
	res := SanitizeResult{RiskScore: s, HasInjection: len(matches) > 0, Matches: matches}

	if e.cfg.SanitizeMode == ModeBlock && s >= e.cfg.ContextThreshold {
		res.Blocked = true
		res.Removed = []Span{{0, len(chunk)}}
		return res, nil
	}
	res.Removed = e.removalSpans(chunk, matches)
	res.SanitizedText = cut(chunk, res.Removed)
	return res, nil
}

// removalSpans widens each match according to its rule's action and merges
// overlapping spans.
func (e *engine) removalSpans(text string, matches []Match) []Span {
	actions := map[string]string{}
	for _, ru := range e.rules.Load().rules {
		actions[ru.id] = ru.action
	}
	spans := make([]Span, 0, len(matches))
	for _, m := range matches {
		sp := Span{m.Start, m.End}
		switch actions[m.RuleID] {
		case "strip_line":
			sp.Start = strings.LastIndexByte(text[:m.Start], '\n') + 1
			if i := strings.IndexByte(text[m.End:], '\n'); i >= 0 {
				sp.End = m.End + i
			} else {
				sp.End = len(text)
			}
		case "strip_block":
			sp.Start = 0
			if i := strings.LastIndex(text[:m.Start], "\n\n"); i >= 0 {
				sp.Start = i + 2
			}
			if i := strings.Index(text[m.End:], "\n\n"); i >= 0 {
				sp.End = m.End + i
			} else {
				sp.End = len(text)
			}
		}
		spans = append(spans, sp)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].Start < spans[j].Start })
	var merged []Span
	for _, sp := range spans {
		if n := len(merged); n > 0 && sp.Start <= merged[n-1].End {
			if sp.End > merged[n-1].End {
				merged[n-1].End = sp.End
			}
			continue
		}
		merged = append(merged, sp)
	}
	return merged
}

func cut(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	prev := 0
	for _, sp := range spans {
		b.WriteString(text[prev:sp.Start])
		prev = sp.End
	}
	b.WriteString(text[prev:])
	return b.String()
}

func (e *engine) RegisterPrompt(id, systemPrompt string) error {
	grams := ngrams(systemPrompt)
	if len(grams) == 0 {
		return ErrInvalidRules
	}
	e.mu.Lock()
	e.prompts[id] = grams
	e.mu.Unlock()
	return nil
}

func (e *engine) RegisterCanary(id, token string) error {
	if token == "" {
		return ErrInvalidRules
	}
	e.mu.Lock()
	e.canaries[id] = token
	e.mu.Unlock()
	return nil
}

func (e *engine) ScanOutput(response string) (OutputResult, error) {
	if err := e.precheck(len(response)); err != nil {
		return OutputResult{IsLeaked: !e.cfg.FailOpen, LeakConfidence: failScore(e.cfg.FailOpen)}, err
	}
	res := OutputResult{Matches: e.collect(response, entryOutput, false)}
	conf := score(res.Matches)

	e.mu.RLock()
	for id, tok := range e.canaries {
		if strings.Contains(response, tok) {
			res.MatchedCanaries = append(res.MatchedCanaries, id)
			conf = 1
		}
	}
	if len(e.prompts) > 0 {
		respGrams := ngrams(response)
		for id, grams := range e.prompts {
			hit := 0
			for g := range grams {
				if _, ok := respGrams[g]; ok {
					hit++
				}
			}
			overlap := float64(hit) / float64(len(grams))
			if overlap >= e.cfg.LeakThreshold {
				res.MatchedPrompts = append(res.MatchedPrompts, id)
			}
			if overlap > conf {
				conf = overlap
			}
		}
	}
	e.mu.RUnlock()

	sort.Strings(res.MatchedCanaries)
	sort.Strings(res.MatchedPrompts)
	res.LeakConfidence = conf
	res.IsLeaked = conf >= e.cfg.LeakThreshold
	return res, nil
}

// ngrams returns the set of lowercase word n-grams of s. Texts shorter than
// fingerprintN words yield no n-grams.
func ngrams(s string) map[string]struct{} {
	words := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	set := map[string]struct{}{}
	for i := 0; i+fingerprintN <= len(words); i++ {
		set[strings.Join(words[i:i+fingerprintN], " ")] = struct{}{}
	}
	return set
}

func failScore(failOpen bool) float64 {
	if failOpen {
		return 0
	}
	return 1
}
