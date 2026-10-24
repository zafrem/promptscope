package promptscope

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

//go:embed rules/baseline.json
var baselineJSON []byte

//go:embed rules/english-only.json
var englishOnlyJSON []byte

const maxRulesBytes = 16 << 20

type entryPoint uint8

const (
	entryPrompt entryPoint = 1 << iota
	entryContext
	entryOutput
)

var idPattern = regexp.MustCompile(`^[A-Z]{2,6}-[0-9]{3,4}$`)

type ruleFile struct {
	Version string     `json:"version"`
	Pack    string     `json:"pack,omitempty"`
	Rules   []ruleSpec `json:"rules"`
}

type ruleSpec struct {
	ID          string   `json:"id"`
	Category    Category `json:"category"`
	AppliesTo   []string `json:"applies_to"`
	Kind        string   `json:"kind"`
	Patterns    []string `json:"patterns"`
	Weight      float64  `json:"weight"`
	Action      string   `json:"action,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty"`
	Description string   `json:"description,omitempty"`
}

type runeRange struct{ lo, hi rune }

type rule struct {
	id       string
	category Category
	entries  entryPoint
	weight   float64
	action   string
	enabled  bool

	re     *regexp.Regexp // literal and regex kinds
	ranges []runeRange    // charclass kind
}

// RuleSet is an immutable, compiled collection of rules.
type RuleSet struct {
	version string
	pack    string
	rules   []*rule
}

// Version returns the rule set version string.
func (rs *RuleSet) Version() string { return rs.version }

// Pack returns the pack name, if any.
func (rs *RuleSet) Pack() string { return rs.pack }

// Len returns the number of rules, including disabled ones.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// BaselineRules returns the public rule pack embedded in the module.
func BaselineRules() *RuleSet {
	rs, err := LoadRules(bytes.NewReader(baselineJSON))
	if err != nil {
		panic("promptscope: embedded baseline rules are invalid: " + err.Error())
	}
	return rs
}

// EnglishOnlyRules returns an optional pack for deployments whose input should be English. It flags Hangul,
// Hiragana/Katakana and Han characters in prompts (rules SCR-001 to SCR-005, category unexpected_script).
// It is not part of the baseline: layer it on with MergeRules(BaselineRules(), EnglishOnlyRules()).
func EnglishOnlyRules() *RuleSet {
	rs, err := LoadRules(bytes.NewReader(englishOnlyJSON))
	if err != nil {
		panic("promptscope: embedded english-only rules are invalid: " + err.Error())
	}
	return rs
}

// BuiltinPackNames lists the packs BuiltinPack accepts.
var BuiltinPackNames = []string{"baseline", "english-only"}

// BuiltinPack returns an embedded rule pack by name.
func BuiltinPack(name string) (*RuleSet, error) {
	switch name {
	case "baseline":
		return BaselineRules(), nil
	case "english-only":
		return EnglishOnlyRules(), nil
	}
	return nil, fmt.Errorf("%w: unknown built-in pack %q (have %s)", ErrInvalidRules, name, strings.Join(BuiltinPackNames, ", "))
}

// LoadRulesFile parses and validates a JSON rule file.
func LoadRulesFile(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadRules(f)
}

// LoadRules parses and validates a JSON rule set. Any problem is reported as an
// error wrapping ErrInvalidRules.
func LoadRules(r io.Reader) (*RuleSet, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxRulesBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRulesBytes {
		return nil, fmt.Errorf("%w: file larger than %d bytes", ErrInvalidRules, maxRulesBytes)
	}
	var rf ruleFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRules, err)
	}
	if rf.Version == "" {
		return nil, fmt.Errorf("%w: missing version", ErrInvalidRules)
	}
	if len(rf.Rules) == 0 {
		return nil, fmt.Errorf("%w: no rules", ErrInvalidRules)
	}
	rs := &RuleSet{version: rf.Version, pack: rf.Pack}
	seen := make(map[string]bool, len(rf.Rules))
	for _, spec := range rf.Rules {
		if seen[spec.ID] {
			return nil, fmt.Errorf("%w: duplicate rule id %q", ErrInvalidRules, spec.ID)
		}
		seen[spec.ID] = true
		ru, err := compileRule(spec)
		if err != nil {
			return nil, fmt.Errorf("%w: rule %q: %v", ErrInvalidRules, spec.ID, err)
		}
		rs.rules = append(rs.rules, ru)
	}
	return rs, nil
}

// MergeRules combines rule sets. A rule in a later set replaces an earlier rule
// with the same ID (including replacing it with a disabled one).
func MergeRules(sets ...*RuleSet) (*RuleSet, error) {
	if len(sets) == 0 {
		return nil, fmt.Errorf("%w: nothing to merge", ErrInvalidRules)
	}
	out := &RuleSet{}
	index := map[string]int{}
	var versions, packs []string
	for _, rs := range sets {
		if rs == nil {
			return nil, fmt.Errorf("%w: nil rule set", ErrInvalidRules)
		}
		versions = append(versions, rs.version)
		if rs.pack != "" {
			packs = append(packs, rs.pack)
		}
		for _, ru := range rs.rules {
			if i, ok := index[ru.id]; ok {
				out.rules[i] = ru
				continue
			}
			index[ru.id] = len(out.rules)
			out.rules = append(out.rules, ru)
		}
	}
	out.version = strings.Join(versions, ",")
	out.pack = strings.Join(packs, "+")
	return out, nil
}

func compileRule(s ruleSpec) (*rule, error) {
	if !idPattern.MatchString(s.ID) {
		return nil, fmt.Errorf("id must match %s", idPattern)
	}
	if !s.Category.valid() {
		return nil, fmt.Errorf("unknown category %q", s.Category)
	}
	if s.Weight <= 0 || s.Weight > 1 {
		return nil, fmt.Errorf("weight %v outside (0,1]", s.Weight)
	}
	if len(s.Patterns) == 0 {
		return nil, fmt.Errorf("no patterns")
	}
	ru := &rule{id: s.ID, category: s.Category, weight: s.Weight, enabled: true, action: "strip_match"}
	if s.Enabled != nil {
		ru.enabled = *s.Enabled
	}
	switch s.Action {
	case "":
	case "strip_match", "strip_line", "strip_block":
		ru.action = s.Action
	default:
		return nil, fmt.Errorf("unknown action %q", s.Action)
	}
	if len(s.AppliesTo) == 0 {
		return nil, fmt.Errorf("applies_to is empty")
	}
	for _, a := range s.AppliesTo {
		switch a {
		case "prompt":
			ru.entries |= entryPrompt
		case "context":
			ru.entries |= entryContext
		case "output":
			ru.entries |= entryOutput
		default:
			return nil, fmt.Errorf("unknown applies_to %q", a)
		}
	}
	switch s.Kind {
	case "literal":
		quoted := make([]string, len(s.Patterns))
		for i, p := range s.Patterns {
			if p == "" {
				return nil, fmt.Errorf("empty pattern")
			}
			quoted[i] = regexp.QuoteMeta(p)
		}
		ru.re = regexp.MustCompile("(?i)" + strings.Join(quoted, "|"))
	case "regex":
		parts := make([]string, len(s.Patterns))
		for i, p := range s.Patterns {
			if _, err := regexp.Compile(p); err != nil {
				return nil, fmt.Errorf("pattern %d: %v", i, err)
			}
			parts[i] = "(?:" + p + ")"
		}
		re, err := regexp.Compile(strings.Join(parts, "|"))
		if err != nil {
			return nil, err
		}
		ru.re = re
	case "charclass":
		for _, p := range s.Patterns {
			rr, err := parseRange(p)
			if err != nil {
				return nil, err
			}
			ru.ranges = append(ru.ranges, rr)
		}
	default:
		return nil, fmt.Errorf("unknown kind %q", s.Kind)
	}
	return ru, nil
}

func parseRange(p string) (runeRange, error) {
	lo, hi, found := strings.Cut(p, "-")
	if !found {
		hi = lo
	}
	parse := func(s string) (rune, error) {
		if !strings.HasPrefix(s, "U+") {
			return 0, fmt.Errorf("bad code point %q", s)
		}
		n, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil || n > 0x10FFFF {
			return 0, fmt.Errorf("bad code point %q", s)
		}
		return rune(n), nil
	}
	l, err := parse(lo)
	if err != nil {
		return runeRange{}, err
	}
	h, err := parse(hi)
	if err != nil {
		return runeRange{}, err
	}
	if h < l {
		return runeRange{}, fmt.Errorf("range %q is reversed", p)
	}
	return runeRange{l, h}, nil
}

// find returns the non-empty spans of text matched by the rule.
func (ru *rule) find(text string) []Span {
	var spans []Span
	if ru.re != nil {
		for _, loc := range ru.re.FindAllStringIndex(text, -1) {
			if loc[1] > loc[0] {
				spans = append(spans, Span{loc[0], loc[1]})
			}
		}
		return spans
	}
	runStart := -1
	for i, r := range text {
		in := false
		for _, rr := range ru.ranges {
			if r >= rr.lo && r <= rr.hi {
				in = true
				break
			}
		}
		switch {
		case in && runStart < 0:
			runStart = i
		case !in && runStart >= 0:
			spans = append(spans, Span{runStart, i})
			runStart = -1
		}
	}
	if runStart >= 0 {
		spans = append(spans, Span{runStart, len(text)})
	}
	return spans
}
