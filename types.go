package promptscope

// Category classifies what a rule detects.
type Category string

const (
	CatInstructionOverride Category = "instruction_override" // FR-1.1
	CatDelimiterEscape     Category = "delimiter_escape"     // FR-1.2
	CatObfuscation         Category = "obfuscation"          // FR-1.3
	CatInvisibleChar       Category = "invisible_char"       // FR-2.1
	CatBoundaryViolation   Category = "boundary_violation"   // FR-2.2
	CatTemplateBleed       Category = "template_bleed"       // FR-3.3
	// CatHomoglyph marks a word that mixes Latin letters with look-alike letters from another script. Its rules
	// run on the text before look-alikes are folded to Latin, so they can still see them.
	CatHomoglyph Category = "homoglyph"
	// CatUnexpectedScript marks text in a script the deployment does not expect (for example Hangul, kana or
	// Han in an English-only application). It is a policy signal, not an attack signature.
	CatUnexpectedScript Category = "unexpected_script"
)

func (c Category) valid() bool {
	switch c {
	case CatInstructionOverride, CatDelimiterEscape, CatObfuscation,
		CatInvisibleChar, CatBoundaryViolation, CatTemplateBleed, CatUnexpectedScript, CatHomoglyph:
		return true
	}
	return false
}

// Span is a half-open byte range [Start, End) into the original input.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Match is one rule hit. Start and End are byte offsets into the original input.
type Match struct {
	RuleID   string   `json:"rule_id"`
	Category Category `json:"category"`
	Weight   float64  `json:"weight"`
	Start    int      `json:"start"`
	End      int      `json:"end"`
	// Via records transforms applied before the match was found (e.g. "base64").
	// Empty for a direct match.
	Via []string `json:"via,omitempty"`
}

// ScanResult is the verdict for ScanPrompt.
type ScanResult struct {
	IsSafe    bool    `json:"is_safe"`
	RiskScore float64 `json:"risk_score"` // 0.0 to 1.0
	Matches   []Match `json:"matches,omitempty"`
}

// SanitizeResult is the verdict for SanitizeContext.
type SanitizeResult struct {
	SanitizedText string  `json:"sanitized_text"` // empty when Blocked
	HasInjection  bool    `json:"has_injection"`
	RiskScore     float64 `json:"risk_score"`
	Blocked       bool    `json:"blocked"`
	Removed       []Span  `json:"removed,omitempty"`
	Matches       []Match `json:"matches,omitempty"`
}

// OutputResult is the verdict for ScanOutput.
type OutputResult struct {
	IsLeaked        bool     `json:"is_leaked"`
	LeakConfidence  float64  `json:"leak_confidence"` // 0.0 to 1.0
	MatchedPrompts  []string `json:"matched_prompts,omitempty"`
	MatchedCanaries []string `json:"matched_canaries,omitempty"` // canary IDs, never token values
	Matches         []Match  `json:"matches,omitempty"`
}
