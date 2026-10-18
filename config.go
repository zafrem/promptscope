package promptscope

import "errors"

var (
	ErrInputTooLarge = errors.New("promptscope: input exceeds Limits.MaxInputBytes")
	ErrInvalidRules  = errors.New("promptscope: invalid rule set")
	ErrNoRules       = errors.New("promptscope: no rules loaded")
)

// SanitizeMode selects how SanitizeContext treats flagged chunks.
type SanitizeMode int

const (
	// ModeFilter strips only the malicious spans.
	ModeFilter SanitizeMode = iota
	// ModeBlock drops the whole chunk when the risk reaches ContextThreshold.
	ModeBlock
)

// Limits bound the work done per call. Zero values select defaults.
type Limits struct {
	MaxInputBytes int // default 64 KiB
	// The fields below are reserved for the decoding stage (FR-1.3) and are
	// not enforced yet.
	MaxDecodeDepth  int // default 3
	MaxExpansion    int // default 4
	MinEncodedBytes int // default 24
}

// Config is read once by New and never mutated afterwards.
type Config struct {
	PromptThreshold  float64 // IsSafe = RiskScore < PromptThreshold. Default 0.5
	ContextThreshold float64 // ModeBlock drops the chunk at or above this. Default 0.7
	LeakThreshold    float64 // IsLeaked = LeakConfidence >= LeakThreshold. Default 0.6

	SanitizeMode SanitizeMode
	Limits       Limits

	// FailOpen makes a scan that returns an error report the safe verdict.
	// By default the verdict returned alongside an error is the unsafe one.
	FailOpen bool
}

func (c Config) withDefaults() Config {
	if c.PromptThreshold == 0 {
		c.PromptThreshold = 0.5
	}
	if c.ContextThreshold == 0 {
		c.ContextThreshold = 0.7
	}
	if c.LeakThreshold == 0 {
		c.LeakThreshold = 0.6
	}
	if c.Limits.MaxInputBytes == 0 {
		c.Limits.MaxInputBytes = 64 << 10
	}
	if c.Limits.MaxDecodeDepth == 0 {
		c.Limits.MaxDecodeDepth = 3
	}
	if c.Limits.MaxExpansion == 0 {
		c.Limits.MaxExpansion = 4
	}
	if c.Limits.MinEncodedBytes == 0 {
		c.Limits.MinEncodedBytes = 24
	}
	return c
}
