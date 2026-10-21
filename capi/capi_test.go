package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/zafrem/promptscope"
)

// The exported ps_* functions take C pointers and are exercised end to end by the Python tests; these cover
// the pure-Go helpers behind them.

func TestBuildConfigDefaults(t *testing.T) {
	for _, raw := range []string{"", "{}"} {
		cfg, err := buildConfig(raw)
		if err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
		if cfg.SanitizeMode != promptscope.ModeFilter || cfg.FailOpen || cfg.PromptThreshold != 0 {
			t.Errorf("%q: %+v", raw, cfg)
		}
	}
}

func TestBuildConfigMapsEveryField(t *testing.T) {
	cfg, err := buildConfig(`{
		"prompt_threshold": 0.4, "context_threshold": 0.8, "leak_threshold": 0.9,
		"sanitize_mode": "block", "fail_open": true,
		"limits": {"max_input_bytes": 10, "max_decode_depth": 2, "max_expansion": 5, "min_encoded_bytes": 16}}`)
	if err != nil {
		t.Fatal(err)
	}
	want := promptscope.Config{
		PromptThreshold: 0.4, ContextThreshold: 0.8, LeakThreshold: 0.9,
		SanitizeMode: promptscope.ModeBlock, FailOpen: true,
		Limits: promptscope.Limits{MaxInputBytes: 10, MaxDecodeDepth: 2, MaxExpansion: 5, MinEncodedBytes: 16},
	}
	if cfg != want {
		t.Errorf("got %+v\nwant %+v", cfg, want)
	}
}

func TestBuildConfigRejects(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":      `{`,
		"unknown field": `{"prompt_treshold": 0.4}`,
		"unknown mode":  `{"sanitize_mode": "explode"}`,
		"wrong type":    `{"fail_open": "yes"}`,
	} {
		if _, err := buildConfig(raw); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}

func TestErrCode(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{promptscope.ErrInputTooLarge, "input_too_large"},
		{promptscope.ErrInvalidRules, "invalid_rules"},
		{promptscope.ErrNoRules, "no_rules"},
		{fmt.Errorf("wrapped: %w", promptscope.ErrInvalidRules), "invalid_rules"},
		{errors.New("something else"), "internal"},
	}
	for _, c := range cases {
		if got := errCode(c.err); got != c.want {
			t.Errorf("%v -> %q, want %q", c.err, got, c.want)
		}
	}
}

func TestEngineRegistry(t *testing.T) {
	e, err := promptscope.New(promptscope.Config{}, promptscope.BaselineRules())
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	next++
	h := next
	engines[h] = e
	mu.Unlock()

	if got, ok := get(h); !ok || got != e {
		t.Error("registered engine not found")
	}
	drop(h)
	if _, ok := get(h); ok {
		t.Error("freed engine still found")
	}
	drop(h) // freeing twice is a no-op
	if _, ok := get(0); ok {
		t.Error("handle 0 must never be valid")
	}
}
