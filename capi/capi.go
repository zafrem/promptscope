// Command capi builds the C ABI of promptscope:
//
//	go build -buildmode=c-shared -o libpromptscope.so ./capi
//
// Every function that returns a char* returns a JSON envelope the caller must
// release with ps_free:
//
//	{"ok":true,"result":{...}}
//	{"ok":false,"error":"<code>","message":"...","result":{...}}
//
// The result of a failed scan is the verdict the engine reports alongside the
// error (unsafe by default; safe with fail_open). Error codes: input_too_large,
// invalid_rules, no_rules, invalid_handle, invalid_argument, internal.
//
// Text is passed as pointer and byte length, so it may contain NUL bytes.
// Engine handles are non-zero integers; 0 is never a valid handle.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/zafrem/promptscope"
)

const abiVersion = 1

var (
	mu      sync.RWMutex
	engines = map[uint64]promptscope.Engine{}
	next    uint64
)

type configJSON struct {
	PromptThreshold  float64 `json:"prompt_threshold"`
	ContextThreshold float64 `json:"context_threshold"`
	LeakThreshold    float64 `json:"leak_threshold"`
	SanitizeMode     string  `json:"sanitize_mode"` // "filter" (default) or "block"
	FailOpen         bool    `json:"fail_open"`
	Limits           struct {
		MaxInputBytes   int `json:"max_input_bytes"`
		MaxDecodeDepth  int `json:"max_decode_depth"`
		MaxExpansion    int `json:"max_expansion"`
		MinEncodedBytes int `json:"min_encoded_bytes"`
	} `json:"limits"`
}

type envelope struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Result  any    `json:"result,omitempty"`
}

func reply(env envelope) *C.char {
	b, err := json.Marshal(env)
	if err != nil {
		b = []byte(`{"ok":false,"error":"internal","message":"encoding failed"}`)
	}
	return C.CString(string(b))
}

func ok(result any) *C.char { return reply(envelope{OK: true, Result: result}) }

func fail(code string, err error, result any) *C.char {
	msg := code
	if err != nil {
		msg = err.Error()
	}
	return reply(envelope{Error: code, Message: msg, Result: result})
}

func errCode(err error) string {
	switch {
	case errors.Is(err, promptscope.ErrInputTooLarge):
		return "input_too_large"
	case errors.Is(err, promptscope.ErrInvalidRules):
		return "invalid_rules"
	case errors.Is(err, promptscope.ErrNoRules):
		return "no_rules"
	}
	return "internal"
}

// guard turns a panic into an internal-error envelope instead of crashing the host process.
func guard(out **C.char) {
	if r := recover(); r != nil {
		*out = fail("internal", fmt.Errorf("panic: %v", r), nil)
	}
}

func goString(p *C.char, n C.size_t) string {
	if p == nil || n == 0 {
		return ""
	}
	return C.GoStringN(p, C.int(n))
}

func lookup(h C.uint64_t) (promptscope.Engine, bool) { return get(uint64(h)) }

func get(h uint64) (promptscope.Engine, bool) {
	mu.RLock()
	defer mu.RUnlock()
	e, ok := engines[h]
	return e, ok
}

func drop(h uint64) {
	mu.Lock()
	delete(engines, h)
	mu.Unlock()
}

func buildConfig(raw string) (promptscope.Config, error) {
	var c configJSON
	if raw != "" {
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return promptscope.Config{}, err
		}
	}
	cfg := promptscope.Config{
		PromptThreshold:  c.PromptThreshold,
		ContextThreshold: c.ContextThreshold,
		LeakThreshold:    c.LeakThreshold,
		FailOpen:         c.FailOpen,
		Limits: promptscope.Limits{
			MaxInputBytes:   c.Limits.MaxInputBytes,
			MaxDecodeDepth:  c.Limits.MaxDecodeDepth,
			MaxExpansion:    c.Limits.MaxExpansion,
			MinEncodedBytes: c.Limits.MinEncodedBytes,
		},
	}
	switch c.SanitizeMode {
	case "", "filter":
		cfg.SanitizeMode = promptscope.ModeFilter
	case "block":
		cfg.SanitizeMode = promptscope.ModeBlock
	default:
		return cfg, fmt.Errorf("unknown sanitize_mode %q", c.SanitizeMode)
	}
	return cfg, nil
}

//export ps_abi_version
func ps_abi_version() C.int { return abiVersion }

// ps_engine_new creates an engine with the embedded baseline rules.
// config is optional JSON (may be NULL). The result is {"handle": N}.
//
//export ps_engine_new
func ps_engine_new(config *C.char, configLen C.size_t) (out *C.char) {
	defer guard(&out)
	cfg, err := buildConfig(goString(config, configLen))
	if err != nil {
		return fail("invalid_argument", err, nil)
	}
	e, err := promptscope.New(cfg, promptscope.BaselineRules())
	if err != nil {
		return fail(errCode(err), err, nil)
	}
	mu.Lock()
	next++
	h := next
	engines[h] = e
	mu.Unlock()
	return ok(map[string]uint64{"handle": h})
}

// ps_engine_free releases an engine. Freeing an unknown handle is a no-op.
//
//export ps_engine_free
func ps_engine_free(h C.uint64_t) { drop(uint64(h)) }

// ps_load_rules parses a JSON rule set and installs it. With merge non-zero it
// is layered over the baseline pack; otherwise it replaces all rules.
//
//export ps_load_rules
func ps_load_rules(h C.uint64_t, rules *C.char, rulesLen C.size_t, merge C.int) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	rs, err := promptscope.LoadRules(bytes.NewReader([]byte(goString(rules, rulesLen))))
	if err != nil {
		return fail(errCode(err), err, nil)
	}
	if merge != 0 {
		if rs, err = promptscope.MergeRules(promptscope.BaselineRules(), rs); err != nil {
			return fail(errCode(err), err, nil)
		}
	}
	if err := e.Reload(rs); err != nil {
		return fail(errCode(err), err, nil)
	}
	return ok(map[string]string{"version": e.RulesVersion()})
}

//export ps_rules_version
func ps_rules_version(h C.uint64_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	return ok(map[string]string{"version": e.RulesVersion()})
}

//export ps_register_prompt
func ps_register_prompt(h C.uint64_t, id *C.char, idLen C.size_t, prompt *C.char, promptLen C.size_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	if err := e.RegisterPrompt(goString(id, idLen), goString(prompt, promptLen)); err != nil {
		return fail("invalid_argument", errors.New("system prompt is too short to fingerprint"), nil)
	}
	return ok(nil)
}

//export ps_register_canary
func ps_register_canary(h C.uint64_t, id *C.char, idLen C.size_t, token *C.char, tokenLen C.size_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	if err := e.RegisterCanary(goString(id, idLen), goString(token, tokenLen)); err != nil {
		return fail("invalid_argument", errors.New("canary token is empty"), nil)
	}
	return ok(nil)
}

//export ps_scan_prompt
func ps_scan_prompt(h C.uint64_t, text *C.char, n C.size_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	res, err := e.ScanPrompt(goString(text, n))
	if err != nil {
		return fail(errCode(err), err, res)
	}
	return ok(res)
}

//export ps_sanitize_context
func ps_sanitize_context(h C.uint64_t, text *C.char, n C.size_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	res, err := e.SanitizeContext(goString(text, n))
	if err != nil {
		return fail(errCode(err), err, res)
	}
	return ok(res)
}

//export ps_scan_output
func ps_scan_output(h C.uint64_t, text *C.char, n C.size_t) (out *C.char) {
	defer guard(&out)
	e, found := lookup(h)
	if !found {
		return fail("invalid_handle", nil, nil)
	}
	res, err := e.ScanOutput(goString(text, n))
	if err != nil {
		return fail(errCode(err), err, res)
	}
	return ok(res)
}

// ps_free releases a string returned by any ps_* function.
//
//export ps_free
func ps_free(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func main() {}
