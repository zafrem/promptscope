// Package promptscope is a low-latency, dependency-free inspection engine for
// prompt injection, indirect injection, and system prompt leakage.
//
// Build an Engine from a Config and a RuleSet, then call ScanPrompt,
// SanitizeContext, or ScanOutput. All scanning methods are safe for
// concurrent use; rules can be swapped at runtime with Reload.
//
// See docs/SRS.md and docs/SRS-section4-proposal.md for the specification.
package promptscope
