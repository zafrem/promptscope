# Software Requirements Specification (SRS)

**Project Name:** promptscope-forge

## 1. Introduction

### 1.1 Purpose

This document specifies the software requirements for promptscope-forge, an ultra-low-latency, zero-dependency security inspection engine implemented in Go. The engine inspects user inputs, ingested RAG contexts, and LLM responses to detect and neutralize prompt injections, jailbreak attempts, and system prompt exfiltration.

### 1.2 System Scope

promptscope-forge operates as a lightweight inline scanner. It deliberately excludes heavyweight LLM-as-a-judge patterns, relying instead on deterministic string matching, regex state machines, multi-pattern search algorithms (Aho-Corasick), and heuristic text analysis.

## 2. Functional Requirements

### 2.1 Inbound Inspection: Direct Prompt Injection (ScanPrompt)

- **FR-1.1 (Instruction Override Detection):** Identify patterns attempting to override foundational directives (e.g., "ignore previous instructions", "disregard all rules", "system prompt override").
- **FR-1.2 (Chat Template & Delimiter Escapes):** Detect adversarial delimiters and role-spoofing markers (e.g., `<|im_start|>`, `### System:`, `[INST]`, `<<SYS>>`).
- **FR-1.3 (Obfuscation & Encoding Normalization):** Decode and normalize incoming text before evaluation (Base64 decoding, hex unpacking, zero-width space elimination, and Unicode normalization Form NFKC).
- **FR-1.4 (Scoring & Classification):** Return an aggregated risk score between 0.0 (benign) and 1.0 (high confidence attack) along with matching rule IDs and snippet ranges.

### 2.2 Data Ingestion Inspection: Indirect Injection (SanitizeContext)

- **FR-2.1 (Invisible Character Stripping):** Detect and strip zero-width spaces (ZWSP, ZWNJ), bidirectional override controls, and embedded HTML/Markdown comment tags (`<!-- ... -->`).
- **FR-2.2 (Instructional Boundary Violation):** Flag declarative command structures embedded within third-party factual texts (e.g., secondary instructions commanding the model to execute side effects).
- **FR-2.3 (Sanitization Actions):** Provide two operating modes:
  - **Filter:** Strip only malicious tokens or instruction blocks.
  - **Block:** Drop the entire retrieval chunk if risk exceeds threshold.

### 2.3 Outbound Inspection: Leakage & Egress Control (ScanOutput)

- **FR-3.1 (System Prompt Fingerprinting):** Compute n-gram similarity and token-level overlap against registered system prompts to prevent inadvertent disclosure.
- **FR-3.2 (Canary / Honey-Token Verification):** Perform exact string matching against pre-configured decoy tokens inserted into the system instructions.
- **FR-3.3 (Template Variable Bleed):** Flag template placeholder leaks such as `{{context}}`, `{system_instruction}`, or internal infrastructure environment variables.

## 3. Non-Functional Requirements

- **NFR-1 (Latency):** Median execution time under 1.0 millisecond for a 1,000-character payload on standard x86_64 / arm64 hardware.
- **NFR-2 (Zero External Runtime Dependencies):** Built strictly with Go standard library primitives and vendored pure-Go data structures (no external daemon, model checkpoint, or GPU required).
- **NFR-3 (Concurrency & Thread-Safety):** Stateless, concurrent-safe inspection routines capable of processing high-throughput HTTP/gRPC pipelines.
- **NFR-4 (Rules Hot-Reloading):** Support runtime rule definition via structured formats (YAML/JSON) with thread-safe hot-reload support (`sync.RWMutex` / atomic pointers).

## 4. Go Interface & Data Model Draft

```go
package promptscope

// ScanResult represents the inspection verdict for input prompts.
type ScanResult struct {
    IsSafe          bool     `json:"is_safe"`
    RiskScore       float64  `json:"risk_score"` // 0.0 to 1.0
    MatchedRuleIDs  []string `json:"matched_rule_ids"`
    DetectedTokens  []string `json:"detected_tokens,omitempty"`
}

// SanitizeResult represents cleaned RAG context and detection metadata.
type SanitizeResult struct {
    SanitizedText string   `json:"sanitized_text"`
    HasInjection  bool     `json:"has_injection"`
    DroppedBlocks []string `json:"dropped_blocks,omitempty"`
}

// OutputResult represents leakage validation on model responses.
type OutputResult struct {
    IsLeaked        bool     `json:"is_leaked"`
    LeakConfidence  float64  `json:"leak_confidence"`
    MatchedCanaries []string `json:"matched_canaries,omitempty"`
}

// Engine defines the core scanner contract.
type Engine interface {
    ScanPrompt(prompt string) (ScanResult, error)
    SanitizeContext(context string) (SanitizeResult, error)
    ScanOutput(response string, systemPromptFingerprint string, canaries []string) (OutputResult, error)
}
```
