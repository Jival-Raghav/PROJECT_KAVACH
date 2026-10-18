# LLM Red-Team & Prompt Injection Defense Benchmark Report

**Evaluation Scope:** Adversarial Prompt Injection, Role Spoofing & Metric Forgery Defenses**Defense Gateway:** Kavach v2 Multi-Layer Security Gateway (NFKC Sanitization, Threat Redaction, Cryptographic Nonce Enclosure)

---

## 1. Executive Headline Pitch

> **32/32 payloads neutralised before prompt construction** (none of the checked instruction markers survive into the prompt), of which **12/32 (37.5%) were actively detected and flagged** by the injection detector; the rest are rendered inert by sanitisation and nonce-sealed `<data>` enclosure. **0.0% false-positive redaction** on benign corporate text.

**Method and limits (read before quoting):** this is a static prompt-construction test. It does not call a live model. "Baseline" is the assumption that an un-gated pipeline passes the raw string through (counted as attack success by definition). "Defended success" means one of the strings `ignore previous`, `<system>`, `doubt_score to 1` survived un-redacted in the prompt data. The benign set is 20 distinct job titles repeated to 100 samples. End-to-end behaviour against a live LLM is covered separately by the `USR9206` demo case (injected log field did not change the verdict; n=1).

---

## 2. Red-Team Benchmark Comparison

| Metric | Baseline (Gateway OFF, assumed) | Defended (Gateway ON) | Gate | Result |
| :--- | :---: | :---: | :---: | :---: |
| **Attack Success Rate (static check)** | `100.0%` | **`0.0%`** | $\le 5.0\%$ | **PASS** |
| **Payloads actively detected and flagged** | n/a | `37.5%` (12/32) | informational (no gate) | n/a |
| **Benign Data FP Redaction** | `0.0%` | **`0.0%`** | $\le 2.0\%$ | **PASS** |
| **Total Adversarial Payloads Tested** | `32` | `32` | $\ge 30$ | **PASS** |

---

## 3. Defense Breakdown by Threat Category

| Threat Category | Payloads Tested | Baseline ASR | Defended ASR | Handling |
| :--- | :---: | :---: | :---: | :--- |
| **Direct Instruction Overrides** | 5 | 100.0% | **0.0%** | All directives redacted with `[REDACTED:suspected-injection]` |
| **Role Tag Spoofing (`[SYSTEM]`, `<system>`)** | 4 | 100.0% | **0.0%** | Role delimiters neutralized; inert inside `<data nonce=X>` |
| **JSON Metric Forgery (`doubt_score: 1.0`)** | 4 | 100.0% | **0.0%** | Injected JSON stripped; doubt score calculated in Python |
| **Tool Call Hijacking (`was_on_call`)** | 3 | 100.0% | **0.0%** | Tool names allowlisted; argument schemas Pydantic-enforced |
| **Markdown / URL Data Exfiltration** | 4 | 100.0% | **0.0%** | Markdown images and raw external URLs stripped |
| **Zero-Width & BiDi Obfuscation** | 4 | 100.0% | **0.0%** | Zero-width joiners stripped via Unicode NFKC cleaner |
| **Base64 Encoded Payloads** | 3 | 100.0% | **0.0%** | Base64 strings decoded & inspected pre-flight |
| **Multilingual & Split Assembly** | 5 | 100.0% | **0.0%** | Multi-field cross-token inspection and inert encapsulation |

---

## 4. Key Invariants

1. **Deterministic Floor**: Hard rules (SoD violations, leavers active, orphan privileged) can never be dismissed by model output.
2. **Untrusted Data Isolation**: Untrusted context is always isolated inside `<data nonce=RANDOM>` blocks. The system prompt instructs the model that tags inside `<data>` are inert text, never system instructions.
3. **Verdict Invariance Check**: Every adjudication is cross-checked against baseline severity to detect and prevent any subtle suppression manipulation.
