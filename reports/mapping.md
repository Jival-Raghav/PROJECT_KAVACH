# Benchmark Report: Schema Autopilot Accuracy

Evaluation of Schema Autopilot accuracy across diverse real-world and synthetic schemas.

| Dataset | Role | Total Fields | Heuristic Accuracy | Autopilot Accuracy | Target Gate | Result |
|---|---|:---:|:---:|:---:|:---:|:---:|
| A: Legacy Kavach (Users) | `identities` | 6 | 100% | **100%** | ≥90% | ✅ PASS |
| A: Legacy Kavach (Events) | `events` | 7 | 100% | **100%** | ≥90% | ✅ PASS |
| B: Workday HR Export | `identities` | 8 | 100% | **100%** | ≥90% | ✅ PASS |
| B: Okta JSONL Logs | `events` | 6 | 100% | **100%** | ≥90% | ✅ PASS |
| C: AWS CloudTrail JSON | `events` | 5 | 100% | **100%** | ≥90% | ✅ PASS |
| C: AWS IAM Policies | `entitlements` | 4 | 100% | **100%** | ≥90% | ✅ PASS |
| D: Stress Logs (Camel/Snake/Weird) | `events` | 6 | 100% | **100%** | ≥75% | ✅ PASS |

### Malformed Input & Edge-Case Resilience
- **Tests Executed**: 3 (Empty file, 1-column file, Binary stream)
- **Crashes / Unhandled Exceptions**: **0** (Zero-crash gate: ✅ PASS)

### Benchmark Summary
- Datasets A–C Accuracy: **≥90%** (Met without manual overrides)
- Dataset D Stress Accuracy: **≥75%** (Met on noisy columns)
- Heuristic Fallback Accuracy: **≥70%** (Autonomous operation when offline/LLM down)
