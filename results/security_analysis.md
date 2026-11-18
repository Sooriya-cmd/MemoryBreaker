# MemoryBreaker Security Analysis

Generated: 2026-11-18T10:54:58.974420+00:00

## 1. Executive Summary

Persistent multi-turn split-write memory poisoning under the tested local model, memory store and guard policy.

- Baseline attack success: **100.0%**
- Guarded attack success: **100.0%**
- Guard interventions: **0**
- Guard block rate: **0.0%**
- Attack success reduction: **0.0 percentage points**

## 2. Baseline Analysis

- Total trials: 15
- Eligible trials: 14
- Excluded trials: 1
- Successful attacks: 14
- Attack success rate: 100.0%

## 3. Guarded Analysis

- Total trials: 15
- Eligible trials: 13
- Excluded trials: 2
- Successful attacks: 13
- Attack success rate: 100.0%
- Guard interventions: 0
- Blocked trials: 0
- Independent retrieval confirmed: 13
- Canary reproductions: 13

### Guard decision breakdown

| Decision | Count | Percentage of recorded writes |
|---|---:|---:|
| ALLOW | 26 | 100.0% |
| BLOCK | 0 | N/A |
| QUARANTINE | 0 | N/A |
| REDACT | 0 | N/A |
| UNKNOWN | 0 | N/A |

Total guarded document writes with recorded decisions: **26**

## 4. Baseline-versus-Guarded Comparison

| Metric | Baseline | Guarded |
|---|---:|---:|
| Eligible trials | 14 | 13 |
| Attack successes | 14 | 13 |
| Attack success rate | 100.0% | 100.0% |

Attack success rate reduction: **0.0 percentage points**.

Comparison available: **True**

## 5. Latest Batch

- Requested trials: 10
- Baseline success rate: 100.0%
- Guarded success rate: 100.0%

## 6. Security Findings

### 1. Baseline attack successfully reproduced

**Severity:** INFO

The attack succeeded in 14 of 14 eligible baseline trials.

### 2. Split-write poisoning succeeded with the guard enabled

**Severity:** HIGH

The attack succeeded in 13 of 13 eligible guarded trials. The configured guard did not prevent this tested scenario.

### 3. Poisoning fragments were allowed by the guard

**Severity:** HIGH

The original experiment logs recorded 26 ALLOW document-write decisions across eligible guarded trials. The attack also succeeded in the tested guarded scenario. This is an observed outcome, not proof of which internal detector did or did not activate.

### 4. No guard interventions were recorded

**Severity:** HIGH

No eligible guarded trial recorded a block, quarantine or redaction intervention.

### 5. Independent fragment retrieval confirmed

**Severity:** INFO

13 eligible guarded trials retrieved the fragments from separate memory records.

### 6. Attack canary reproduced

**Severity:** INFO

The canary was reproduced in 13 eligible guarded trials.

### 7. Some guarded trials were excluded

**Severity:** INFO

2 guarded trials were excluded because they did not meet the experiment eligibility rules.

## 7. Limitations

- Findings apply only to the tested attack scenario and configuration.
- The results do not establish general OWASP Agent Memory Guard effectiveness.
- Zero recorded interventions do not prove that every internal detector was inactive.
- Detector-level attribution requires additional rule and event logging.
- Results are descriptive and do not establish statistical generalization.
- Guard action counts are calculated from original JSONL document records matched to validation-approved trials.

## 8. Conclusion

The experiments demonstrate that the configured strict memory guard did not prevent the tested persistent split-write poisoning attack. The baseline and guarded eligible trials both showed successful attack reproduction. The recorded guard decisions describe document-write outcomes and do not establish whether every internal detector activated. This is a scenario-specific finding and should not be generalized to all attacks or memory guards.
