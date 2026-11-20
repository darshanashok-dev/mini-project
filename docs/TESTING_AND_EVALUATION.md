# Testing & Evaluation Methodology Documentation

## 1. Testing Strategy

The **Cybersecurity Awareness Platform** implements a multi-tiered testing strategy ensuring functional correctness, security compliance, architectural separation, and detection accuracy.

```
                      ▲
                     / \
                    /   \
                   / Eval\        Evaluation Harness (24 real-world samples)
                  / Harness\      (Precision, Recall, Latency benchmarking)
                 /───────────\
                / Integration \   ControllerTest (MockMvc) & FrontendIntegrationTest
               /   & Security  \  SecurityAndPrivacyAuditTest (Input Bounding, Offline Safety)
              /─────────────────\
             /    Unit Tests     \ ScoringEngineTest, MessageAnalyzerTest,
            /                     \ UrlAnalyzerTest, PermissionServiceTest
           ─────────────────────────
```

---

## 2. Test Suite Overview (47 Tests Passing)

The project includes **47 automated JUnit 5 tests** across 8 test classes:

| Test Class | Focus & Scope | Tests Count | Status |
| :--- | :--- | :---: | :---: |
| **`ScoringEngineTest`** | Mathematical weighting, deduplication, capping at 100, exact boundary tests (`0`, `30`, `31`, `65`, `66`, `100`). | 6 | PASS |
| **`MessageAnalyzerTest`** | Impersonation, urgency, arrest threats, secrecy, payment demands, credential theft, and false-positive suppression. | 10 | PASS |
| **`UrlAnalyzerTest`** | Numeric IP hosts, brand subdomain masquerading, typosquatting homoglyphs, excessive hyphens, `@` authority symbols, shorteners, and offline execution safety. | 9 | PASS |
| **`PermissionServiceTest`**| 20 cataloged permissions, Allow/Deny/Review advice, uncataloged permission fallback, and disclaimers. | 6 | PASS |
| **`ControllerTest`** | REST endpoints (`POST /message`, `POST /url`, `GET /permissions`, `POST /check`), HTTP 200/400 mapping, and input validation. | 6 | PASS |
| **`FrontendIntegrationTest`** | Static HTML/CSS/JS asset integrity, presence of required warnings, character counter constraints, and DOM privacy invariants. | 3 | PASS |
| **`SecurityAndPrivacyAuditTest`** | Input length boundary enforcement (>10,000 / >2,048 chars), offline URL safety, idempotency, score bounds, and unknown permission safety. | 6 | PASS |
| **`EvaluationRunnerTest`** | Benchmark evaluation harness verifying Precision $\ge$ 85%, Recall $\ge$ 85%, and latency < 1,000 ms against `evaluation/dataset.json`. | 1 | PASS |

---

## 3. Running Automated Tests (Fedora / Linux)

### Run Entire Test Suite
```bash
./mvnw test
```

### Run Specific Test Classes
```bash
# Test scoring boundaries and capping
./mvnw test -Dtest=ScoringEngineTest

# Test message analysis and context awareness
./mvnw test -Dtest=MessageAnalyzerTest

# Test offline URL structural heuristics
./mvnw test -Dtest=UrlAnalyzerTest

# Test Android permission recommendations
./mvnw test -Dtest=PermissionServiceTest

# Test REST API controllers with MockMvc
./mvnw test -Dtest=ControllerTest

# Test security and privacy constraints
./mvnw test -Dtest=SecurityAndPrivacyAuditTest

# Run benchmark evaluation harness test
./mvnw test -Dtest=EvaluationRunnerTest
```

---

## 4. Benchmark Evaluation Results

The evaluation dataset (`evaluation/dataset.json`) contains 24 labelled samples (12 messages, 12 URLs).

### Evaluation Rules:
- **Low (0 – 30):** Predicted **`BENIGN`**
- **Medium (31 – 65):** Predicted **`SUSPICIOUS`**
- **High (66 – 100):** Predicted **`SUSPICIOUS`**

### Actual Confusion Matrix & Performance Metrics:
```text
================================================================================
 OVERALL PERFORMANCE SUMMARY
================================================================================
 Total Samples Analyzed : 24
 Correct Predictions    : 24 (100.00%)
 Incorrect Predictions  : 0 (0.00%)
 True Positives (TP)    : 12
 False Positives (FP)   : 0
 True Negatives (TN)    : 12
 False Negatives (FN)   : 0
--------------------------------------------------------------------------------
 Accuracy               : 100.00%
 Precision              : 100.00%
 Recall (Sensitivity)   : 100.00%
 False Positive Rate    : 0.00%
--------------------------------------------------------------------------------
 Mean Response Time     : 1.420 ms  (Target: < 1,000 ms)
 Max Response Time      : 8.720 ms
 Total Evaluation Time  : 92.15 ms
================================================================================
```

---

## 5. Security & Boundary Verification

1. **Exact Risk Thresholds:**
   - Score `0`: Low
   - Score `30`: Low (boundary)
   - Score `31`: Medium (boundary)
   - Score `65`: Medium (boundary)
   - Score `66`: High (boundary)
   - Score `100`: High (capped boundary)
2. **Rejection of Oversized Input:**
   - Text with 10,001 characters $\rightarrow$ HTTP 400 with message *"Message text exceeds maximum allowed length of 10,000 characters"*.
   - URL with 2,050 characters $\rightarrow$ HTTP 400 with message *"URL exceeds maximum allowed length of 2,048 characters"*.
3. **Offline Safety Guarantee:**
   - Non-existent fictional domains (e.g. `http://fictional-domain-999.xyz`) and malformed URIs are evaluated purely through local string analysis with zero network requests or uncaught exceptions.
