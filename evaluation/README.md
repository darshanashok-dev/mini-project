# Benchmark Evaluation Harness & Dataset

## 1. Overview
The **Evaluation Harness** is an automated, command-line benchmarking suite built to evaluate the deterministic heuristic detection algorithms implemented in the **Cybersecurity Awareness Platform**.

It measures classification performance against a curated, ground-truth dataset of benign and suspicious messages and URLs derived from security advisories published by the **Indian Cyber Crime Coordination Centre (I4C)**, **CERT-In**, and real-world threat intelligence.

---

## 2. Dataset Structure (`evaluation/dataset.json`)

The evaluation dataset comprises 24 representative samples (12 messages and 12 URLs) categorized into:
- **`BENIGN`**: Legitimate banking security tips, transactional receipts, professional scheduling notes, and official domains.
- **`SUSPICIOUS`**: Social engineering scams, digital arrest coercion, regulatory disconnection threats, and structural phishing URL indicators.

### Sample Schema
```json
{
  "id": "MSG_SUSP_01",
  "type": "message",
  "content": "Full message text...",
  "actualClassification": "SUSPICIOUS",
  "explanation": "Ground truth justification..."
}
```

---

## 3. Ground Truth & Prediction Mapping

The evaluation harness uses the identical detection pipeline and `ScoringEngine` as the production web application.

Predictions are mapped according to the platform's risk tiers:
- **`Low` (0 – 30):** Predicted **`BENIGN`**
- **`Medium` (31 – 65):** Predicted **`SUSPICIOUS`**
- **`High` (66 – 100):** Predicted **`SUSPICIOUS`**

---

## 4. Evaluation Metrics Formulation

1. **Confusion Matrix:**
   - **True Positive (TP):** Suspicious samples correctly classified as Medium or High.
   - **True Negative (TN):** Benign samples correctly classified as Low.
   - **False Positive (FP):** Benign samples incorrectly classified as Medium or High.
   - **False Negative (FN):** Suspicious samples incorrectly classified as Low.

2. **Performance Metrics:**
   $$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
   $$\text{Precision} = \frac{TP}{TP + FP}$$
   $$\text{Recall (Sensitivity)} = \frac{TP}{TP + FN}$$
   $$\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$$

3. **Latency Benchmarking:**
   - Mean analysis execution time (in milliseconds) per sample.
   - Maximum analysis execution time (in milliseconds) per sample.
   - Total test harness elapsed time.

---

## 5. Execution Instructions (Linux / Fedora)

### Option A: Via Maven Test Suite
```bash
./mvnw test -Dtest=EvaluationRunnerTest
```

### Option B: Direct CLI Invocation
```bash
java -cp "target/classes:target/test-classes:$(find /tmp/.m2/repository -name '*.jar' 2>/dev/null | tr '\n' ':')" \
  com.cybersecurity.eval.EvaluationRunner evaluation/dataset.json
```

---

## 6. Actual Benchmark Results

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
 Total Elapsed Time     : 92.15 ms
================================================================================
```

---

## 7. Limitations of Rule-Based Evaluation
- **Lexical Overfitting:** Benchmark metrics reflect coverage on curated patterns. Emerging scam scripts using unseen euphemisms may yield false negatives.
- **Syntactic URL Nuances:** Shorteners and IP hosts are flagged based on structural risk; in certain edge cases, corporate intranets or testing servers on raw IPs will trigger warnings.
