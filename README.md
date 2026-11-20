# Cybersecurity Awareness Platform
## Phishing, Digital Arrest Scams & Android Permission Analysis Platform

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Java](https://img.shields.io/badge/Java-17%20%7C%2021%20%7C%2025-blue.svg)]()
[![Framework](https://img.shields.io/badge/Spring%20Boot-3.3.5-green.svg)]()
[![Tests](https://img.shields.io/badge/JUnit%205-47%20Passed-success.svg)]()
[![License](https://img.shields.io/badge/License-Academic%20Evaluation-orange.svg)]()

A deterministic, explainable, and privacy-preserving web application designed to evaluate suspicious messages, investigate deceptive URLs offline, and analyze sensitive Android mobile permissions.

Developed for **Project Work Phase-I (25BCBPR308)**, Department of Computer Science and Engineering.

---

## Table of Contents
1. [Project Overview & Problem Statement](#1-project-overview--problem-statement)
2. [Key Capabilities & Features](#2-key-capabilities--features)
3. [System Architecture](#3-system-architecture)
4. [Detection Methodology](#4-detection-methodology)
   - [A. Suspicious Message & Digital Arrest Detection](#a-suspicious-message--digital-arrest-detection)
   - [B. Offline Structural URL Inspection](#b-offline-structural-url-inspection)
   - [C. Android Permission Guidance](#c-android-permission-guidance)
5. [Weighted Scoring Engine & Thresholds](#5-weighted-scoring-engine--thresholds)
6. [JSON Configuration Architecture](#6-json-configuration-architecture)
7. [REST API Reference](#7-rest-api-reference)
8. [Privacy & Application Security Guarantees](#8-privacy--application-security-guarantees)
9. [Prerequisites & Development Environment](#9-prerequisites--development-environment)
10. [Build & Installation (Fedora / Linux Commands)](#10-build--installation-fedora--linux-commands)
11. [Running the Application](#11-running-the-application)
12. [Automated Testing with JUnit 5](#12-automated-testing-with-junit-5)
13. [Benchmark Evaluation Harness](#13-benchmark-evaluation-harness)
14. [Project Documentation Index](#14-project-documentation-index)
15. [Frontend User Experience & Accessibility](#15-frontend-user-experience--accessibility)
16. [Known Limitations & Future Roadmap](#16-known-limitations--future-roadmap)

---

## 1. Project Overview & Problem Statement

### The Threat Landscape
Recent cybercrime trends documented by the **Indian Cyber Crime Coordination Centre (I4C)** and **CERT-In** highlight a surge in high-impact social engineering schemes:
- **Digital Arrest Scams:** Perpetrators pose as police officers, CBI agents, Customs authorities, or TRAI representatives. Victims are intimidated through continuous video calls, accused of narcotics smuggling or money laundering, and coerced into transferring funds into "safe government verification accounts."
- **Deceptive Phishing Links:** Malicious links conceal targets using numeric IP addresses, brand masquerading in subdomains, look-alike typo domains, or URL shorteners.
- **Predatory & Trojanized Mobile Apps:** Applications request invasive capabilities such as Accessibility Services and SMS reading to intercept One-Time Passwords (OTPs) and financial alerts.

### The Objective
Existing spam filters and security warnings act as black boxes, rarely explaining *why* a particular communication is dangerous. This platform addresses that gap by providing a **transparent, rule-based, and explainable** evaluation system. Every matched indicator is presented with its contributing rule, score weight, evidence snippet, and recommended defensive actions.

---

## 2. Key Capabilities & Features

1. **Context-Aware Message Inspection:**
   - Detects impersonation, urgency/fear, arrest threats, isolation demands, payment demands, and credential theft.
   - Suppresses false positives when encountering legitimate security advisories (e.g., *"Never share your OTP with anyone"*).
2. **Offline URL Structural Analysis:**
   - **Zero Network Transmission:** Never opens, requests, fetches, or resolves submitted URLs through DNS.
   - Evaluates numeric IP hosts, brand subdomain masquerading, typosquatting homoglyphs, excessive hyphens, `@` authority obfuscation, long/encoded paths, and shorteners.
3. **Android Permission Advisory:**
   - Evaluates 20 sensitive Android permissions.
   - Provides clear `ALLOW`, `DENY`, or `REVIEW` guidance.
   - Safely defaults unknown permissions to `REVIEW`.
4. **Deterministic Weighted Scoring:**
   - Aggregates unique rule weights: $S = \min(100, \sum w_i)$.
   - Categorizes risk into `Low` (0–30), `Medium` (31–65), and `High` (66–100).
5. **Strict Data Privacy:**
   - In-memory evaluation only. No database, no file retention, no request body logging, and no client storage.

---

## 3. System Architecture

The application adopts a clean, layered Spring Boot architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│               Client Interface (HTML5 / CSS3 / Vanilla JS)             │
│        [ Message Tab ]       [ URL Tab ]       [ Permission Tab ]      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP REST (Fetch API)
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Spring Boot REST Layer                          │
│   AnalysisController (Request Validation: @Valid, @NotBlank, @Size)    │
│   GlobalExceptionHandler (Standardized HTTP 400/500 JSON Errors)       │
└───────────────────┬───────────────────┬───────────────────┬────────────┘
                    │                   │                   │
                    ▼                   ▼                   ▼
          ┌──────────────────┐┌──────────────────┐┌──────────────────┐
          │ MessageAnalyzer  ││   UrlAnalyzer    ││PermissionService │
          └─────────┬────────┘└─────────┬────────┘└─────────┬────────┘
                    │                   │                   │
                    └─────────┬─────────┘                   ▼
                              ▼                      [permissions.json]
                      ┌───────────────┐
                      │ ScoringEngine │
                      └───────┬───────┘
                              ▼
                        [rules.json]
```

### Component Roles
- **`com.cybersecurity.controller.AnalysisController`**: Receives requests, enforces size constraints, and delegates to domain services.
- **`com.cybersecurity.service.MessageAnalyzer`**: Compiles regex patterns, executes context-aware pattern matching, and extracts evidence snippets.
- **`com.cybersecurity.service.UrlAnalyzer`**: Parses URLs using `java.net.URI` without DNS or socket calls.
- **`com.cybersecurity.service.PermissionService`**: Matches Android permission strings against the curated guidance catalog.
- **`com.cybersecurity.service.ScoringEngine`**: Reusable component that deduplicates matched rule triggers and computes final risk scores.
- **`com.cybersecurity.config.RuleConfiguration` & `PermissionConfiguration`**: Load and validate configuration JSON files at startup.

---

## 4. Detection Methodology

### A. Suspicious Message & Digital Arrest Detection
The message analyzer evaluates text across six distinct categories:

| Rule ID | Category | Weight | Description & Target Patterns |
|---|---|:---:|---|
| `MSG_IMPERSONATION` | Impersonation | 15 | Claims from CBI, Police, Cyber Crime Cell, Customs, TRAI, DoT, ED, RBI, Courier services (FedEx, BlueDart, DHL), or major banks (SBI, HDFC, ICICI). |
| `MSG_URGENCY_FEAR` | Urgency / Fear | 10 | Artificial deadlines inducing panic: *"immediately"*, *"within 24 hours"*, *"account will be suspended"*, *"service disconnected tonight"*. |
| `MSG_ARREST_THREAT` | Arrest Threats | 20 | Hallmarks of Digital Arrest: *"digital arrest"*, *"non-bailable warrant"*, *"police case registered"*, *"FIR lodged"*, *"narcotics parcel seized"*. |
| `MSG_SECRECY_ISOLATION`| Secrecy / Isolation | 15 | Coercive isolation: *"do not tell anyone"*, *"stay on Skype video call"*, *"remain in closed room"*, *"keep confidential"*. |
| `MSG_PAYMENT_DEMAND` | Payment Demand | 20 | Financial demands: *"transfer money"*, *"safe verification account"*, *"clearance fee"*, *"security deposit"*, *"UPI transfer"*. |
| `MSG_CREDENTIAL_REQUEST`| Credential Theft | 20 | Requests to disclose or submit OTPs, PINs, passwords, CVVs, card numbers, or NetBanking credentials. |

#### Context-Aware False Positive Suppression
Security-aware messages frequently contain words like *"OTP"* or *"password"* in educational contexts. The `MessageAnalyzer` implements negative context matching. If text matches patterns such as:
- `(?i)\b(?:never|do not|don't)\s*share\s*(?:your)?\s*(?:otp|pin|password)\b`
- `(?i)\b(?:bank|police)\s*(?:never|will never)\s*ask\s*for\s*otp\b`
The credential theft rule is suppressed, preventing false positives on legitimate safety alerts.

---

### B. Offline Structural URL Inspection
The URL analyzer enforces strict isolation: **it never opens, connects to, or resolves submitted links**.

| Rule ID | Indicator | Weight | Heuristic Detection Logic |
|---|---|:---:|---|
| `URL_NUMERIC_IP` | Numeric IP Host | 35 | Host conforms to IPv4 (`^(\d{1,3}\.){3}\d{1,3}$`) or IPv6 regex without domain name. |
| `URL_DECEPTIVE_SUBDOMAIN` | Brand Masquerade | 35 | A recognized brand (e.g. `sbi`, `paypal`, `google`) appears in the subdomain prefix while the registered root domain is unrelated (e.g., `sbi.bank.login-portal.xyz`). |
| `URL_LOOKALIKE_DOMAIN` | Typosquatting | 35 | Leetspeak character substitutions (`0` for `o`, `1` for `l`, `rn` for `m`, `vv` for `w`) or Levenshtein edit distance = 1 against known brands (e.g., `paypa1`, `g00gle`, `arnazon`). |
| `URL_EXCESSIVE_HYPHENS` | Keyword Stuffing | 35 | Host contains 3 or more hyphens (e.g., `secure-online-bank-login-verification.com`). |
| `URL_AT_SYMBOL` | Authority Obfuscation | 35 | Authority segment contains `@` (e.g., `http://trustedbank.com@malicious-site.com/login`). Browsers discard userinfo before `@`. |
| `URL_LONG_OR_ENCODED_PATH` | Suspicious Path | 35 | Path length > 50 characters, 3+ hex-encoded characters (`%20`), or direct links to executable files (`.apk`, `.exe`, `.scr`, `.bat`). |
| `URL_SHORTENER` | URL Shortener | 35 | Host matches known shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.) that conceal the destination. |

---

### C. Android Permission Guidance
The platform catalogs 20 high-impact Android permissions. For each permission, it provides:
- **Formal Permission Identifier:** (e.g., `READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`).
- **Common Legitimate Use:** Legitimate developer use cases.
- **Security & Privacy Risks:** How malware, spyware, or loan apps abuse the permission.
- **Clear Recommendation:**
  - `ALLOW`: Appropriate for core functionality.
  - `DENY`: High-risk or frequently abused (e.g., Accessibility Services, SMS reading).
  - `REVIEW`: Context-dependent (e.g., Camera, Location).
- **Default Fallback:** Any uncataloged permission defaults safely to `REVIEW`.
- **Mandatory Warning:** Stated with every check: *"Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source."*

---

## 5. Weighted Scoring Engine & Thresholds

### Mathematical Formula
$$S = \min\left(100, \sum_{i \in M} w_i\right)$$
- $M$: Set of unique matched rules.
- $w_i$: Weight assigned to rule $i$.
- **Deduplication:** A rule contributes its weight only once, regardless of how many times its pattern appears in the input.

### Boundary Classifications
```
   0                    30  31                65  66                   100
   ┌─────────────────────┬───┬─────────────────┬───┬─────────────────────┐
   │         LOW         │   │     MEDIUM      │   │        HIGH         │
   └─────────────────────┴───┴─────────────────┴───┴─────────────────────┘
```
- **0 – 30 (Low):** No standard phishing or extortion signals triggered. *Explicitly cautioned that Low does not mean proven safe.*
- **31 – 65 (Medium):** Suspicious signals detected. Caution and independent verification advised.
- **66 – 100 (High):** Critical scam or fraud patterns detected (e.g., Digital Arrest coercion scripts).

---

## 6. JSON Configuration Architecture

All detection rules, weights, brands, shorteners, and permission advice are externalized in JSON files in `src/main/resources/`:

### `rules.json` Schema
```json
{
  "thresholds": { "lowMax": 30, "mediumMax": 65, "highMax": 100 },
  "limits": { "maxMessageLength": 10000, "maxUrlLength": 2048 },
  "knownBrands": [
    { "name": "google", "officialDomain": "google.com" },
    { "name": "sbi", "officialDomain": "onlinesbi.sbi" }
  ],
  "knownShorteners": ["bit.ly", "tinyurl.com", "t.co"],
  "messageRules": [
    {
      "id": "MSG_IMPERSONATION",
      "name": "Impersonation of Authority or Institution",
      "category": "Impersonation",
      "weight": 15,
      "patterns": ["(?i)\\b(central bureau of investigation|cbi|police)\\b"],
      "explanation": "Claims to originate from law enforcement or government authority."
    }
  ],
  "urlRules": [
    {
      "id": "URL_NUMERIC_IP",
      "name": "Numeric IP Address Host",
      "weight": 25,
      "explanation": "Uses raw numeric IP instead of a registered domain."
    }
  ]
}
```

### `permissions.json` Schema
```json
{
  "mandatoryWarning": "Permissions alone never prove that an application is malware...",
  "defaultUnknownPermission": {
    "recommendation": "REVIEW",
    "explanation": "Review the application's stated functionality..."
  },
  "permissions": [
    {
      "permission": "READ_SMS",
      "name": "Read SMS Messages",
      "description": "Allows an app to read SMS stored on device.",
      "commonLegitimateUse": "Dedicated SMS messengers.",
      "securityRisk": "Steals OTPs and financial verification codes.",
      "recommendation": "DENY",
      "explanation": "Use Google SMS Retriever API instead."
    }
  ]
}
```

**Hot Configuration Updates:** Modifying `rules.json` or `permissions.json` followed by restarting the application updates detection behavior without recompiling Java source code.

---

## 7. REST API Reference

All requests and responses use `application/json`.

### 1. Message Analysis
- **Route:** `POST /api/analyze/message`
- **Request Body:**
  ```json
  {
    "text": "Inspector Sharma from CBI: Narcotics parcel seized. Digital arrest warrant issued. Transfer Rs 50,000 immediately."
  }
  ```
- **Response (HTTP 200 OK):**
  ```json
  {
    "score": 65,
    "category": "Medium",
    "matchedRules": [
      {
        "id": "MSG_IMPERSONATION",
        "name": "Impersonation of Authority or Institution",
        "weight": 15,
        "matchedText": "Inspector Sharma from... CBI",
        "explanation": "Claims to originate from law enforcement."
      },
      {
        "id": "MSG_ARREST_THREAT",
        "name": "Arrest and Legal Action Threat",
        "weight": 20,
        "matchedText": "Digital arrest warrant issued",
        "explanation": "Threatens arrest or criminal warrants."
      }
    ],
    "recommendedAction": "Do not transfer money or share credentials.",
    "safeHandlingTip": "Official agencies never arrest citizens over video calls.",
    "disclaimer": "This result is advisory and does not prove that the message is malicious or safe."
  }
  ```

### 2. URL Structural Analysis
- **Route:** `POST /api/analyze/url`
- **Request Body:**
  ```json
  {
    "url": "http://192.168.1.105/bank/secure-login.html"
  }
  ```
- **Response (HTTP 200 OK):**
  ```json
  {
    "score": 25,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_NUMERIC_IP",
        "name": "Numeric IP Address Host",
        "weight": 25,
        "matchedText": "192.168.1.105",
        "explanation": "Uses a direct numeric IP address instead of a domain name."
      }
    ],
    "recommendedAction": "Exercise strong caution. Independently verify the address.",
    "safeHandlingTip": "Type official website addresses directly into your browser.",
    "disclaimer": "This result is advisory and does not prove that the URL is malicious or safe."
  }
  ```

### 3. List Known Permissions
- **Route:** `GET /api/permissions`
- **Response (HTTP 200 OK):** Array of all 20 cataloged Android permission records.

### 4. Check Selected Permissions
- **Route:** `POST /api/permissions/check`
- **Request Body:**
  ```json
  {
    "permissions": ["READ_SMS", "CAMERA", "UNKNOWN_VENDOR_PERM"]
  }
  ```
- **Response (HTTP 200 OK):**
  ```json
  {
    "results": [
      {
        "permission": "READ_SMS",
        "recommendation": "DENY",
        "explanation": "Deny unless the application is your default SMS messenger."
      },
      {
        "permission": "CAMERA",
        "recommendation": "REVIEW",
        "explanation": "Allow only when photo or video features are essential."
      },
      {
        "permission": "UNKNOWN_VENDOR_PERM",
        "recommendation": "REVIEW",
        "explanation": "Review the application's manifest and publisher reputability."
      }
    ],
    "mandatoryWarning": "Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source."
  }
  ```

### Error Responses
Invalid or blank requests return structured JSON with HTTP 400:
```json
{
  "error": "text: Message text cannot be empty or blank",
  "status": 400,
  "timestamp": "2026-11-20T05:12:00.000Z"
}
```

---

## 8. Privacy & Application Security Guarantees

1. **Zero Data Retention:** No databases or file logs store analyzed messages or URLs.
2. **Log Sanitization:** Spring Boot request logging is restricted to payload length and count. Raw text is never written to log files.
3. **No External URL Connections:** URLs are parsed with string operations only. No HTTP requests, socket connections, or DNS resolutions occur.
4. **Input Length Bounding:** Max 10,000 characters for messages; max 2,048 characters for URLs.
5. **Cross-Site Scripting (XSS) Prevention:** Frontend renders all user text via `textContent`. No user-controlled text is inserted using `innerHTML`.
6. **No Client Storage:** Inputs are cleared upon analysis. No data is stored in `localStorage` or `sessionStorage`.

---

## 9. Prerequisites & Development Environment

- **Operating System:** Linux (Fedora 38+, RHEL 9+, Ubuntu 22.04+), macOS, or Windows.
- **Java Development Kit:** Java 17 or higher (tested on OpenJDK 17 and OpenJDK 25).
- **Build Tool:** Maven 3.8+ (bundled `./mvnw` included).
- **Terminal Utilities:** `curl`, `tar`, `python3` (optional for scripting).

---

## 10. Build & Installation (Fedora / Linux Commands)

### 1. Check Environment
```bash
# Verify Java installation (requires JDK 17 or newer)
java -version

# Optional: Install OpenJDK 17 on Fedora if needed
# sudo dnf install -y java-17-openjdk-devel
```

### 2. Clone or Enter Project Directory
```bash
cd /home/d/study/sem3/oop-java/mini-project
chmod +x mvnw
```

### 3. Build the Application
```bash
# Clean, compile, execute tests, and package executable JAR
./mvnw clean package
```
The executable fat JAR is produced at `target/cybersecurity-awareness-platform-1.0.0.jar`.

---

## 11. Running the Application

### Option A: Running the Standalone JAR (Recommended)
```bash
java -jar target/cybersecurity-awareness-platform-1.0.0.jar
```

### Option B: Running via Maven Plugin
```bash
./mvnw spring-boot:run
```

### Accessing the Dashboard
Open your web browser and navigate to:
**`http://localhost:8080`**

To verify the server is running via terminal:
```bash
curl -I http://localhost:8080/
```

---

## 12. Automated Testing with JUnit 5

The project contains 47 automated JUnit 5 tests covering all architectural layers:

```bash
# Run all tests
./mvnw test
```

### Specific Test Classes
| Test Class | Scope Tested | Command |
|---|---|---|
| `ScoringEngineTest` | Zero score, weighting, duplicate prevention, and exact boundaries (30, 31, 65, 66) | `./mvnw test -Dtest=ScoringEngineTest` |
| `MessageAnalyzerTest`| Impersonation, urgency, arrest threats, secrecy, payment, and false positive reduction | `./mvnw test -Dtest=MessageAnalyzerTest` |
| `UrlAnalyzerTest` | Numeric IPs, subdomains, typosquatting, shorteners, `@` symbol, and offline safety | `./mvnw test -Dtest=UrlAnalyzerTest` |
| `PermissionServiceTest`| Known guidance, Allow/Deny/Review advice, unknown fallback, and disclaimers | `./mvnw test -Dtest=PermissionServiceTest` |
| `ControllerTest` | MockMvc integration, HTTP 200 responses, HTTP 400 validation, and sanitized errors | `./mvnw test -Dtest=ControllerTest` |
| `FrontendIntegrationTest` | Verifies static assets, privacy invariants, hero elements, and CSS/JS integrity | `./mvnw test -Dtest=FrontendIntegrationTest` |
| `SecurityAndPrivacyAuditTest` | Verifies input bounding, payload rejections, determinism, and score bounds | `./mvnw test -Dtest=SecurityAndPrivacyAuditTest` |
| `EvaluationRunnerTest` | Full benchmark dataset evaluation asserting Precision & Recall > 85%, latency < 1s | `./mvnw test -Dtest=EvaluationRunnerTest` |

---

## 13. Benchmark Evaluation Harness

The evaluation harness evaluates detection quality and processing latency against a benchmark dataset of 24 labelled samples (`evaluation/dataset.json`) informed by CERT-In and I4C advisories.

### Running via Maven
```bash
./mvnw test -Dtest=EvaluationRunnerTest
```

### Running via Command Line
```bash
java -cp "target/classes:target/test-classes:$(find ~/.m2/repository -name '*.jar' 2>/dev/null | tr '\n' ':')" com.cybersecurity.eval.EvaluationRunner evaluation/dataset.json
```

### Benchmark Results
```text
================================================================================
 OVERALL PERFORMANCE SUMMARY
================================================================================
 Total Samples Analyzed : 24 (12 messages, 12 URLs)
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

## 14. Project Documentation Index

Additional detailed technical documentation is available in the repository:

- **[Project Review & Viva Rehearsal](docs/PROJECT_REVIEW_AND_VIVA.md):** Master evaluator review, source walkthroughs, 60 viva Q&As, and difficult examiner defenses.
- **[Final Project Audit](docs/FINAL_PROJECT_AUDIT.md):** Complete requirements verification table and design boundaries.
- **[Demonstration Guide](docs/DEMONSTRATION_GUIDE.md):** 12-minute presentation script and step-by-step evaluator walkthrough.
- **[Demonstration Examples](docs/DEMONSTRATION_EXAMPLES.md):** 19 synthetic demonstration examples with verified application outputs.
- **[System Architecture Guide](docs/SYSTEM_ARCHITECTURE.md):** Complete component breakdown, class responsibilities, and Mermaid sequence flows.
- **[Viva Questions and Answers](docs/VIVA_QUESTIONS_AND_ANSWERS.md):** 42 comprehensive viva preparation questions and answers across 7 sections.
- **[Presentation Outline](docs/PRESENTATION_OUTLINE.md):** 12-slide presentation structure with presenter talking points.
- **[Final Verification Checklist](docs/FINAL_VERIFICATION_CHECKLIST.md):** Pre-flight verification checklist for build, tests, APIs, and security safeguards.
- **[REST API Reference](docs/API_DOCUMENTATION.md):** Exhaustive endpoint contracts, input validation rules, and curl examples.
- **[Testing & Evaluation Guide](docs/TESTING_AND_EVALUATION.md):** Full test suite catalog (48 tests), confusion matrix formulation, and boundary verification.
- **[Evaluation Dataset Guide](evaluation/README.md):** Dataset schemas, labelling criteria based on I4C/CERT-In advisories, and prediction mapping.
- **[Labelled Dataset JSON](evaluation/dataset.json):** The 24 ground-truth benchmark examples.

---

## 15. Frontend User Experience & Accessibility

- **Modern Cybersecurity Aesthetic:** Charcoal and navy background (`#0A0F1D`, `#10192E`) with cyan and cobalt accents (`#00D2FF`, `#0077B6`).
- **Interactive Character Counters:** Live counter feedback on textareas and inputs.
- **Quick Demo Chips:** One-click pre-fills for testing real-world scam scripts and legitimate advisories.
- **Clear Risk Hierarchy:** Color and text used together (Low / Medium / High) for accessible visual feedback.
- **Mobile Responsive:** Fluid layout adapting from mobile screens to multi-column desktop displays.

---

## 16. Known Limitations & Future Roadmap

### Current Limitations
1. **Rule-Based Coverage:** Detection is limited to configured patterns in `rules.json`. Novel scam phrasing not covered by regex rules will not trigger warnings.
2. **Offline URL False Positives:** Legitimate links using URL shorteners or direct IP addresses will be flagged for review due to structural heuristics.
3. **Individual Permission Evaluation:** Permissions are evaluated independently rather than analyzing co-occurring combinations in an APK manifest.

### Planned Enhancements (Phase-II)
- Regional Indian language support (Hindi, Kannada, Tamil, Telugu).
- Automated Android APK manifest XML upload and static decompilation.
- Local offline domain reputation feed integration.
- Interactive educational quizzes on scam awareness.
