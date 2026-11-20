# Application Demonstration Guide & Presentation Script

**Project Title:** Cybersecurity Awareness Platform  
**Target Duration:** 10–15 Minutes  
**Demonstration Scope:** Live Application Walkthrough, Architecture Overview, and Automated Verification  

---

## 1. Demonstration Setup & Prerequisites

Before initiating the demonstration, execute the following commands in the project directory:

```bash
# 1. Verify build and execute automated test suite
./mvnw clean test

# 2. Start the Spring Boot application server
java -Duser.home=/tmp -jar target/cybersecurity-awareness-platform-1.0.0.jar
```

Open a modern web browser (Firefox, Chromium, Chrome) and navigate to:
```text
http://localhost:8080/
```

---

## 2. Step-by-Step Presentation Script

```
+---------------------------------------------------------------------------------+
| Estimated Duration: 12 Minutes                                                  |
| Format: Live Screen Demonstration + Explanatory Talking Points                  |
+---------------------------------------------------------------------------------+
```

### Stage 1: Introduce the Project (0:00 - 1:00)
- **Action:** Display the browser opened to `http://localhost:8080/`. Point to the header logo, platform title, and privacy warning banner.
- **Presenter Spoken Script:**
  > "Good morning, respected members of the evaluation committee. Today, I am demonstrating the Cybersecurity Awareness Platform, an academic software project developed to tackle modern cyber threats targeting ordinary users. The platform focuses on three critical vectors: social engineering in text messages—specifically 'digital arrest' and extortion scams—offline structural inspection of suspicious links, and context-aware guidance on high-risk Android permissions. Our implementation is built strictly with Java 17 and Spring Boot on the backend, with a zero-framework, responsive frontend."

---

### Stage 2: Problem Statement & Context (1:00 - 2:00)
- **Action:** Point to the subtitle: *"Stay Alert. Stay Protected. Understand suspicious messages, inspect potentially deceptive links and learn how application permissions affect your privacy."*
- **Presenter Spoken Script:**
  > "In recent months, law enforcement agencies across India have reported a dramatic surge in 'digital arrest' scams, where victims are intimidated over WhatsApp and Skype video calls under threats of fake police FIRs or courier narcotics seizures. Simultaneously, phishing links deceive users through typographic lookalikes and deceptive subdomains, while rogue applications harvest SMS OTPs and accessibility services. Existing commercial tools either require uploading sensitive personal data to third-party clouds or rely on opaque black-box AI. Our platform provides an explainable, in-memory, privacy-preserving solution."

---

### Stage 3: Dashboard Architecture & Privacy Safeguards (2:00 - 3:00)
- **Action:** Scroll down past the hero section. Highlight the prominent privacy warning:
  > *"Never enter confidential information, passwords, OTPs, banking details or private personal data."*
- **Presenter Spoken Script:**
  > "Before demonstrating our analysis tools, notice our privacy safeguard banner. The system operates on a zero-persistence model: no user accounts, no databases, no server-side logging of submitted message text or URLs, and zero outbound network calls. All evaluations occur purely in server RAM during the lifetime of the HTTP request, and the frontend automatically clears input fields post-submission to prevent client-side credential retention."

---

### Stage 4: Module 1 Demonstration — Message Analyzer (3:00 - 5:00)
- **Action:**
  1. Click on the **Message Analyzer** navigation card.
  2. Click the quick demo chip: **"Digital Arrest Scam"**.
  3. Observe the input area populate with:
     ```text
     You are placed under digital arrest by Mumbai Cyber Crime Branch. Do not disconnect Skype video call or leave the room until investigation clears.
     ```
  4. Click the **"Analyze Message"** button.
  5. Point to the animated score dial reading **50 / 100**, the **Medium Risk** badge, and the matched indicator cards.
- **Presenter Spoken Script:**
  > "Let us test a realistic digital arrest threat. Clicking 'Analyze Message' triggers a POST request to `/api/analyze/message`. The backend MessageAnalyzer evaluates regex patterns and contextual indicators. In this sample, three distinct indicators are detected:
  > 1. Impersonation of authority (Mumbai Cyber Crime Branch - weight 15)
  > 2. Direct arrest and legal action threat (weight 20)
  > 3. Secrecy and video-call isolation coercion (weight 15)
  > Notice the transparent scoring: $15 + 20 + 15 = 50$, placing it squarely in the Medium Risk tier. Below the score, the platform provides actionable advice explaining that official police agencies never conduct arrests or investigations over video calls."

---

### Stage 5: Module 2 Demonstration — URL Analyzer (5:00 - 7:00)
- **Action:**
  1. Switch to the **URL Analyzer** tab.
  2. Click the quick demo chip: **"Look-alike Typo"**.
  3. The input field displays:
     ```text
     https://paypa1-security.com/signin
     ```
  4. Click **"Inspect URL Structure"**.
  5. Review the resulting score (**20 / 100**, **Low Risk**) and the matched indicator card: *Look-alike or Typosquatting Domain (`paypa1` mimicking `paypal`)*.
  6. Next, test an embedded authority `@` sample:
     ```text
     https://secure-login@phishing-server.com/auth
     ```
  7. Show the matched indicator: *Embedded '@' Symbol in URL Authority*.
- **Presenter Spoken Script:**
  > "Next is the URL Analyzer. A critical engineering constraint of our platform is that it NEVER connects to, pings, or resolves submitted links. Notice that even for suspicious URLs, no socket or HTTP connection is made. Instead, our service uses `java.net.URI` for offline structural parsing. Here, it uses a Levenshtein distance algorithm to detect typosquatting where the character '1' replaces 'l' in PayPal. In the second sample, it flags the '@' character, which obscures the real destination host under RFC 3986."

---

### Stage 6: Module 3 Demonstration — Android Permission Analyzer (7:00 - 8:30)
- **Action:**
  1. Switch to the **Android Permissions** tab.
  2. Point out the searchable grid of sensitive permissions.
  3. Filter by category: click **"SMS"** and select `android.permission.READ_SMS`.
  4. Switch category to **"System"** and select `android.permission.BIND_ACCESSIBILITY_SERVICE`.
  5. Click **"Evaluate Selected Permissions"**.
  6. Show the resulting guidance cards:
     - `READ_SMS`: Red **DENY** badge with explanation of OTP harvesting risks.
     - `BIND_ACCESSIBILITY_SERVICE`: Red **DENY** badge highlighting banking trojan risks.
  7. Point to the mandatory educational disclaimer:
     > *"Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source."*
- **Presenter Spoken Script:**
  > "Our third module addresses Android application permissions. We maintain an offline catalog of 20 high-risk Android permissions. When evaluating `READ_SMS` and `BIND_ACCESSIBILITY_SERVICE`, the engine immediately issues a strong 'DENY' recommendation. As explained on screen, accessibility access allows trojans to read passwords across any application and bypass 2FA. Crucially, the platform emphasizes context: while a dedicated screen reader legitimately requires accessibility, a calculator or photo editor requesting it is almost certainly malicious."

---

### Stage 7: Shared Scoring Engine & Configuration (8:30 - 9:30)
- **Action:** Open [`rules.json`](file:///home/d/study/sem3/oop-java/mini-project/src/main/resources/rules.json) in the editor or terminal.
- **Presenter Spoken Script:**
  > "The scoring engine is completely decoupled from detection logic. Matched indicators are passed to `ScoringEngine`, which aggregates weights:
  > $$S = \min(100, \sum w_i)$$
  > Thresholds are standardized: 0–30 is Low, 31–65 is Medium, and 66–100 is High. Importantly, rule weights, regex patterns, brand dictionaries, and shortener lists are loaded from external JSON files at startup via Spring configuration beans. This means security analysts can update rules or adjust weights without recompiling Java source code."

---

### Stage 8: Backend Architecture Overview (9:30 - 10:30)
- **Action:** Display the architecture diagram from [`SYSTEM_ARCHITECTURE.md`](file:///home/d/study/sem3/oop-java/mini-project/docs/SYSTEM_ARCHITECTURE.md).
- **Presenter Spoken Script:**
  > "The backend follows a strict layered Spring Boot architecture:
  > - Controllers handle HTTP request validation and status codes using Jakarta Validation.
  > - Service classes execute business logic: `MessageAnalyzer`, `UrlAnalyzer`, `PermissionService`, and the shared `ScoringEngine`.
  > - A `GlobalExceptionHandler` intercepts validation failures and malformed requests, returning standardized JSON error bodies.
  > - All dependencies are injected via Spring inversion of control, ensuring testability and modularity."

---

### Stage 9: Automated Testing & Evaluation Harness (10:30 - 11:30)
- **Action:** Open terminal and run:
  ```bash
  ./mvnw test -Dtest=EvaluationRunnerTest
  ```
  Show the terminal test output displaying 100% Accuracy, 100% Precision, 100% Recall, and sub-2 millisecond latency.
- **Presenter Spoken Script:**
  > "To ensure rigorous academic evaluation, we built an automated benchmark harness. Across a 24-sample ground-truth dataset spanning diverse attack and benign scenarios:
  > - Detection Accuracy: 100%
  > - False Positive Rate: 0.00%
  > - Mean response latency: 1.42 milliseconds, well within our sub-second requirement.
  > Our overall automated test suite contains 48 unit, integration, and security audit tests, all passing with zero failures."

---

### Stage 10: Limitations & Conclusion (11:30 - 12:30)
- **Action:** Return to presentation slides or summary.
- **Presenter Spoken Script:**
  > "To conclude: the Cybersecurity Awareness Platform delivers an educational, explainable, and privacy-respecting defense tool against emerging threats like digital arrest scams. In terms of limitations, our current lexical analysis is optimized for English, and offline URL analysis cannot inspect redirected destinations behind shorteners. In Phase-II, we plan to incorporate Indian regional language tokenization and client-side Android manifest parsing. Thank you, and I am now ready for your questions."
