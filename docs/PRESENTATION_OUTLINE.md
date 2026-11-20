# Academic Project Presentation Outline

**Project Title:** Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications  
**Course Code:** 25BCBPR308 (Academic Project Work Phase-I)  
**Format:** 12-Slide PowerPoint / Beamer Presentation  

---

### Slide 1: Title and Project Introduction
- **Heading:** Cybersecurity Awareness Platform
- **Important Points:**
  - An explainable, privacy-preserving advisory platform for modern cyber threats.
  - Addresses three key attack vectors: social engineering scam messages, phishing link structures, and mobile app permissions.
  - Built with Java 17, Spring Boot, and responsive vanilla web technologies.
- **Suggested Visual / Diagram:**
  - Project banner graphic featuring a shield icon, platform title, and the three core module badges (Message, URL, Permissions).
- **Talking Points for Presenter:**
  > "Respected members of the review panel, today we present the Cybersecurity Awareness Platform. Our project is designed to bridge the gap between complex cyber threat intelligence and everyday user awareness, empowering citizens with transparent, instant guidance on modern digital threats."

---

### Slide 2: Problem Statement
- **Heading:** The Surge in Digital Arrest and Mobile Scams
- **Important Points:**
  - Digital arrest scams coerce victims using fake police and regulatory agency notices over WhatsApp and Skype video calls.
  - Phishing attacks employ typosquatting, deceptive brand subdomains, and obfuscated URLs.
  - Rogue Android apps harvest SMS 2FA codes, contacts, and abuse Accessibility Services.
  - Ordinary users lack accessible tools that explain the mechanics of threats in an understandable manner.
- **Suggested Visual / Diagram:**
  - Infographic highlighting recent statistics from cyber crime agencies regarding digital arrest financial losses and mobile malware prevalence.
- **Talking Points for Presenter:**
  > "In 2024–2026, cyber crime authorities have observed an unprecedented surge in digital arrest scams where victims are kept under continuous video surveillance and extorted of their savings. Concurrently, deceptive links and mobile malware exploit trust. Users need proactive education, not just post-incident reporting."

---

### Slide 3: Project Objectives
- **Heading:** Core Project Objectives
- **Important Points:**
  - Develop an explainable, rule-based message analysis engine targeting scam and extortion indicators.
  - Implement an offline structural URL analyzer with zero network access.
  - Provide actionable Allow/Deny/Review guidance for 20 high-risk Android permissions.
  - Establish a transparent weighted scoring system capped at 100 with Low, Medium, and High risk tiers.
  - Guarantee zero data retention and strict user privacy.
- **Suggested Visual / Diagram:**
  - 3-column feature grid illustrating the three modules feeding into the unified scoring engine.
- **Talking Points for Presenter:**
  > "Our primary objective is to deliver a transparent, rule-driven educational platform. It does not replace enterprise antivirus software, but empowers users to recognize red flags themselves, all while guaranteeing that user data is never logged or persisted."

---

### Slide 4: Existing Solutions vs. Proposed Solution
- **Heading:** Limitations of Existing Tools vs. Our Approach
- **Important Points:**
  - *Existing Commercial Tools:* Black-box AI, heavy cloud data collection, intrusive tracking, and opaque risk numbers without explanation.
  - *Threat Intelligence Platforms (e.g., VirusTotal):* Intended for security analysts; expose submitted links to external servers.
  - *Proposed Solution:* 100% in-memory processing, zero data retention, fully explainable rule indicators, and complete offline link inspection.
- **Suggested Visual / Diagram:**
  - Feature comparison table highlighting Privacy, Explainability, Offline Safety, and Zero Cloud Persistence.
- **Talking Points for Presenter:**
  > "Unlike cloud-based services that harvest submitted data or rely on unexplainable neural networks, our platform uses deterministic rules that clearly highlight which phrases or URL characteristics triggered the alert."

---

### Slide 5: Technology Stack & Environment
- **Heading:** Technology Stack & System Requirements
- **Important Points:**
  - **Backend:** Java 17+, Spring Boot 3.3.5 (Spring Web, Jakarta Validation, Jackson).
  - **Build & Dependency Management:** Apache Maven 3.9.x.
  - **Frontend:** HTML5, CSS3 (Dark cybersecurity aesthetic), Vanilla JavaScript (Fetch API, DOM manipulation).
  - **Testing:** JUnit 5, Spring MockMvc, Surefire Plugin.
  - **Platform:** Linux (Fedora 43 / RHEL compatible).
- **Suggested Visual / Diagram:**
  - Tech stack logo grid (Java, Spring Boot, Maven, HTML5/CSS3/JS, JUnit 5).
- **Talking Points for Presenter:**
  > "We selected Java 17 and Spring Boot for high performance, type safety, and clean inversion-of-control architecture. The frontend uses standard vanilla web APIs without bloated frameworks, ensuring lightweight hosting directly through Spring Boot."

---

### Slide 6: System Architecture
- **Heading:** Layered System Architecture
- **Important Points:**
  - Decoupled 4-tier design: Presentation -> Controller Layer -> Service Layer -> Configuration Layer.
  - Centralized REST endpoints with Jakarta Bean Validation.
  - Shared, reusable `ScoringEngine` utilized by both Message and URL analyzers.
  - Externalized rule catalogs loaded at boot time via Jackson.
- **Suggested Visual / Diagram:**
  - System architecture diagram showing data flow from User Browser -> AnalysisController -> Analyzers -> ScoringEngine -> Response.
- **Talking Points for Presenter:**
  > "The architecture follows strict software engineering separation of concerns. The REST controller validates incoming requests, delegates to domain-specific analyzer services, and utilizes a shared scoring engine. Dynamic configurations are loaded from JSON files at startup."

---

### Slide 7: Module 1 — Message Analyzer
- **Heading:** Text & Scam Indicator Inspection
- **Important Points:**
  - Evaluates 6 key social engineering categories:
    1. Authority & Police Impersonation (weight: 15)
    2. Urgency & Panic Induction (weight: 10)
    3. Digital Arrest & Legal Threats (weight: 20)
    4. Secrecy & Video Call Isolation (weight: 15)
    5. Urgent Payment Demands (weight: 20)
    6. Sensitive Credential / OTP Harvesting (weight: 20)
  - Negative context filtering suppresses false alarms on legitimate security advisories.
- **Suggested Visual / Diagram:**
  - Screenshot of the Message Analyzer dashboard showing matched indicator cards and recommended safe handling tips.
- **Talking Points for Presenter:**
  > "Our Message Analyzer specifically targets coercive scam tactics. In a digital arrest scenario, the system detects authority impersonation, arrest threats, and video-call isolation demands simultaneously, returning clear explanations for each matched indicator."

---

### Slide 8: Module 2 — Offline URL Analyzer
- **Heading:** Offline Structural Link Inspection
- **Important Points:**
  - Strict security guarantee: zero outbound connections, zero DNS queries.
  - Structural analysis via `java.net.URI`:
    - Numeric IP hosts (e.g., `http://192.168.1.100`)
    - Brand subdomain deception (e.g., `sbi.co.in.attacker.com`)
    - Typosquatting look-alike domains via Levenshtein edit distance
    - Embedded `@` authority masking (RFC 3986)
    - Excessive hyphens ($\ge 3$) and known URL shorteners
- **Suggested Visual / Diagram:**
  - Anatomy diagram of a deceptive URL highlighting subdomain spoofing, typosquatting tokens, and the `@` character.
- **Talking Points for Presenter:**
  > "To ensure complete server safety, the URL Analyzer never connects to submitted links. By analyzing the anatomy of the link using URI parsing and Levenshtein distance against known brand dictionaries, it flags high-risk patterns safely offline."

---

### Slide 9: Module 3 — Android Permission Guidance
- **Heading:** Mobile Permission Guidance
- **Important Points:**
  - Curated catalog of 20 high-risk Android permissions.
  - Categorized guidance:
    - **DENY:** High-risk privileges with severe abuse history (`READ_SMS`, `RECEIVE_SMS`, `BIND_ACCESSIBILITY_SERVICE`).
    - **REVIEW:** Context-dependent permissions (`ACCESS_FINE_LOCATION`, `CAMERA`, `READ_CONTACTS`).
    - **ALLOW:** Low-risk regional permissions (`ACCESS_COARSE_LOCATION`).
  - Educational disclaimer: Permissions must always be evaluated in the context of the app's legitimate purpose.
- **Suggested Visual / Diagram:**
  - Grid of permission cards with green (Allow), amber (Review), and red (Deny) status badges.
- **Talking Points for Presenter:**
  > "The Permission Analyzer educates users on mobile attack surfaces. Permissions like Accessibility Services and SMS reading are strongly flagged with 'DENY' due to their frequent abuse by banking trojans, while emphasizing that context determines legitimacy."

---

### Slide 10: Risk Scoring & Evaluation Benchmark
- **Heading:** Transparent Scoring & Benchmark Results
- **Important Points:**
  - Formula: $S = \min\left(100, \sum w_i\right)$ with rule deduplication.
  - Standardized tiers: Low ($0–30$), Medium ($31–65$), High ($66–100$).
  - Evaluated on a 24-sample ground-truth dataset across attack and benign scenarios:
    - **Accuracy:** 100.00%
    - **Precision:** 100.00% | **Recall:** 100.00%
    - **False Positive Rate:** 0.00%
    - **Mean Latency:** 1.42 ms (Target: $< 1,000$ ms)
- **Suggested Visual / Diagram:**
  - Confusion matrix graphic and horizontal score gauge (Low/Medium/High).
- **Talking Points for Presenter:**
  > "Our scoring is transparent and predictable. In automated benchmark testing against 24 verified ground-truth scenarios, the platform achieved 100% accuracy and zero false positives with an average latency of under 2 milliseconds."

---

### Slide 11: Security, Privacy & Automated Testing
- **Heading:** Engineering Rigor & Privacy Safeguards
- **Important Points:**
  - **Zero Persistence:** No database, no user accounts, no disk writes of submitted content.
  - **Zero Ingestion Logging:** Server logs record only metadata lengths, never user text.
  - **DOM Injection Immunity:** Vanilla JS creates elements using `.textContent`, eliminating XSS.
  - **Automated Test Suite:** 48 JUnit 5 tests covering controllers, analyzers, scoring boundaries, security audits, and evaluation runners.
- **Suggested Visual / Diagram:**
  - JUnit 5 test execution summary showing `48 Tests Run, 0 Failures, BUILD SUCCESS`.
- **Talking Points for Presenter:**
  > "Security and privacy were built into the platform from day one. We enforce strict input length limits, sanitize all DOM interactions, omit server-side request logging, and back every component with 48 automated tests."

---

### Slide 12: Conclusion & Phase-II Roadmap
- **Heading:** Project Summary & Future Scope
- **Important Points:**
  - **Summary:** Successfully built, tested, packaged, and verified a standalone, privacy-preserving cybersecurity awareness web platform.
  - **Phase-II Roadmap:**
    1. Local tokenization and multilingual regex rules for Indian regional languages (Hindi, Tamil, Telugu).
    2. Client-side static parser for Android manifests (`AndroidManifest.xml`).
    3. Sandboxed, non-rendering HTTP header inspection for URL unshortening.
- **Suggested Visual / Diagram:**
  - Phase-I Accomplishments vs. Phase-II Roadmap roadmap diagram.
- **Talking Points for Presenter:**
  > "In conclusion, Phase-I delivers a robust, responsive, and verifiable academic prototype. For Phase-II, we envision expanding language coverage and adding static APK manifest analysis. Thank you, and we welcome your questions."
