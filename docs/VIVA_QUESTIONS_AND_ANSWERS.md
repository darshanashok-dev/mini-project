# Comprehensive Viva Questions and Answers

**Project:** Cybersecurity Awareness Platform  
**Target:** Bachelor of Technology / Computer Science & Engineering Project Examination  
**Focus Areas:** Software Engineering, Web Architecture, Application Security, Rule-Based Detection  

---

## Section A: Project Fundamentals

### Q1: What problem does the platform solve?
**A:** The platform addresses the rapid growth of social engineering attacks—particularly coercive "digital arrest" scams, impersonation extortion, deceptive phishing links, and Android permission abuse. It provides an explainable, in-memory, privacy-preserving advisory tool that educates users on threat indicators without requiring them to share sensitive data with third-party cloud services.

### Q2: Why was this project selected?
**A:** Recent cybersecurity reports and government advisories (e.g., CERT-In and Indian Cyber Crime Coordination Centre - I4C) highlight that millions of citizens are deceived by digital arrest scams and mobile malware. While enterprise threat intelligence tools exist, accessible educational tools that clearly explain *why* a message, URL, or permission is dangerous are lacking.

### Q3: What are the primary objectives of the platform?
**A:**
1. Identify social engineering patterns in suspicious messages (impersonation, urgency, digital arrest threats, secrecy, payment demands, credential requests).
2. Perform offline structural inspection of suspicious links without connecting to untrusted hosts.
3. Provide contextual guidance on sensitive Android permissions (`ALLOW`, `DENY`, `REVIEW`).
4. Implement a transparent, configurable scoring engine that caps risk at 100 and classifies scores into Low, Medium, and High tiers.

### Q4: Who are the intended end users?
**A:** Everyday internet and mobile users, university students, corporate employees undergoing security awareness training, and cybersecurity educators who need an interactive tool to demonstrate common scam anatomy.

### Q5: What are the current limitations of the platform?
**A:**
1. Message analysis is lexical and regex-based, optimized for English; heavily obscured or vernacular phrasing may evade detection.
2. URL analysis is offline; it cannot inspect destination landing pages behind shorteners or dynamic redirection chains.
3. Android analysis is static and educational; it does not parse compiled APK files or Android manifests directly.

---

## Section B: Java and Spring Boot

### Q6: What is Spring Boot, and why was it chosen for this project?
**A:** Spring Boot is an open-source Java framework that simplifies the creation of stand-alone, production-grade Spring applications through opinionated starter dependencies and auto-configuration. It was chosen because it provides an embedded Tomcat server, robust REST controllers, automatic JSON serialization with Jackson, and seamless integration with testing frameworks like JUnit 5.

### Q7: What is Apache Maven and how is it used in this project?
**A:** Maven is a build automation and dependency management tool based on the Project Object Model (`pom.xml`). It manages the application lifecycle, including downloading dependencies (Spring Boot starter web, validation, Jackson, JUnit 5), compiling Java 17 bytecode, executing automated test suites via Surefire, and packaging the standalone executable JAR.

### Q8: What is Dependency Injection (DI) and how is it used here?
**A:** Dependency Injection is a design pattern where an object's dependencies are provided by an external framework rather than created internally by the object. In our application, Spring's `@Autowired` constructor injection provides `ScoringEngine` and `RulesConfig` to `MessageAnalyzer` and `UrlAnalyzer`, and passes all three analyzers into `AnalysisController`. This ensures loose coupling and simplifies unit testing with mocks.

### Q9: What is a REST API?
**A:** A Representational State Transfer (REST) API is an architectural style for networked systems. It uses standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) and stateless communication. In our platform, clients submit JSON payloads to HTTP endpoints (`/api/analyze/message`, `/api/analyze/url`, `/api/permissions/check`) and receive structured JSON responses representing analysis results.

### Q10: Explain the Controller-Service architecture used in the backend.
**A:** The controller layer (`AnalysisController`) handles HTTP communication, deserializes incoming JSON, enforces validation constraints, and returns HTTP status codes. The service layer (`MessageAnalyzer`, `UrlAnalyzer`, `PermissionService`, `ScoringEngine`) encapsulates business logic, regex matching, scoring aggregation, and risk classification. This separation ensures controllers remain lightweight and services can be reused or tested independently of the web layer.

### Q11: How does Jackson handle JSON serialization and deserialization?
**A:** Jackson's `ObjectMapper` inspects Java classes and maps JSON keys to class attributes using getters and setters. During startup, `RuleConfiguration` and `PermissionConfiguration` read `rules.json` and `permissions.json` and deserialize them into strongly typed `RulesConfig` and `PermissionsConfig` POJOs. When an API endpoint returns an `AnalysisResult`, Jackson automatically serializes it to an outgoing JSON string.

### Q12: How are runtime exceptions handled gracefully in the application?
**A:** We use a centralized `@RestControllerAdvice` class (`GlobalExceptionHandler`). When a client submits an invalid request (e.g., an empty message or malformed JSON), Spring intercepts the exception and delegates it to `GlobalExceptionHandler`, which formats a standardized `ErrorResponse` JSON with a meaningful error message and HTTP 400 Bad Request status.

---

## Section C: Detection and Scoring

### Q13: How does the Message Analyzer identify scam patterns?
**A:** It evaluates the submitted text against six rule categories defined in `rules.json`: Authority Impersonation, Urgency/Fear, Digital Arrest Threats, Secrecy/Isolation, Payment Demands, and Credential Requests. Detection uses case-insensitive regular expressions and keyword dictionaries tailored to modern scam terminology (e.g., "digital arrest", "CBI", "Skype video call", "non-bailable warrant").

### Q14: How does the system reduce false positives in message analysis?
**A:** It incorporates negative context filtering. For instance, legitimate security advisories from CERT-In or banks often mention scam keywords ("Do not share OTP", "Police will never ask for funds"). The analyzer checks whether scam keywords are preceded by warning prefixes such as "beware of", "do not share", or "never", suppressing rule triggers when benign educational context is detected.

### Q15: How does offline URL structural analysis work?
**A:** The submitted URL is parsed locally using `java.net.URI`. The analyzer examines structural characteristics of the URI components:
- **Host:** Checks for raw IPv4 addresses, excessive hyphens ($\ge 3$), and known URL shortener domains.
- **Authority:** Checks for the presence of the `@` symbol, which browser engines treat as user-info to mask the true destination host.
- **Subdomains:** Checks for trusted brand names (e.g., `sbi`, `paypal`) placed as subdomains on unrelated parent domains.
- **Path:** Checks for deep nesting or encoded hexadecimal characters.

### Q16: How does the platform detect look-alike (typosquatting) domains?
**A:** It uses the Levenshtein distance algorithm. The analyzer splits the domain label into tokens and computes the minimum single-character edit distance (insertions, deletions, substitutions) against a catalog of 18 protected high-value brands (e.g., `paypal`, `google`, `microsoft`, `netflix`). If a token like `paypa1` has an edit distance of 1 from `paypal`, it is flagged as a look-alike domain.

### Q17: What is weighted scoring and how is the score computed?
**A:** Each detection rule carries an individual integer weight reflecting its severity (e.g., digital arrest threats = 20, numeric IP host = 25, urgency = 10). When a message or URL is analyzed, all triggered rules are deduplicated by rule ID, and their weights are summed. The total score is capped at 100:
$$S = \min\left(100, \sum_{i \in \text{Unique Matched Rules}} w_i\right)$$

### Q18: Why is the score capped at 100?
**A:** Capping normalizes the score to a standard percentage-like scale ($0–100$), allowing users to easily understand relative severity regardless of how many individual indicators triggered.

### Q19: Why were the risk thresholds (0–30 Low, 31–65 Medium, 66–100 High) chosen?
**A:** These thresholds provide clear separation:
- **0–30 (Low):** Minor or single isolated indicators (e.g., simple urgency or a brand mention alone) that may occur in ordinary communication.
- **31–65 (Medium):** Combinations of multiple suspicious indicators (e.g., brand impersonation + urgent payment demand, or typosquatting + suspicious path) that indicate high probability of fraud.
- **66–100 (High):** Aggressive multi-vector scam scenarios (e.g., impersonation + digital arrest + secrecy + payment demand).

### Q20: Why are analysis results explicitly labeled as "advisory"?
**A:** A fundamental principle of cybersecurity is that no rule-based heuristic can guarantee safety. Declaring a clean score as "safe" could instill false confidence and lead to victim compromise if a novel attack bypasses existing rules. Results are therefore explicitly presented as guidance to prompt critical thinking.

---

## Section D: Android Permissions

### Q21: What are Android permissions?
**A:** Android permissions are a security mechanism implemented by the Android OS to control application access to sensitive user data (contacts, SMS, location) and privileged hardware features (camera, microphone). Users must grant these permissions at install time or runtime.

### Q22: What constitutes a "sensitive" or "dangerous" permission?
**A:** Google classifies permissions that directly impact user privacy or device operation as "dangerous" (runtime) permissions. Examples include `READ_SMS`, `ACCESS_FINE_LOCATION`, `CAMERA`, and `RECORD_AUDIO`. These require explicit runtime consent from the user.

### Q23: Why do accessibility permissions require extreme scrutiny?
**A:** `BIND_ACCESSIBILITY_SERVICE` is designed for assistive technologies (such as TalkBack screen readers for visually impaired users). However, it grants complete control over the UI: the app can read text displayed in any application (including passwords and OTPs), detect keystrokes, and simulate touch gestures. Modern Android banking trojans abuse accessibility services to grant themselves further permissions and execute unauthorized financial transactions.

### Q24: Why is permission context critical?
**A:** Permissions cannot be evaluated in isolation. For example, `ACCESS_FINE_LOCATION` is legitimate and necessary for a ride-sharing or navigation app (Uber, Google Maps), but highly suspicious for a calculator, flashlight, or photo editing app. Users must evaluate whether the requested permission aligns with the app's core functionality.

### Q25: Why can permissions alone never prove an application is malware?
**A:** Many legitimate applications require dangerous permissions for valid features (e.g., WhatsApp needs `CAMERA`, `RECORD_AUDIO`, and `READ_CONTACTS`). Conversely, malware can operate with minimal permissions or exploit unpatched OS vulnerabilities. Therefore, permissions indicate potential attack surface and exposure, not definitive malice.

---

## Section E: Security and Privacy Safeguards

### Q26: Why does the platform never open or fetch submitted URLs?
**A:** Opening an untrusted URL exposes the analysis server to remote code execution, client-side browser exploits, tracking pixels, and server IP leakage. Furthermore, querying threat actor infrastructure alerts the attacker that their domain is under investigation, prompting them to change hosts. Structural offline inspection completely eliminates these risks.

### Q27: What is DNS resolution, and why is it avoided here?
**A:** DNS (Domain Name System) resolution translates human-readable hostnames into numeric IP addresses. Even without making an HTTP connection, resolving a domain sends a DNS query to upstream nameservers. Threat actors monitoring authoritative DNS logs can detect these queries and identify that security researchers or users are investigating their domain. The platform avoids DNS lookups entirely.

### Q28: What is Cross-Site Scripting (XSS) and how does the frontend prevent it?
**A:** XSS occurs when untrusted user input is rendered into the DOM without sanitization, allowing an attacker to execute malicious JavaScript in the victim's browser. Our frontend prevents XSS by avoiding `innerHTML` when displaying user-submitted text or analysis results; instead, it uses `document.createElement()` and sets text content via the safe `.textContent` property, ensuring all characters are treated strictly as plain text.

### Q29: Why should submitted request bodies not be logged?
**A:** Users may inadvertently submit sensitive personal information, such as real phone numbers, names, or financial amounts contained in scam text messages. Logging request bodies to server log files or console streams would create an unencrypted, persistent record of confidential data, violating user privacy principles.

### Q30: How does the application handle submitted data in memory?
**A:** Payloads are bound to temporary Java DTO objects during the HTTP POST request. After the controller returns the response, the DTOs go out of scope and become eligible for JVM garbage collection. No records are written to databases, temporary files, or caches.

### Q31: How does the frontend handle submitted input after analysis?
**A:** Immediately after sending the analysis request, the JavaScript application clears the textarea and input fields. This ensures that sensitive text does not linger on the screen if the user walks away from their workstation or shares their display.

---

## Section F: Testing and Evaluation

### Q32: What is JUnit 5 and how is it used in this project?
**A:** JUnit 5 is the standard testing framework for modern Java applications. It consists of the JUnit Platform, Jupiter engine, and Vintage engine. In this project, JUnit 5 is used to write comprehensive unit and integration tests covering rule detection, Levenshtein distance calculations, scoring boundary limits, MockMvc REST controller endpoints, and security/privacy constraints.

### Q33: Define Precision, Recall, and False Positive Rate (FPR).
**A:**
- **Precision:** The proportion of predicted suspicious samples that were truly malicious:
  $$\text{Precision} = \frac{TP}{TP + FP}$$
- **Recall (Sensitivity):** The proportion of actual malicious samples that the model successfully caught:
  $$\text{Recall} = \frac{TP}{TP + FN}$$
- **False Positive Rate (FPR):** The proportion of benign samples that were incorrectly flagged as suspicious:
  $$\text{FPR} = \frac{FP}{FP + TN}$$

### Q34: What are TP, TN, FP, and FN in the context of this platform?
**A:**
- **True Positive (TP):** A scam message or phishing link correctly classified as Medium or High risk.
- **True Negative (TN):** A benign message or legitimate link correctly classified as Low risk.
- **False Positive (FP):** A legitimate message or link incorrectly classified as Medium or High risk.
- **False Negative (FN):** A malicious scam message or link incorrectly classified as Low risk.

### Q35: How is response time measured in the evaluation harness?
**A:** `EvaluationRunner` records high-resolution wall-clock timestamps using `System.nanoTime()` immediately before and after invoking `analyze()`. The elapsed time is converted to milliseconds. Across our 24 evaluation samples, the mean processing time was 1.42 ms, well below the 1,000 ms requirement.

### Q36: What are the fundamental limitations of a rule-based detection system?
**A:** Rule-based systems rely on predefined patterns, keyword lists, and regular expressions. They excel at transparency, speed, and explainability, but cannot generalize to completely novel attack phrasings or obfuscation techniques that have not yet been codified into rules. Combining rule-based systems with machine learning is often the next step in enterprise deployments.

---

## Section G: Advanced Technical & Architectural Questions

### Q37: How does Spring Boot manage static resources like HTML and CSS?
**A:** Spring Boot's resource handler automatically maps classpath directories under `src/main/resources/static/` to the root context path (`/`). When a user accesses `http://localhost:8080/`, Spring's `WelcomePageHandlerMapping` serves `index.html`, and relative paths serve `css/style.css` and `js/app.js` with appropriate MIME types.

### Q38: What HTTP status codes are used by the platform's REST endpoints?
**A:**
- `200 OK`: Request was valid and analysis was completed successfully.
- `400 Bad Request`: Client submitted invalid data (e.g., empty text, blank URL, or payload exceeding size limits).
- `500 Internal Server Error`: An unexpected internal server error occurred (handled by `GlobalExceptionHandler`).

### Q39: What validation annotations are applied to request models?
**A:** We use Jakarta Bean Validation annotations:
- `@NotBlank(message = "Message text cannot be empty or blank")`
- `@Size(max = 10000, message = "Message text cannot exceed 10000 characters")`
- `@Size(max = 2048, message = "URL cannot exceed 2048 characters")`

### Q40: What happens if `rules.json` contains invalid JSON or cannot be read?
**A:** `RuleConfiguration` wraps file loading in a `try-catch` block. If parsing fails, it logs an error and throws an `InvalidConfigurationException`, preventing the application from starting in an undefined state.

### Q41: Why did you not use a database like MySQL or MongoDB?
**A:** A database is unnecessary because the platform's design explicitly requires zero persistence of user inputs to safeguard privacy. Configuration rules and permission catalogs are read-only and loaded from static JSON files at boot time. Introducing a database would add operational complexity, maintenance overhead, and a privacy liability without functional benefit.

### Q42: How does the application support configuration updates without code changes?
**A:** Because all scoring weights, regex patterns, brand lists, and shortener domains are defined in `rules.json` and `permissions.json`, an administrator can adjust weights or add new detection keywords simply by modifying the JSON files and restarting the application, with zero Java code modification or recompilation required.
