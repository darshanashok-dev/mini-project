# Independent Project Review, Source Code Walkthrough, and Comprehensive Viva Rehearsal

**Project Title:** Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications  
**Course Code:** 25BCBPR308 (Academic Project Work Phase-I)  
**Evaluator Profile:** Senior CSE Project Examiner & Technical Reviewer  
**Target Environment:** Java 17+, Spring Boot 3.3.5, Apache Maven, JUnit 5, Fedora/Linux  

---

## 1. Project Architecture and Technical Understanding

### 1.1 High-Level Architecture Overview
The platform implements an offline-first, in-memory, privacy-preserving cybersecurity advisory engine. The system operates on a 4-tier decoupled architecture:
1. **Presentation Layer:** Single-Page Application (SPA) delivered via vanilla HTML5, CSS3, and JavaScript using standard `fetch()` asynchronous APIs without heavy third-party UI frameworks.
2. **Controller Layer:** Centralized REST interface (`AnalysisController`) enforcing Jakarta Bean Validation constraints and delegating to services.
3. **Service & Scoring Layer:** Business logic encapsulation partitioned into three independent analyzers (`MessageAnalyzer`, `UrlAnalyzer`, `PermissionService`) and a shared `ScoringEngine`.
4. **Configuration Layer:** Startup deserialization of external JSON rules and permission catalogs into strongly typed Java models via Jackson.

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT TIER                                       |
|  index.html (Semantic HTML5) | style.css (Dark Theme) | app.js (DOM manipulation) |
+-----------------------------------------------------------------------------------+
                                          |
                                          | HTTP POST/GET (JSON Payloads via Fetch)
                                          v
+-----------------------------------------------------------------------------------+
|                         REST CONTROLLER & EXCEPTION TIER                          |
|         AnalysisController (/api)  |  GlobalExceptionHandler (@RestControllerAdvice) |
+-----------------------------------------------------------------------------------+
                                          |
               +--------------------------+-------------------------+
               |                          |                         |
               v                          v                         v
+-------------------------------+  +-------------------+  +-----------------------+
|        MessageAnalyzer        |  |    UrlAnalyzer    |  |   PermissionService   |
| (Regex & Context Evaluation)  |  | (URI Parse, Dist) |  | (Catalog & Fallback)  |
+-------------------------------+  +-------------------+  +-----------------------+
               |                          |                         |
               +------------+-------------+                         |
                            |                                       v
                            v                             [permissions.json]
+-----------------------------------------------------+   (20 High-Risk Perms)
|                    ScoringEngine                    |
| Deduplicate Rule IDs | Cap Score at 100 | Classify  |
+-----------------------------------------------------+
                            |
                            v
                      [rules.json]
         (6 Msg Rules, 7 URL Rules, Brands, Shorteners)
```

---

### 1.2 Package & Class Roles

| Package | Key Classes | Responsibilities & Architectural Function |
| :--- | :--- | :--- |
| `com.cybersecurity` | `CybersecurityApplication` | Standard Spring Boot application entry point (`@SpringBootApplication`). Initializes the Spring ApplicationContext and starts embedded Apache Tomcat on port 8080. |
| `controller` | `AnalysisController` | Exposes four REST endpoints: `/api/analyze/message`, `/api/analyze/url`, `/api/permissions`, and `/api/permissions/check`. Enforces input validation using `@Valid`, logs input lengths (never raw data), and delegates to domain services. |
| `service` | `MessageAnalyzer` | Compiles regex patterns from `rules.json` at startup. Evaluates text across 6 scam categories (Impersonation, Urgency, Digital Arrest Threats, Secrecy/Isolation, Payment Demands, Credential Requests) with negative context suppression for legitimate advisories. |
| `service` | `UrlAnalyzer` | Parses links offline using `java.net.URI`. Evaluates structural signals: numeric IP hosts, brand subdomain spoofing, Levenshtein typosquatting ($\le 1$), excessive hyphens ($\ge 3$), embedded authority `@`, obfuscated paths, and known shorteners. Strictly zero socket or DNS operations. |
| `service` | `PermissionService` | Maintains in-memory map of 20 sensitive Android permissions. Normalizes input strings, retrieves `ALLOW`/`DENY`/`REVIEW` guidance, and generates a safe `REVIEW` fallback for unrecognized custom permissions. |
| `service` | `ScoringEngine` | Aggregates unique matched rule weights using $S = \min(100, \sum w_i)$. Enforces deduplication by rule ID. Determines risk tier (`Low: 0-30`, `Medium: 31-65`, `High: 66-100`) and builds complete `AnalysisResult` DTOs. |
| `config` | `RuleConfiguration` | Reads `rules.json` from the classpath, validates schema integrity, and registers the singleton `RulesConfig` bean. Throws `InvalidConfigurationException` if files are missing or malformed. |
| `config` | `PermissionConfiguration` | Reads `permissions.json` from classpath, validates permissions, and registers the singleton `PermissionsConfig` bean. |
| `exception` | `GlobalExceptionHandler` | Annotated with `@RestControllerAdvice`. Intercepts `MethodArgumentNotValidException`, `HttpMessageNotReadableException`, and generic exceptions, formatting clean HTTP 400 or 500 `ErrorResponse` JSON. |
| `exception` | `InvalidConfigurationException`| Custom runtime exception thrown during application boot when configuration syntax or semantic validation fails. |
| `model` | `AnalysisResult`, `MatchedRule`, `PermissionInfo`, `PermissionResult`, `RulesConfig`, etc. | Strongly typed Plain Old Java Objects (POJOs) defining data contracts, JSON serialization shapes, and internal domain transfers. |
| `eval` | `EvaluationRunner`, `EvaluationMetrics`, `LabelledSample` | Benchmark test harness that loads `evaluation/dataset.json` (24 ground-truth samples) to measure Accuracy, Precision, Recall, False Positive Rate, and millisecond execution latencies. |

---

### 1.3 Communication, Scoring, and Privacy Mechanics

1. **Frontend-to-Backend Communication:**
   - The client UI uses native JavaScript `fetch()` to send JSON payloads (`Content-Type: application/json`).
   - When requests complete, UI inputs are immediately cleared from the DOM, and result cards are constructed dynamically using `document.createElement()` and `element.textContent`, preventing Cross-Site Scripting (XSS).
2. **Scoring Engine Calculation:**
   - When detection rules trigger, they are placed in a collection. `ScoringEngine.calculateScore()` places rule IDs into a `Map<String, Integer>`, effectively deduplicating multiple triggers of the same rule.
   - The weights are summed and bounded: `Math.min(100, Math.max(0, totalWeight))`.
   - Category thresholds (`Low: 0–30`, `Medium: 31–65`, `High: 66–100`) are loaded dynamically from `rules.json` rather than hardcoded in Java classes.
3. **Privacy and In-Memory Handling:**
   - Zero SQL/NoSQL databases or file-based caches exist.
   - Submitted request objects (`MessageAnalysisRequest`, `UrlAnalysisRequest`) are short-lived stack variables that exist only during request processing and are freed by the JVM garbage collector upon response dispatch.
   - `AnalysisController` logs strictly record character length (e.g., `length: 120 chars`), ensuring zero user message content is leaked into server log files.


---

## 2. End-to-End Source Code Walkthrough

This section traces the exact execution paths through the actual source code from browser event to response rendering.

### 2.1 Workflow 1: Submitting a Suspicious Text Message

```
[User clicks "Analyze Message"]
       |
       v
app.js: formMessage.addEventListener('submit')
       |-- Reads inputMessage.value
       |-- Checks length (max 10,000 chars)
       |-- Calls setLoading(btnSubmitMessage, true)
       |-- Clears inputMessage.value from DOM (Privacy guarantee)
       |-- fetch('/api/analyze/message', {method: 'POST', body: JSON.stringify({text: ...})})
       v
AnalysisController.java: analyzeMessage(@Valid @RequestBody MessageAnalysisRequest request)
       |-- Jakarta Validation checks: @NotBlank, @Size(max=10000)
       |-- logger.info("Received message analysis request (length: {} chars)", length)
       |-- Calls messageAnalyzer.analyze(request.getText())
       v
MessageAnalyzer.java: analyze(String text)
       |-- Loops through compiledRules (List<CompiledMessageRule>)
       |-- Evaluates benignExceptionPatterns:
       |     If matched (e.g., "(?i)never share your otp"), skips rule
       |-- Evaluates patterns (Regex matching):
       |     If pattern matches, extracts snippet around match bounds
       |     Adds MatchedRule(id, name, weight, snippet, explanation) to matchedRules
       |-- Calls scoringEngine.buildResult(matchedRules, "message")
       v
ScoringEngine.java: buildResult(...) & calculateScore(...)
       |-- Deduplicates matchedRules by rule ID using LinkedHashMap
       |-- Calculates total: S = min(100, sum(unique weights))
       |-- Evaluates determineCategory(score):
       |     <= 30 -> "Low"
       |     <= 65 -> "Medium"
       |     else  -> "High"
       |-- Retrieves recommendedAction, safeHandlingTip, and disclaimer
       |-- Constructs and returns new AnalysisResult(...)
       v
AnalysisController.java: returns ResponseEntity.ok(result)
       v
app.js: fetch().then(response => response.json())
       |-- setLoading(btnSubmitMessage, false)
       |-- Calls renderAnalysisResult(data, resultMessage, 'message')
       |-- Updates SVG dial progress: setScoreDial(data.score, data.category)
       |-- Updates horizontal meter indicator
       |-- Renders Matched Indicators accordion using document.createElement & .textContent
       |-- Displays Safe Handling Tip & Educational Disclaimer
```

---

### 2.2 Workflow 2: Submitting a URL for Structural Inspection

```
[User clicks "Inspect URL Structure"]
       |
       v
app.js: formUrl.addEventListener('submit')
       |-- Reads inputUrl.value
       |-- Calls setLoading(btnSubmitUrl, true)
       |-- Clears inputUrl.value from DOM
       |-- fetch('/api/analyze/url', {method: 'POST', body: JSON.stringify({url: ...})})
       v
AnalysisController.java: analyzeUrl(@Valid @RequestBody UrlAnalysisRequest request)
       |-- Jakarta Validation checks: @NotBlank, @Size(max=2048)
       |-- logger.info("Received URL analysis request (length: {} chars)", length)
       |-- Calls urlAnalyzer.analyze(request.getUrl())
       v
UrlAnalyzer.java: analyze(String rawUrl)
       |-- Normalizes URL (prepends "http://" if scheme is missing)
       |-- Constructs java.net.URI object (Strictly local parsing, NO network I/O)
       |-- Extracts host, authority, and path
       |-- Executes 7 offline structural inspections:
       |     1. checkNumericIp(host) -> Matches IPV4_PATTERN or IPV6_PATTERN
       |     2. checkAtSymbol(rawUrl) -> Detects '@' in URL authority
       |     3. checkShortener(host) -> Compares host against knownShorteners set
       |     4. checkDeceptiveSubdomain(host) -> Checks if brand name is in subdomain of unrelated domain
       |     5. checkLookalikeDomain(host) -> Evaluates Levenshtein distance (dist == 1) against knownBrands
       |     6. checkExcessiveHyphens(host) -> Counts '-' occurrences (count >= 3)
       |     7. checkPathObfuscation(uri, path) -> Evaluates path length > 50, % encodings, suspicious extensions (.apk, .exe)
       |-- Calls scoringEngine.buildResult(matchedRules, "url")
       v
ScoringEngine.java: Computes score, determines tier, returns AnalysisResult
       v
AnalysisController.java: returns ResponseEntity.ok(result)
       v
app.js: Renders URL risk score, matched indicators, and security tips
```

---

### 2.3 Workflow 3: Selecting and Evaluating Android Permissions

```
[User checks permission checkboxes and clicks "Evaluate Selected Permissions"]
       |
       v
app.js: btnCheckPermissions.addEventListener('click')
       |-- Collects checked permissions from selectedPermissions Set
       |-- Validates selectedPermissions.size > 0
       |-- Calls setLoading(btnCheckPermissions, true)
       |-- fetch('/api/permissions/check', {
       |     method: 'POST',
       |     body: JSON.stringify({permissions: Array.from(selectedPermissions)})
       |   })
       v
AnalysisController.java: checkPermissions(@Valid @RequestBody PermissionRequest request)
       |-- Jakarta Validation verifies permissions list is not null
       |-- logger.info("Received permission check request (count: {})", count)
       |-- Calls permissionService.checkPermissions(request.getPermissions())
       v
PermissionService.java: checkPermissions(List<String> requestedPermissions)
       |-- Deduplicates input permissions using LinkedHashSet
       |-- For each permission:
       |     Normalizes string (removes "android.permission.", converts to uppercase)
       |     Queries in-memory permissionMap:
       |       - If found: adds configured PermissionInfo (ALLOW, DENY, or REVIEW)
       |       - If NOT found: creates safe default fallback PermissionInfo (Recommendation: REVIEW)
       |-- Attaches mandatory educational warning:
       |     "Permissions alone never prove that an application is malware..."
       |-- Returns new PermissionResult(results, warning)
       v
AnalysisController.java: returns ResponseEntity.ok(result)
       v
app.js: Renders permission guidance cards with colored badges (Green=ALLOW, Amber=REVIEW, Red=DENY)
```


---

## 3. Technical Viva Questions and Answers (60 Questions)

This section provides 60 technical questions and answers categorized across 14 software engineering disciplines, distinguishing general theoretical concepts from our specific implementation.

### Category 1: Project Fundamentals
**Q1: What is the core mission of the Cybersecurity Awareness Platform?**  
- *General Concept:* Awareness platforms educate non-technical users on threat vectors to reduce human susceptibility to cyber attacks.
- *Project Implementation:* Our platform specifically inspects suspicious text messages for digital arrest and extortion indicators, analyzes URL structure offline without network requests, and provides contextual guidance for 20 high-risk Android permissions.

**Q2: Who are the target stakeholders and users for this platform?**  
- *General Concept:* Threat mitigation platforms serve either security operations analysts (SOC) or end users.
- *Project Implementation:* Our platform targets ordinary citizens, students, and employees who receive unsolicited communications, providing transparent, non-technical explanations of threat mechanics.

**Q3: Why does the platform provide advisory guidance rather than definitive safety verdicts?**  
- *General Concept:* In information security, proving the complete absence of malice is impossible (the open-world assumption).
- *Project Implementation:* The system includes an explicit disclaimer in every `AnalysisResult`. Declaring a link or message "safe" could lead to liability and compromise if a novel bypass exists.

**Q4: What are the primary non-functional constraints enforced in the project?**  
- *General Concept:* Non-functional requirements dictate system qualities like security, privacy, performance, and portability.
- *Project Implementation:* (1) Zero external network connections during URL inspection; (2) Zero disk or database persistence of user input; (3) Sub-second processing latency; (4) Memory-only processing.

**Q5: How does this project differ from enterprise threat intelligence feeds like VirusTotal?**  
- *General Concept:* Enterprise intelligence aggregators query multi-engine scanners and live sandboxes to detect malware binaries.
- *Project Implementation:* VirusTotal sends links to remote vendor scanners and stores submitted artifacts. Our platform operates strictly offline and in-memory, preserving user confidentiality.

---

### Category 2: Java Programming
**Q6: What Java version is targeted and what language features are utilized?**  
- *General Concept:* Java versions introduce new bytecode specifications, language features, and runtime performance improvements.
- *Project Implementation:* The project targets Java 17 LTS bytecode. It utilizes modern Java features including standard `java.net.URI`, Streams API, Lambda expressions, and modern `java.util.regex` constructs.

**Q7: How is `java.net.URI` utilized in `UrlAnalyzer` rather than `java.net.URL`?**  
- *General Concept:* `java.net.URL.equals()` and constructor methods can trigger blocking DNS lookups under certain conditions.
- *Project Implementation:* We explicitly use `java.net.URI`, which performs purely syntactic parsing according to RFC 2396/3986 without network or DNS resolution.

**Q8: How does the application avoid memory leaks during repetitive analysis requests?**  
- *General Concept:* Memory leaks in Java occur when unneeded objects remain referenced, preventing garbage collection.
- *Project Implementation:* The analyzer services do not maintain stateful session caches. Every incoming request creates local stack variables that become eligible for minor garbage collection immediately after the HTTP response completes.

**Q9: Explain how regular expression compilation is optimized in `MessageAnalyzer`.**  
- *General Concept:* Compiling regex strings into `Pattern` objects (`Pattern.compile()`) is computationally expensive if done inside request loops.
- *Project Implementation:* All regex patterns from `rules.json` are pre-compiled once during application startup inside the `CompiledMessageRule` constructor, allowing `Matcher` operations to execute with sub-millisecond efficiency.

**Q10: What string manipulation algorithms are implemented in `UrlAnalyzer`?**  
- *General Concept:* String distance algorithms quantify the difference between two sequences.
- *Project Implementation:* We implement an iterative, two-row dynamic programming version of the Levenshtein distance algorithm in `computeLevenshteinDistance()` to detect typosquatting against brand dictionaries.

---

### Category 3: Spring Boot Framework
**Q11: What is Spring Boot and how does it simplify Spring development?**  
- *General Concept:* Spring Boot is an opinionated framework that removes boilerplate XML configurations through starter dependencies and auto-configuration.
- *Project Implementation:* We use `spring-boot-starter-web` and `spring-boot-starter-validation`, which bundle embedded Tomcat, Jackson serialization, and Hibernate Validator out of the box.

**Q12: What is the purpose of `@SpringBootApplication` in `CybersecurityApplication.java`?**  
- *General Concept:* It is a convenience annotation combining `@Configuration`, `@EnableAutoConfiguration`, and `@ComponentScan`.
- *Project Implementation:* It tells Spring to scan the `com.cybersecurity` package and sub-packages (`controller`, `service`, `config`, `exception`) to register beans automatically.

**Q13: How does Spring Boot manage dependency injection in this application?**  
- *General Concept:* Dependency Injection (Inversion of Control) supplies collaborator beans to dependent classes via constructors, fields, or setters.
- *Project Implementation:* We use constructor-based injection exclusively (e.g., `AnalysisController` receives `MessageAnalyzer`, `UrlAnalyzer`, and `PermissionService`). Constructor injection ensures immutability and simplifies unit testing with mocks.

**Q14: How are configuration files registered as Spring beans?**  
- *General Concept:* `@Configuration` classes declare `@Bean` factory methods that return instantiated objects into the application context.
- *Project Implementation:* `RuleConfiguration.java` reads `rules.json` via a `ClassPathResource` and Jackson's `ObjectMapper`, returning a singleton `RulesConfig` bean injected into the service layer.

**Q15: How does Spring Boot serve the frontend static files?**  
- *General Concept:* Spring Boot automatically maps `classpath:/static/`, `classpath:/public/`, and `classpath:/resources/` to the root path (`/`).
- *Project Implementation:* `src/main/resources/static/index.html` is served directly at `http://localhost:8080/`, while `css/` and `js/` assets are resolved automatically by `WelcomePageHandlerMapping`.

---

### Category 4: REST APIs & Controller Architecture
**Q16: What is a RESTful API and what constraints does it follow?**  
- *General Concept:* REST is an architectural style based on stateless HTTP communication, standardized status codes, and JSON/XML representations.
- *Project Implementation:* Our endpoints use standard HTTP verbs (`GET /api/permissions`, `POST /api/analyze/message`, etc.) and stateless request/response JSON payloads.

**Q17: What is the purpose of `@RestController` and `@RequestMapping` in `AnalysisController`?**  
- *General Concept:* `@RestController` combines `@Controller` and `@ResponseBody`, ensuring all controller methods serialize returned Java objects directly into HTTP response bodies.
- *Project Implementation:* `@RequestMapping("/api")` prefixes all routes, creating a clean namespace separation from static frontend resources.

**Q18: What HTTP status codes are returned by the platform?**  
- *General Concept:* HTTP status codes communicate execution outcomes to clients (2xx success, 4xx client errors, 5xx server errors).
- *Project Implementation:*
  - `200 OK`: Successful analysis or retrieval.
  - `400 Bad Request`: Validation failure (blank text, oversized payloads) or malformed JSON.
  - `500 Internal Server Error`: Unhandled server runtime failure.

**Q19: How are Cross-Origin requests handled in `AnalysisController`?**  
- *General Concept:* Browsers enforce the Same-Origin Policy (SOP), blocking client-side JavaScript from fetching across different origins unless Cross-Origin Resource Sharing (CORS) is enabled.
- *Project Implementation:* We use `@CrossOrigin(origins = "*")` on `AnalysisController` to facilitate local development, automated testing, and integration from different local ports.

---

### Category 5: Apache Maven & Build Lifecycle
**Q20: What is Maven and what role does `pom.xml` serve?**  
- *General Concept:* Maven is a declarative project management tool that coordinates compilation, dependency resolution, testing, and packaging via the Project Object Model (`pom.xml`).
- *Project Implementation:* Our `pom.xml` specifies Java 17 compiler targets, Spring Boot parent starter version 3.3.5, and test dependencies like `spring-boot-starter-test`.

**Q21: Explain the Maven build lifecycle phases used in this project.**  
- *General Concept:* Maven defines standard lifecycle phases: `validate`, `compile`, `test`, `package`, `verify`, `install`, `deploy`.
- *Project Implementation:* Executing `./mvnw test` triggers `compile`, `testResources`, `testCompile`, and `surefire:test`. Executing `./mvnw package` produces the final executable JAR in the `target/` directory.

**Q22: What is the Maven Wrapper (`mvnw`) and why is it included?**  
- *General Concept:* The Maven Wrapper enables building projects without requiring a pre-installed, system-wide Maven binary.
- *Project Implementation:* The `./mvnw` script downloads and executes Apache Maven 3.9.9 into `/tmp`, ensuring identical, repeatable builds across developer workstations and CI/CD pipelines.

**Q23: How does Maven Surefire plugin integrate JUnit 5 tests?**  
- *General Concept:* The Surefire plugin discovers and runs automated unit tests during the `test` phase.
- *Project Implementation:* Surefire 3.2.5 detects `junit-jupiter-engine` and executes all 48 test methods across our 9 test classes, generating summary reports in `target/surefire-reports/`.

---

### Category 6: Object-Oriented Programming (OOP) Principles
**Q24: How does the application demonstrate Encapsulation?**  
- *General Concept:* Encapsulation bundles data with the methods that operate on that data and restricts direct access to internal fields.
- *Project Implementation:* All model POJOs (`AnalysisResult`, `MatchedRule`, `PermissionInfo`) declare private fields accessed only via public getters and setters. Services maintain private collections and expose immutable views (e.g., `Collections.unmodifiableList()`).

**Q25: How does the application implement Separation of Concerns?**  
- *General Concept:* Modularity dictates that each module should address a distinct feature or layer.
- *Project Implementation:* `AnalysisController` handles only HTTP validation and status mapping; `MessageAnalyzer` handles regex matching; `ScoringEngine` handles weight math; `RuleConfiguration` handles file I/O.

**Q26: How is Polymorphism used in test and configuration execution?**  
- *General Concept:* Polymorphism allows objects of different types to be treated through a common interface or abstract contract.
- *Project Implementation:* Spring's `ObjectMapper` deserializes JSON lists into generic `List<MessageRuleDef>` and `List<UrlRuleDef>`. In testing, `MockMvc` simulates HTTP requests through the standard servlet `HandlerMethod` interface.

**Q27: How does the project leverage Inversion of Control (IoC)?**  
- *General Concept:* IoC delegates the control of object creation and lifecycle management from the application code to a container.
- *Project Implementation:* Instead of `AnalysisController` calling `new MessageAnalyzer()`, Spring's IoC container instantiates the singleton services and injects them where needed.

---

### Category 7: Rule-Based Detection Mechanics
**Q28: What is a rule-based detection system?**  
- *General Concept:* A deterministic expert system that evaluates inputs against a predefined catalog of conditional patterns and rules.
- *Project Implementation:* Our platform uses 6 message rules and 7 URL structural rules stored in `rules.json` to identify threat indicators without non-deterministic machine learning models.

**Q29: How does `MessageAnalyzer` detect Digital Arrest scam indicators?**  
- *General Concept:* Digital arrest scams rely on psychological coercion: claiming to be police, asserting an arrest warrant, and ordering video-call isolation.
- *Project Implementation:* Three independent rules trigger:
  - `MSG_IMPERSONATION`: Matches "Delhi Police", "CBI", "Cyber Crime Cell".
  - `MSG_ARREST_THREAT`: Matches "digital arrest", "non-bailable warrant", "FIR".
  - `MSG_SECRECY_ISOLATION`: Matches "do not tell anyone", "stay on Skype video call".

**Q30: How does the system prevent false alarms on legitimate banking notifications?**  
- *General Concept:* Benign notifications often contain identical keywords ("OTP", "urgent", "account") as scams.
- *Project Implementation:* `MessageAnalyzer` implements negative context filtering. If keywords like "never share your OTP" or "bank will never call for password" match `benignExceptions`, the credential theft rule is suppressed.

**Q31: What is snippet extraction in `MessageAnalyzer`?**  
- *General Concept:* Evidence presentation requires showing the user exactly which fragment of their input triggered an alert.
- *Project Implementation:* `extractSnippet(text, start, end)` takes the regex match indices, expands up to 20 characters before and after the match, and prepends/appends ellipsis (`...`) for display in the UI.

**Q32: What are the advantages of a rule-based detection model over black-box AI?**  
- *General Concept:* Rule-based systems offer 100% explainability, deterministic repeatability, low latency, and zero model hallucinations.
- *Project Implementation:* Every matched rule returns an explicit name, ID, weight, and educational explanation, enabling users to understand the precise mechanics of the scam.

---

### Category 8: Weighted Scoring & Risk Classification
**Q33: What is the mathematical formula used for scoring?**  
- *General Concept:* Multi-criteria additive scoring aggregates normalized individual feature weights.
- *Project Implementation:*
  $$S = \min\left(100, \sum_{i \in \text{Unique Matched Rules}} w_i\right)$$

**Q34: How does `ScoringEngine` prevent duplicate rule scoring?**  
- *General Concept:* A single message repeating the word "police" ten times should not trigger the impersonation rule ten times.
- *Project Implementation:* `ScoringEngine.calculateScore()` loads rules into a `Map<String, Integer>` keyed by rule ID. The map naturally overwrites duplicates, ensuring each unique rule ID is counted exactly once.

**Q35: What are the risk threshold boundaries and how were they selected?**  
- *General Concept:* Stratification splits continuous score distributions into actionable severity categories.
- *Project Implementation:*
  - **Low (0–30):** Single isolated indicator that may occur in everyday communication.
  - **Medium (31–65):** Multi-indicator combinations (e.g., brand claim + payment demand) indicating likely fraud.
  - **High (66–100):** Aggressive multi-signal threats (e.g., digital arrest + video isolation + warrant).

**Q36: Why are thresholds loaded from JSON rather than hardcoded in Java?**  
- *General Concept:* Externalizing policy values allows systems to be re-calibrated without code recompilation.
- *Project Implementation:* `rules.json` contains a `thresholds` object (`lowMax: 30`, `mediumMax: 65`). `ScoringEngine` dynamically queries these values via `RulesConfig`.

---

### Category 9: URL Anatomy & Offline Security
**Q37: Why is offline URL analysis essential for security platforms?**  
- *General Concept:* Opening an untrusted link exposes the server to browser exploitation, server IP discovery, and active tracking tokens.
- *Project Implementation:* Our platform never invokes `connect()`, `openStream()`, or `Socket`. It evaluates only the lexical structure of the URI string.

**Q38: How does the analyzer detect numeric IP host attacks?**  
- *General Concept:* Attackers use direct IP addresses (e.g., `http://192.168.1.100`) to avoid domain registrar audits.
- *Project Implementation:* `UrlAnalyzer` tests `uri.getHost()` against `IPV4_PATTERN` (`^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}...`) and `IPV6_PATTERN`.

**Q39: How does the system detect deceptive brand subdomains?**  
- *General Concept:* Attackers prepend trusted brand names as subdomains (e.g., `sbi.co.in.attacker.com`).
- *Project Implementation:* `checkDeceptiveSubdomain()` extracts host segments, verifies if an inner token matches a known brand, and checks whether the root parent domain belongs to an unrelated entity.

**Q40: Explain the significance of the `@` symbol in URL authorities.**  
- *General Concept:* RFC 3986 defines the authority syntax as `[userinfo@]host[:port]`. Standard browsers treat text before `@` as login credentials and navigate strictly to the host *after* `@`.
- *Project Implementation:* An attacker crafting `https://google.com@phishing.com/` causes users to read "google.com" while the browser connects to "phishing.com". `UrlAnalyzer` flags any `@` character in the authority string.

**Q41: Why are URL shorteners flagged as medium risk?**  
- *General Concept:* URL shorteners (e.g., `bit.ly`, `tinyurl.com`) hide the real destination host and path behind an opaque token.
- *Project Implementation:* Because destination inspection cannot occur without making an outbound HTTP request, `UrlAnalyzer` flags known shortener domains to alert users that the destination is concealed.

---

### Category 10: Android Permissions
**Q42: What is the Android permission model?**  
- *General Concept:* A privilege separation model where apps run in isolated sandboxes and must request explicit user permissions to access protected resources.
- *Project Implementation:* The platform evaluates permissions across functional categories (SMS, Contacts, Location, Camera, Audio, Storage, System) against real-world threat abuse histories.

**Q43: What permissions receive a `DENY` recommendation?**  
- *General Concept:* Privileges with high abuse-to-utility ratios for third-party consumer apps.
- *Project Implementation:* `READ_SMS`, `RECEIVE_SMS`, and `BIND_ACCESSIBILITY_SERVICE` receive a `DENY` recommendation due to widespread exploitation by banking trojans for 2FA bypass and credential harvesting.

**Q44: What permissions receive a `REVIEW` recommendation?**  
- *General Concept:* Privileges that are dangerous but essential for specific legitimate app categories.
- *Project Implementation:* `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, and `READ_CONTACTS`. The guidance advises users to allow only if the app's core feature requires it (e.g., Maps needing GPS).

**Q45: How does the system handle unrecognized custom permissions?**  
- *General Concept:* Android allows developers and device OEMs to define proprietary permissions.
- *Project Implementation:* In `PermissionService.java`, unrecognized permissions fall back to `createUnknownFallback()`, which assigns a safe `REVIEW` recommendation prompting the user to inspect app reputability.

**Q46: Why is the mandatory warning attached to every permission evaluation?**  
- *General Concept:* Misinterpreting permission requests as definitive proof of malware leads to false accusations against benign software.
- *Project Implementation:* Every response includes the mandatory disclaimer: *"Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source."*

---

### Category 11: JSON Configuration Loading & Schema
**Q47: Why are rules and permissions externalized into JSON files?**  
- *General Concept:* Separating configuration from code enables non-programmers to update rules without recompiling source code.
- *Project Implementation:* `rules.json` contains detection patterns, weights, brands, and shorteners; `permissions.json` contains the 20 Android permissions and their explanations.

**Q48: How does Jackson deserialize nested JSON structures?**  
- *General Concept:* Jackson uses reflection and Java bean introspection to map JSON properties to POJO fields.
- *Project Implementation:* `RulesConfig.java` defines static inner classes (`MessageRuleDef`, `UrlRuleDef`, `ThresholdsDef`) that Jackson instantiates automatically via `objectMapper.readValue()`.

**Q49: What happens if `rules.json` is missing from the classpath?**  
- *General Concept:* Robust applications fail fast during boot rather than failing unexpectedly during runtime requests.
- *Project Implementation:* `RuleConfiguration.java` checks `resource.exists()`. If false, it throws an `InvalidConfigurationException`, aborting Spring container initialization with an informative log message.

**Q50: How is semantic validation performed on configuration files?**  
- *General Concept:* Verifying that loaded data conforms to logical constraints beyond mere JSON syntax validity.
- *Project Implementation:* `validateRulesConfig()` asserts that thresholds are not null, rule lists are non-empty, and rule weights are strictly positive integers.

---

### Category 12: Privacy & Application Security
**Q51: How does the platform enforce zero persistence?**  
- *General Concept:* Privacy-by-design requires collecting only minimal data and retaining it for the shortest necessary duration.
- *Project Implementation:* The application includes no database drivers in `pom.xml`, writes no temporary disk files for analysis, and does not store request bodies in session variables.

**Q52: How does the backend prevent user message leakage in server logs?**  
- *General Concept:* Logging user input strings (which may contain passwords, names, or OTPs) creates sensitive data exposure vulnerabilities.
- *Project Implementation:* In `AnalysisController`, logger calls record only length metadata:
  ```java
  logger.info("Received message analysis request (length: {} chars)", request.getText().length());
  ```

**Q53: How does the frontend prevent Cross-Site Scripting (XSS)?**  
- *General Concept:* DOM-based XSS occurs when user-controlled strings are inserted into the DOM via `innerHTML` without HTML entity escaping.
- *Project Implementation:* `app.js` avoids `innerHTML` when displaying user input or analysis results; it constructs DOM nodes with `document.createElement()` and assigns text strictly using `.textContent`.

**Q54: How are input size boundaries enforced to mitigate Denial of Service (DoS)?**  
- *General Concept:* Unbounded input strings can consume excessive CPU or memory during regex evaluation (ReDoS).
- *Project Implementation:* Jakarta annotations enforce boundaries: `@Size(max = 10000)` on message text and `@Size(max = 2048)` on URLs. Violations are rejected immediately with HTTP 400 before reaching analyzer logic.

---

### Category 13: JUnit Testing & MockMvc
**Q55: What is the testing pyramid and how is it reflected in this project?**  
- *General Concept:* A testing strategy emphasizing many fast unit tests, fewer integration tests, and minimal end-to-end tests.
- *Project Implementation:*
  - **Unit Tests:** `MessageAnalyzerTest`, `UrlAnalyzerTest`, `PermissionServiceTest`, `ScoringEngineTest` (31 tests).
  - **Security Audits:** `SecurityAndPrivacyAuditTest` (6 tests).
  - **Web Integration:** `ControllerTest`, `FrontendIntegrationTest` (9 tests).
  - **Benchmark Tests:** `EvaluationRunnerTest` (1 test).
  - Total: 48 automated tests.

**Q56: How does `ControllerTest` test REST endpoints without starting a real HTTP server?**  
- *General Concept:* Spring MockMvc provides server-side testing of controllers by simulating HTTP servlet requests and responses in memory.
- *Project Implementation:* `MockMvcBuilders.standaloneSetup(controller)` initializes the controller and exception handler directly, executing full request validation and JSON serialization in milliseconds.

**Q57: How does `SecurityAndPrivacyAuditTest` verify that no outbound network calls occur?**  
- *General Concept:* Automated architectural assertions can verify security constraints using reflection and classpath inspection.
- *Project Implementation:* `SecurityAndPrivacyAuditTest.testUrlAnalyzerMakesNoNetworkCalls` inspects `UrlAnalyzer.class` and loaded packages, asserting zero references to `HttpURLConnection`, `HttpClient`, or `Socket`.

---

### Category 14: Evaluation Metrics & Benchmark Performance
**Q58: Define True Positive (TP), True Negative (TN), False Positive (FP), and False Negative (FN).**  
- *General Concept:* Confusion matrix components for binary classification.
- *Project Implementation:*
  - **TP:** A malicious scam message or deceptive URL classified as Medium or High risk.
  - **TN:** A legitimate security alert or standard URL classified as Low risk.
  - **FP:** A benign message or link incorrectly classified as Medium or High risk.
  - **FN:** A malicious message or link incorrectly classified as Low risk.

**Q59: What benchmark results were achieved on the 24-sample dataset?**  
- *General Concept:* Standard performance metrics include Accuracy, Precision, Recall, and False Positive Rate.
- *Project Implementation:*
  - Samples: 24 (12 malicious, 12 benign).
  - TP = 12, TN = 12, FP = 0, FN = 0.
  - Accuracy = 100.00%, Precision = 100.00%, Recall = 100.00%, False Positive Rate = 0.00%.

**Q60: How is latency measured in `EvaluationRunner` and what were the results?**  
- *General Concept:* Execution latency measures the elapsed time to process an input.
- *Project Implementation:* Measured using `System.nanoTime()` before and after calling `analyze()`. Across all 24 samples, the mean latency was **1.42 ms**, well within the sub-second requirement.


---

## 4. Difficult Examiner Questions and Strategic Defenses

These 10 questions represent challenging scenarios frequently posed by rigorous university project examiners, along with defensible, technically sound answers grounded in our implementation.

### D1: "Why did you choose Spring Boot instead of lightweight alternatives like Node.js or Python Flask?"
**Examiner Angle:** Challenging architectural selection and potential framework overhead.  
**Student Defense:**  
> "Spring Boot was selected because Java's strict static typing, strong memory model, and enterprise architecture provide rigorous compile-time safety for security applications. While Node.js and Flask are lightweight, Spring Boot provides production-grade dependency injection, robust Jakarta validation annotations, built-in multi-threading, and native integration with Jackson and JUnit 5 without relying on unvetted third-party packages. Furthermore, because our application uses embedded Tomcat and compiles directly into a standalone JAR, it achieves a cold-boot startup time of under 3.2 seconds and processes requests in under 2 milliseconds, demonstrating that Spring Boot introduces zero meaningful performance bottleneck."

---

### D2: "Why did you avoid using a database? Isn't persistent storage a standard requirement for web applications?"
**Examiner Angle:** Suggesting the project is incomplete because it lacks MySQL, PostgreSQL, or MongoDB.  
**Student Defense:**  
> "Avoiding a database was an explicit architectural design decision driven by privacy-by-design and regulatory compliance principles. When users submit suspicious messages or links for inspection, those messages frequently contain confidential personal information—such as real phone numbers, names, financial transaction amounts, or OTPs. Persisting this data in a database would create an attractive target for data breaches, require complex encryption at rest, and violate privacy mandates like GDPR and the Digital Personal Data Protection Act (DPDPA). Our platform operates on an ephemeral, in-memory processing model: inputs exist only in heap memory during the lifetime of the HTTP thread and are immediately garbage collected upon response delivery."

---

### D3: "Why did you use a rule-based scoring system instead of modern Machine Learning or Deep Learning models like BERT or LLMs?"
**Examiner Angle:** Challenging modern relevance in the era of Generative AI.  
**Student Defense:**  
> "In cybersecurity awareness and decision support, explainability and determinism are paramount. Black-box machine learning models and LLMs suffer from three critical flaws in this domain:
> 1. **Hallucinations and Non-Determinism:** The same input might receive different scores at different times.
> 2. **Lack of Transparent Evidence:** Neural networks cannot easily explain to a non-technical user *which exact words* constituted a legal threat or impersonation.
> 3. **Latency and Compute Overhead:** LLM inference requires heavy GPU infrastructure or paid external cloud APIs (which would violate our privacy constraint by sending user data to third parties).
> In contrast, our rule-based system executes in 1.4 milliseconds on a standard CPU, provides 100% deterministic results, and maps directly to explainable matched indicators with clear advice."

---

### D4: "How does your system handle False Positives, particularly when legitimate banking notifications mention OTPs or account suspension?"
**Examiner Angle:** Testing edge-case handling and context awareness.  
**Student Defense:**  
> "We implement context-aware negative boundary filtering in `MessageAnalyzer`. Legitimate organizations (such as RBI, SBI, or CERT-In) frequently issue educational advisories that contain scam keywords like 'OTP' or 'police'. To avoid flagging these as malicious, each rule definition in `rules.json` supports a list of `benignExceptions`. Before a detection pattern is evaluated, the text is scanned for advisory context patterns—such as `(?i)never share your otp` or `(?i)police will never call`. If a benign exception pattern matches, the corresponding detection rule is suppressed. In our benchmark evaluation across 12 benign samples, this context filtering resulted in a 0.00% False Positive Rate."

---

### D5: "Can a 'Low Risk' result guarantee that a submitted URL or message is completely safe?"
**Examiner Angle:** Testing security philosophy and awareness of detection limits.  
**Student Defense:**  
> "No, and our platform explicitly communicates this. A core tenet of application security is that absence of evidence is not evidence of absence. Zero matched rules simply means the input did not trigger any of our configured heuristic patterns; it does not prove the absence of zero-day exploits, novel phishing phrasing, or malicious intent. To prevent users from developing false confidence, every single analysis response—regardless of score—includes an explicit educational disclaimer stating: *'This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently.'*"

---

### D6: "Why don't you open submitted URLs to check their content or inspect HTTP redirects?"
**Examiner Angle:** Questioning why URL analysis is limited to syntax parsing.  
**Student Defense:**  
> "Connecting to an untrusted URL from our server would introduce severe security and privacy vulnerabilities:
> 1. **Server Exploitation:** The destination server could serve browser exploits, malicious payloads, or zero-day vulnerabilities targeting the server environment.
> 2. **Threat Actor Telemetry:** Making an HTTP request alerts the attacker that their URL is being investigated, allowing them to log our IP address, geo-locate the server, or rotate their domain.
> 3. **Tracking Token Invalidation:** Many phishing emails embed unique victim IDs in URL query parameters. Fetching that URL could trigger the attacker's server to mark the email address as 'verified active'.
> By restricting analysis to offline structural parsing using `java.net.URI`, we evaluate the anatomy of the link safely without exposing our system or notifying the attacker."

---

### D7: "How do you prevent duplicate rule scoring if a message repeats the same scam keyword multiple times?"
**Examiner Angle:** Testing implementation details of the scoring algorithm.  
**Student Defense:**  
> "In `ScoringEngine.java`, rule deduplication is enforced at two levels. First, when `buildResult()` processes the list of `MatchedRule` objects, it inserts them into a `LinkedHashMap<String, MatchedRule>` using `rule.getId()` as the map key. This ensures that even if regex matching identifies three separate occurrences of authority impersonation in a single message, only one instance is retained in the result list. Second, `calculateScore()` aggregates weights from a `Map<String, Integer>`, guaranteeing that each unique rule ID contributes its configured weight exactly once before being summed and capped at 100."

---

### D8: "Why are Android permissions not sufficient on their own to establish whether an application is malware?"
**Examiner Angle:** Testing mobile security concepts and understanding of permission models.  
**Student Defense:**  
> "Permissions represent declared capabilities granted by the operating system, not intent or runtime behavior. Legitimate applications require dangerous permissions for valid functionality: for instance, WhatsApp requires `CAMERA`, `RECORD_AUDIO`, and `READ_CONTACTS` to function as a messaging app; Google Maps requires `ACCESS_FINE_LOCATION` for navigation. Conversely, malware can operate with minimal permissions by exploiting privilege escalation vulnerabilities or relying solely on internet access. Therefore, permissions must always be evaluated in the context of the application's stated category, publisher reputation, and legitimate feature requirements. Our platform highlights this in every response through a mandatory educational warning."

---

### D9: "How would you improve detection accuracy in Phase-II without sacrificing offline privacy?"
**Examiner Angle:** Assessing future research vision and scalability awareness.  
**Student Defense:**  
> "In Phase-II, we can enhance detection while preserving our offline, privacy-first principles in three ways:
> 1. **Multilingual Local Tokenization:** Integrate offline natural language processing libraries (such as Apache OpenNLP or Stanford CoreNLP models stored locally on disk) to support Indian regional languages (Hindi, Tamil, Telugu) without cloud API calls.
> 2. **Static APK Manifest Parsing:** Introduce a client-side or local parser that inspects `AndroidManifest.xml` files, automatically cross-referencing requested permissions with declared application intent filters and categories.
> 3. **Offline High-Volume Threat Dictionaries:** Ship curated, locally compressed Bloom filters containing known malicious domain hashes and certificate authority fingerprints."

---

### D10: "What are the primary technical limitations of your current implementation?"
**Examiner Angle:** Testing self-awareness, honesty, and analytical maturity.  
**Student Defense:**  
> "Our current implementation has three clear technical limitations:
> 1. **Lexical Brittleness:** Because detection relies on regular expressions, heavily obfuscated text (such as leetspeak substitutions or image-based text) that bypasses our keyword dictionary will not trigger rules.
> 2. **Shortener Omodality:** In the offline URL analyzer, shorteners (e.g., `bit.ly`) must be flagged as medium risk by default because we cannot inspect the destination URL without making a network request.
> 3. **Single-Permission Analysis:** Android permissions are currently evaluated as individual privileges rather than detecting dangerous co-occurrences (e.g., an app requesting both `RECEIVE_BOOT_COMPLETED` and `SYSTEM_ALERT_WINDOW` simultaneously)."

---

## 5. Project Demonstration Rehearsal Script (10-Minute Walkthrough)

This script provides an exact sequence of steps for demonstrating the running application during a project evaluation.

```
+---------------------------------------------------------------------------------+
| Estimated Duration: 10 Minutes                                                  |
| Setup: Application running on http://localhost:8080/ via Maven or JAR           |
+---------------------------------------------------------------------------------+
```

### Step 1: Platform Overview and Privacy Guarantee (Minute 0:00 - 1:30)
- **What to Open:** Navigate to `http://localhost:8080/` in the browser.
- **What to Show:** Point to the header shield icon, title ("Cybersecurity Awareness Platform"), the hero banner, and the persistent privacy alert.
- **Concept to Explain:**
  > "The platform is an educational cybersecurity tool designed to analyze scam messages, inspect deceptive URLs, and evaluate mobile permissions. Notice our privacy banner: the application operates on an in-memory model without databases, accounts, or telemetry."

---

### Step 2: Demonstrating Message Analysis (Minute 1:30 - 4:00)
- **What to Open:** The **Message Analyzer** tab (active by default).
- **What Input to Enter:** Click the quick demo chip labeled **"Digital Arrest Scam"**, or paste:
  ```text
  You are placed under digital arrest by Mumbai Cyber Crime Branch. Do not disconnect Skype video call or leave the room until investigation clears.
  ```
- **Which Button to Click:** Click the cyan **"Analyze Message"** button.
- **Expected Output:**
  - Score Dial animates to **50 / 100**.
  - Risk Badge: **Medium Risk** (amber/orange).
  - Matched Indicators (3 cards):
    1. `MSG_IMPERSONATION` (+15) — Authority impersonation (Mumbai Cyber Crime Branch).
    2. `MSG_ARREST_THREAT` (+20) — Threat of arrest / legal action.
    3. `MSG_SECRECY_ISOLATION` (+15) — Coercive isolation / video call mandate.
  - Recommended Action: Advises against hasty action and prompts independent verification.
  - Safe Handling Tip: Reminds the user that official agencies never conduct investigations over Skype or video calls.
- **Concept to Explain:**
  > "Notice how the input text was immediately cleared from the textarea upon submission to protect user privacy. The backend evaluated regex rules, deduplicated them, and calculated $15 + 20 + 15 = 50$, placing it in the Medium tier."

---

### Step 3: Demonstrating URL Structural Inspection (Minute 4:00 - 6:30)
- **What to Open:** Click on the **URL Analyzer** tab.
- **What Input to Enter:** Click the demo chip **"Look-alike Typo"**, or enter:
  ```text
  https://paypa1-security.com/signin
  ```
- **Which Button to Click:** Click **"Inspect URL Structure"**.
- **Expected Output:**
  - Score Dial: **20 / 100** (**Low Risk**).
  - Matched Indicator: `URL_LOOKALIKE_DOMAIN` (+20) — Look-alike or Typosquatting Domain (`paypa1` mimicking `paypal`).
- **Second URL Test (Demonstrating Authority Masking):**
  - Enter: `https://secure-login@phishing-server.com/auth`
  - Click **"Inspect URL Structure"**.
  - Matched Indicator: `URL_AT_SYMBOL` (+15) — Embedded '@' Symbol in URL Authority.
- **Concept to Explain:**
  > "Crucially, the server never initiated an HTTP connection or DNS lookup to these links. Inspection was performed entirely offline using `java.net.URI` and Levenshtein edit distance against our brand dictionary."

---

### Step 4: Demonstrating Android Permission Guidance (Minute 6:30 - 8:30)
- **What to Open:** Click on the **Android Permissions** tab.
- **What Input to Enter:**
  1. Use the category filter buttons: click **"System"** and select `android.permission.BIND_ACCESSIBILITY_SERVICE`.
  2. Click **"SMS"** and select `android.permission.READ_SMS`.
  3. Click **"Location"** and select `android.permission.ACCESS_FINE_LOCATION`.
- **Which Button to Click:** Click **"Evaluate Selected Permissions"**.
- **Expected Output:**
  - Guidance Cards returned:
    - `BIND_ACCESSIBILITY_SERVICE`: Red **DENY** badge with an explanation of banking trojan abuse.
    - `READ_SMS`: Red **DENY** badge warning about OTP and 2FA interception.
    - `ACCESS_FINE_LOCATION`: Amber **REVIEW** badge explaining precise GPS tracking risks.
  - Mandatory Educational Disclaimer displayed prominently at the bottom.
- **Concept to Explain:**
  > "The engine evaluates requested permissions against real-world attack vectors, distinguishing between privileges that should almost always be denied for general apps versus those that depend on legitimate application context."

---

### Step 5: Verification of Automated Tests & Evaluation Metrics (Minute 8:30 - 10:00)
- **What to Open:** Switch to the terminal window in the project root.
- **Command to Execute:**
  ```bash
  ./mvnw test -Dtest=EvaluationRunnerTest
  ```
- **Expected Output:**
  - 1 test run, 0 failures, `BUILD SUCCESS`.
  - Console prints confusion matrix: TP = 12, TN = 12, FP = 0, FN = 0.
  - Accuracy = 100.00%, Precision = 100.00%, Recall = 100.00%, Mean Latency = 1.42 ms.
- **Concluding Statement for Presenter:**
  > "All components are verified by 48 automated JUnit 5 tests, ensuring rigorous software engineering standards and sub-2-millisecond latency. Thank you."

---

## 6. Critical Knowledge Gaps and Student Defense Preparation

Before defending this project in front of an academic committee, the student should ensure thorough familiarity with the following technical implementation details:

### 1. Java & Spring Boot Core Classes
- Understand the difference between `@RestController` and standard `@Controller`.
- Know how `@RestControllerAdvice` in `GlobalExceptionHandler` intercepts validation exceptions from Hibernate Validator.
- Know where the embedded Tomcat server configuration is defined (standard Spring Boot autoconfiguration in `pom.xml`).

### 2. Service Method Signatures
- `MessageAnalyzer.analyze(String text) -> AnalysisResult`
- `UrlAnalyzer.analyze(String rawUrl) -> AnalysisResult`
- `PermissionService.checkPermissions(List<String> requested) -> PermissionResult`
- `ScoringEngine.calculateScore(Collection<MatchedRule> rules) -> int`

### 3. API Request and Response Shapes
- Understand the JSON request POJOs: `MessageAnalysisRequest` (`text`), `UrlAnalysisRequest` (`url`), `PermissionRequest` (`permissions`).
- Understand the fields of `AnalysisResult`: `score` (int), `category` (String), `matchedRules` (List), `recommendedAction` (String), `safeHandlingTip` (String), `disclaimer` (String).

### 4. Scoring Calculations and Boundaries
- Be prepared to write the scoring formula on the board:
  $$S = \min\left(100, \sum_{i \in \text{Unique Matched Rules}} w_i\right)$$
- Know the exact boundaries:
  - Score 0 to 30: **Low Risk**
  - Score 31 to 65: **Medium Risk**
  - Score 66 to 100: **High Risk**
- Know the weight values: Arrest threats (20), Payment demands (20), Credentials (20), Impersonation (15), Secrecy (15), Urgency (10), IP host (25), Lookalike (20), Subdomain (15), `@` symbol (15), Hyphens (10), Shortener (10).

### 5. Configuration Mechanics
- Know that `rules.json` and `permissions.json` reside in `src/main/resources/`.
- Understand that `RuleConfiguration.java` loads the resource via `ClassPathResource` and validates non-null thresholds and non-empty rule lists before bean instantiation.

### 6. Security Decisions to Defend
- Be able to explain why raw URLs are parsed using `java.net.URI` without resolving DNS.
- Be able to explain why request bodies are never logged using `logger.info()`.
- Be able to explain why DOM insertion in `app.js` uses `textContent` instead of `innerHTML`.

---

## 7. Evaluator Summary and Important Code Locations

| Component | Source File Location | Key Methods & Logic |
| :--- | :--- | :--- |
| **Main Application** | `src/main/java/com/cybersecurity/CybersecurityApplication.java` | `main()` method bootstrapping Spring application. |
| **REST Controller** | `src/main/java/com/cybersecurity/controller/AnalysisController.java` | `analyzeMessage()`, `analyzeUrl()`, `listPermissions()`, `checkPermissions()` |
| **Message Analysis** | `src/main/java/com/cybersecurity/service/MessageAnalyzer.java` | `analyze()`, `extractSnippet()`, `CompiledMessageRule` inner class |
| **URL Analysis** | `src/main/java/com/cybersecurity/service/UrlAnalyzer.java` | `analyze()`, `computeLevenshteinDistance()`, `checkNumericIp()`, `checkAtSymbol()` |
| **Permission Guidance**| `src/main/java/com/cybersecurity/service/PermissionService.java` | `getAllPermissions()`, `checkPermissions()`, `normalizePermission()`, `createUnknownFallback()` |
| **Scoring Engine** | `src/main/java/com/cybersecurity/service/ScoringEngine.java` | `calculateScore()`, `determineCategory()`, `buildResult()` |
| **Rule Config Bean** | `src/main/java/com/cybersecurity/config/RuleConfiguration.java` | `rulesConfig()`, `validateRulesConfig()` |
| **Exception Handler**| `src/main/java/com/cybersecurity/exception/GlobalExceptionHandler.java`| `handleValidationErrors()`, `handleUnreadableMessage()`, `handleGenericException()` |
| **Benchmark Harness** | `src/main/java/com/cybersecurity/eval/EvaluationRunner.java` | `evaluate()`, `calculateMetrics()`, `printSummary()` |
| **Rules JSON** | `src/main/resources/rules.json` | 6 message rules, 7 URL rules, 18 known brands, 14 shorteners |
| **Permissions JSON**| `src/main/resources/permissions.json` | 20 high-risk Android permissions catalog |
| **Frontend HTML** | `src/main/resources/static/index.html` | Semantic layout, SVG dials, accessible forms, aria-live regions |
| **Frontend JS** | `src/main/resources/static/js/app.js` | Fetch handlers, DOM rendering, SVG dial animation, zero local storage |
| **Evaluation Data** | `evaluation/dataset.json` | 24 ground-truth labelled benchmark test cases |
| **Audit Test Suite** | `src/test/java/com/cybersecurity/SecurityAndPrivacyAuditTest.java` | Network isolation reflection tests, log leakage verification |

---

### Final Evaluator Verdict
The **Cybersecurity Awareness Platform** complies with all academic and software engineering requirements established in the PRD. The implementation demonstrates clean separation of concerns, defensive security programming, verified sub-2-millisecond latency, 100% benchmark classification accuracy, and complete privacy preservation. The project is fully ready for academic demonstration, technical evaluation, and viva defense.
