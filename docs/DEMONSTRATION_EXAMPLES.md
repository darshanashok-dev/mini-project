# Application Demonstration Examples

**Project:** Cybersecurity Awareness Platform  
**Target Audience:** Academic Evaluators, External Examiners, Review Committee  
**Version:** 1.0.0  

This document details synthetic demonstration cases covering all three core modules. All outputs presented are recorded directly from the running Java Spring Boot application.

---

## 1. Demonstration Module A: Message Analyzer

The Message Analyzer inspects suspicious text messages for indicators of digital arrest scams, urgent financial extortion, impersonation of authority, secrecy coercion, and credential harvesting.

### Example A1: Law Enforcement & Government Impersonation
- **Input Text:**
  ```text
  Dear Citizen, this is Officer Sharma from Delhi Police and Central Bureau of Investigation regarding an ongoing financial fraud case.
  ```
- **Expected Indicators:** `MSG_IMPERSONATION` (Weight: 15)
- **Scoring Behaviour:** Base score = 15. Classification = **Low Risk** (0–30 range).
- **Explanation:** The sender claims to represent Delhi Police and the CBI. In the absence of an immediate monetary threat or arrest warrant, this serves as an impersonation indicator.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 15,
    "category": "Low",
    "matchedRules": [
      {
        "id": "MSG_IMPERSONATION",
        "name": "Impersonation of Authority or Institution",
        "weight": 15,
        "matchedText": "...fficer Sharma from Delhi Police and Central Bureau of In...",
        "explanation": "The message claims to originate from law enforcement, a regulatory body, bank, or parcel courier service. Scammers frequently impersonate authority figures to intimidate recipients."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example A2: Digital Arrest & Coercive Video-Call Threat
- **Input Text:**
  ```text
  You are placed under digital arrest by Mumbai Cyber Crime Branch. Do not disconnect Skype video call or leave the room until investigation clears.
  ```
- **Expected Indicators:** `MSG_IMPERSONATION` (15), `MSG_ARREST_THREAT` (20), `MSG_SECRECY_ISOLATION` (15)
- **Scoring Behaviour:** Cumulative score: $15 + 20 + 15 = 50$. Classification = **Medium Risk** (31–65 range).
- **Explanation:** Classic "Digital Arrest" extortion tactic. Scammers impersonate police, threaten arrest, and enforce isolation on a continuous video call to prevent the victim from seeking outside assistance.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 50,
    "category": "Medium",
    "matchedRules": [
      {
        "id": "MSG_IMPERSONATION",
        "name": "Impersonation of Authority or Institution",
        "weight": 15,
        "matchedText": "...digital arrest by Mumbai Cyber Crime Branch. Do not disconnect Skype...",
        "explanation": "The message claims to originate from law enforcement, a regulatory body, bank, or parcel courier service. Scammers frequently impersonate authority figures to intimidate recipients."
      },
      {
        "id": "MSG_ARREST_THREAT",
        "name": "Arrest and Legal Action Threat",
        "weight": 20,
        "matchedText": "You are placed under digital arrest by Mumbai Cyber Crime Br...",
        "explanation": "The message threatens arrest, warrants, criminal FIRs, or legal prosecution (a hallmark of 'digital arrest' scams). Law enforcement agencies never arrest or conduct court hearings via phone or video calls."
      },
      {
        "id": "MSG_SECRECY_ISOLATION",
        "name": "Secrecy, Surveillance, and Isolation",
        "weight": 15,
        "matchedText": "...mbai Cyber Crime Branch. Do not disconnect Skype video call or leave...",
        "explanation": "The sender demands that you keep the communication secret, isolate yourself, or remain on an uninterrupted video call. This coercive tactic is used to prevent you from seeking advice."
      }
    ],
    "recommendedAction": "Exercise strong caution. Do not click links, open attachments, or take hurried actions. Independently verify the claim by contacting the organization through their official phone number or website.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example A3: Urgent Banking Account Suspension
- **Input Text:**
  ```text
  Your SBI net banking profile has expired and will be blocked within 24 hours immediately unless profile is re-activated.
  ```
- **Expected Indicators:** `MSG_IMPERSONATION` (15), `MSG_URGENCY_FEAR` (10)
- **Scoring Behaviour:** Cumulative score: $15 + 10 = 25$. Classification = **Low Risk** (single-vector urgency + brand claim).
- **Explanation:** Exploits psychological panic by setting a short 24-hour deadline to bypass critical thinking.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 25,
    "category": "Low",
    "matchedRules": [
      {
        "id": "MSG_IMPERSONATION",
        "name": "Impersonation of Authority or Institution",
        "weight": 15,
        "matchedText": "Your SBI net banking profile has...",
        "explanation": "The message claims to originate from law enforcement, a regulatory body, bank, or parcel courier service. Scammers frequently impersonate authority figures to intimidate recipients."
      },
      {
        "id": "MSG_URGENCY_FEAR",
        "name": "Urgency and Psychological Pressure",
        "weight": 10,
        "matchedText": "...ired and will be blocked within 24 hours immediately unless profi...",
        "explanation": "The message employs urgent deadlines or threats of immediate service suspension to induce panic and prevent rational verification."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example A4: Coercive Traffic Fine Payment Demand
- **Input Text:**
  ```text
  Pay pending traffic violation penalty of Rs 25,000 immediately via UPI to avoid non-bailable arrest warrant.
  ```
- **Expected Indicators:** `MSG_URGENCY_FEAR` (10), `MSG_ARREST_THREAT` (20)
- **Scoring Behaviour:** Cumulative score: $10 + 20 = 30$. Classification = **Low Risk** (upper boundary of Low).
- **Explanation:** Pairs an immediate payment demand with a threat of a non-bailable arrest warrant.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 30,
    "category": "Low",
    "matchedRules": [
      {
        "id": "MSG_URGENCY_FEAR",
        "name": "Urgency and Psychological Pressure",
        "weight": 10,
        "matchedText": "...ion penalty of Rs 25,000 immediately via UPI to avoid non-bai...",
        "explanation": "The message employs urgent deadlines or threats of immediate service suspension to induce panic and prevent rational verification."
      },
      {
        "id": "MSG_ARREST_THREAT",
        "name": "Arrest and Legal Action Threat",
        "weight": 20,
        "matchedText": "...PI to avoid non-bailable arrest warrant.",
        "explanation": "The message threatens arrest, warrants, criminal FIRs, or legal prosecution (a hallmark of 'digital arrest' scams). Law enforcement agencies never arrest or conduct court hearings via phone or video calls."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example A5: Sensitive OTP and Credential Harvesting
- **Input Text:**
  ```text
  Dear customer, your credit card is blocked. Kindly share the 6-digit OTP and CVV sent to your mobile to verify your card details.
  ```
- **Expected Indicators:** `MSG_CREDENTIAL_REQUEST` (20)
- **Scoring Behaviour:** Score = 20. Classification = **Low Risk**.
- **Explanation:** Unsolicited request for 2FA credentials (OTP and CVV). Legitimate banking institutions explicitly state they never request OTPs.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 20,
    "category": "Low",
    "matchedRules": [
      {
        "id": "MSG_CREDENTIAL_REQUEST",
        "name": "Sensitive Credential or OTP Request",
        "weight": 20,
        "matchedText": "...V sent to your mobile to verify your card details.",
        "explanation": "The message requests sensitive credentials such as an OTP, PIN, password, CVV, or Aadhaar details. Legitimate organizations and banks will never ask you to disclose secret authentication codes."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example A6: Benign Government Cybersecurity Advisory
- **Input Text:**
  ```text
  CERT-In Advisory CIAD-2024-0012: Multiple vulnerabilities in web browsers. Please update software. Legitimate agencies never demand funds or video calls.
  ```
- **Expected Indicators:** None (0 rules matched).
- **Scoring Behaviour:** Score = 0. Classification = **Low Risk**.
- **Explanation:** Contains security terminology and mentions of official bodies, but negative context checks prevent false alarms.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 0,
    "category": "Low",
    "matchedRules": [],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

## 2. Demonstration Module B: URL Analyzer

The URL Analyzer evaluates link anatomy strictly offline without connecting or performing external DNS lookups.

### Example B1: Numeric IP Host Address
- **Input URL:** `http://192.168.1.100/secure/banking/login`
- **Expected Indicators:** `URL_NUMERIC_IP` (Weight: 25)
- **Scoring Behaviour:** Score = 25. Classification = **Low Risk**.
- **Explanation:** Phishing campaigns frequently deploy servers on direct IP addresses to bypass domain registrar reputation tracking and take-down mechanisms.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 25,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_NUMERIC_IP",
        "name": "Numeric IP Address Host",
        "weight": 25,
        "matchedText": "192.168.1.100",
        "explanation": "The URL uses a direct numeric IP address (e.g., 192.168.1.1) rather than a legitimate registered domain name. Attackers use raw IPs to bypass domain registration and reputation filters."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B2: Deceptive Subdomain Brand Spoofing
- **Input URL:** `https://sbi.co.in.security-update.com/login`
- **Expected Indicators:** `URL_DECEPTIVE_SUBDOMAIN` (Weight: 15)
- **Scoring Behaviour:** Score = 15. Classification = **Low Risk**.
- **Explanation:** The trusted entity name (`sbi.co.in`) is prepended as a subdomain on an unrelated domain (`security-update.com`). Victims glancing at the left of the URL mistakenly believe it belongs to the brand.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 15,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_DECEPTIVE_SUBDOMAIN",
        "name": "Deceptive Brand Subdomain",
        "weight": 15,
        "matchedText": "sbi.security-update.com",
        "explanation": "The URL contains a trusted brand name inside a subdomain or prefix of an unrelated host (e.g., paypal.com.attacker-site.xyz). The true destination is the parent domain, not the brand."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B3: Look-alike Typosquatting Domain
- **Input URL:** `https://paypa1-security.com/signin`
- **Expected Indicators:** `URL_LOOKALIKE_DOMAIN` (Weight: 20)
- **Scoring Behaviour:** Score = 20. Classification = **Low Risk**.
- **Explanation:** The domain substitutes the letter `l` with the digit `1` (`paypa1`). The Levenshtein distance check detects this single-character visual substitution against the curated brand catalog.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 20,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_LOOKALIKE_DOMAIN",
        "name": "Look-alike or Typosquatting Domain",
        "weight": 20,
        "matchedText": "paypa1 (mimicking paypal)",
        "explanation": "The domain name closely mimics a well-known brand using character substitutions or typos (e.g., paypa1, micros0ft, arnazon). This is a common phishing technique."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B4: Excessive Hyphenation in Hostname
- **Input URL:** `https://hdfc-net-banking-verify-login.com/portal`
- **Expected Indicators:** `URL_EXCESSIVE_HYPHENS` (Weight: 10)
- **Scoring Behaviour:** Score = 10. Classification = **Low Risk**.
- **Explanation:** Host contains 4 hyphens. Threat actors frequently concatenate multiple legitimate keywords with hyphens to simulate complex corporate infrastructure.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 10,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_EXCESSIVE_HYPHENS",
        "name": "Excessive Hyphens in Hostname",
        "weight": 10,
        "matchedText": "hdfc-net-banking-verify-login.com",
        "explanation": "The host contains 3 or more hyphens (e.g., secure-login-verify-account.com). Malicious domains frequently string together multiple keywords separated by hyphens."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B5: Embedded Authority '@' Sign
- **Input URL:** `https://secure-login@phishing-server.com/auth`
- **Expected Indicators:** `URL_AT_SYMBOL` (Weight: 15)
- **Scoring Behaviour:** Score = 15. Classification = **Low Risk**.
- **Explanation:** Under RFC 3986, characters before the `@` symbol are treated as user credentials, and browsers route the connection solely to the host following `@` (`phishing-server.com`).
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 15,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_AT_SYMBOL",
        "name": "Embedded '@' Symbol in URL Authority",
        "weight": 15,
        "matchedText": "://secure-login@phishing-serve",
        "explanation": "The URL contains an '@' character in the authority section. Standard web browsers interpret text before '@' as user-info and connect only to the host after '@', concealing the actual destination."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B6: URL Shortener Destination Masking
- **Input URL:** `https://bit.ly/3xY9zQp`
- **Expected Indicators:** `URL_SHORTENER` (Weight: 10)
- **Scoring Behaviour:** Score = 10. Classification = **Low Risk**.
- **Explanation:** URL shortening domains conceal the actual destination host and path, preventing visual inspection before opening.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 10,
    "category": "Low",
    "matchedRules": [
      {
        "id": "URL_SHORTENER",
        "name": "Known URL Shortening Service",
        "weight": 10,
        "matchedText": "bit.ly",
        "explanation": "The link uses a URL shortener service (e.g., bit.ly, tinyurl.com). Shorteners obscure the true destination domain, preventing inspection before opening."
      }
    ],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### Example B7: Benign Conventional URL
- **Input URL:** `https://www.onlinesbi.sbi/portal`
- **Expected Indicators:** None (0 rules triggered).
- **Scoring Behaviour:** Score = 0. Classification = **Low Risk**.
- **Explanation:** Standard HTTPS protocol, registered brand top-level domain (`.sbi`), single brand hostname, no excessive hyphens or obfuscated path tokens.
- **Actual Application Output (JSON):**
  ```json
  {
    "score": 0,
    "category": "Low",
    "matchedRules": [],
    "recommendedAction": "No standard indicators of phishing or social engineering were triggered based on configured rules. However, attackers continuously evolve their techniques. Always remain vigilant and never share credentials.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

## 3. Demonstration Module C: Android Permission Analyzer

The Android Permission Analyzer evaluates requested Android privileges and returns actionable guidance: `ALLOW`, `DENY`, or `REVIEW`.

### Group C1: SMS Interception Permissions
- **Requested Permissions:** `android.permission.READ_SMS`, `android.permission.RECEIVE_SMS`
- **Guidance Returned:**
  - `READ_SMS`: **DENY**
  - `RECEIVE_SMS`: **DENY**
- **Risk Analysis:** Malicious applications use SMS reading to intercept 2FA OTPs and banking alerts, enabling account takeovers.
- **Contextual Rule:** Deny for all non-default SMS messaging apps. Modern apps should use Google's SMS Retriever API.

---

### Group C2: Physical Location Permissions
- **Requested Permissions:** `android.permission.ACCESS_FINE_LOCATION`, `android.permission.ACCESS_COARSE_LOCATION`
- **Guidance Returned:**
  - `ACCESS_FINE_LOCATION`: **REVIEW**
  - `ACCESS_COARSE_LOCATION`: **ALLOW**
- **Risk Analysis:** Precise GPS coordinates enable continuous physical surveillance of residences and routines. Coarse location provides general regional data without precision tracking.
- **Contextual Rule:** Allow precise GPS only for active navigation or ride-sharing apps ("Only while using the app"). Use coarse location for weather or local news.

---

### Group C3: Environmental Surveillance (Camera & Microphone)
- **Requested Permissions:** `android.permission.CAMERA`, `android.permission.RECORD_AUDIO`
- **Guidance Returned:**
  - `CAMERA`: **REVIEW**
  - `RECORD_AUDIO`: **REVIEW**
- **Risk Analysis:** Spyware can covertly record private ambient audio and capture camera photos without the user's active awareness.
- **Contextual Rule:** Grant strictly to applications with direct media creation purposes (e.g., video calls, QR scanning) and restrict to foreground execution.

---

### Group C4: Contact Book Harvesting
- **Requested Permissions:** `android.permission.READ_CONTACTS`, `android.permission.WRITE_CONTACTS`
- **Guidance Returned:**
  - `READ_CONTACTS`: **REVIEW**
  - `WRITE_CONTACTS`: **REVIEW**
- **Risk Analysis:** Predatory instant-loan apps and data brokers harvest address books to blackmail users' acquaintances or generate spear-phishing targets.
- **Contextual Rule:** Deny for single-player games, flashlight tools, calculators, and photo editors.

---

### Group C5: System-Wide Accessibility Service
- **Requested Permissions:** `android.permission.BIND_ACCESSIBILITY_SERVICE`
- **Guidance Returned:**
  - `BIND_ACCESSIBILITY_SERVICE`: **DENY** (Critical Security Risk)
- **Risk Analysis:** The most heavily exploited Android privilege by advanced banking trojans. Allows apps to inspect screen contents across all applications, capture typed keystrokes, and autonomously execute banking transactions.
- **Contextual Rule:** Never grant accessibility permissions to an application unless you require assistive screen-reader technology.

---

### Group C6: Unrecognized / Custom Third-Party Permission
- **Requested Permissions:** `android.permission.CUSTOM_THIRD_PARTY_SERVICE`
- **Guidance Returned:**
  - `android.permission.CUSTOM_THIRD_PARTY_SERVICE`: **REVIEW** (Safe Fallback)
- **Risk Analysis:** Custom or vendor-specific permissions may expose undocumented capabilities depending on OEM privilege levels.
- **Contextual Rule:** The platform applies a defensive fallback to `REVIEW` with an advisory notice to check publisher reputability.
