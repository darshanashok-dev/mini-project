# REST API Reference Documentation

All application endpoints are served under the root context path (`/api/*`) and communicate exclusively using `application/json`.

---

## 1. Endpoints Summary

| Method | Endpoint | Description | Request Body | Status Codes |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze/message` | Evaluates suspicious text messages, SMS, or emails | `{"text": "..."}` | `200`, `400` |
| `POST` | `/api/analyze/url` | Evaluates URL structure offline without connecting | `{"url": "..."}` | `200`, `400` |
| `GET` | `/api/permissions` | Retrieves the catalog of all 20 sensitive permissions | _None_ | `200` |
| `POST` | `/api/permissions/check`| Evaluates selected Android permissions | `{"permissions": [...]}` | `200`, `400` |

---

## 2. Endpoint Details

### A. POST `/api/analyze/message`
Evaluates text for impersonation, urgency/fear, arrest threats, secrecy demands, safe account fund transfers, and credential theft.

- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "text": "This is CBI Inspector Sharma. A digital arrest warrant has been issued against you for narcotics trafficking. Stay on video call and transfer Rs 50,000 to the RBI safe verification account immediately."
  }
  ```
- **Validation Constraints:**
  - `@NotBlank`: Cannot be null, empty, or whitespace-only.
  - `@Size(max = 10000)`: Maximum 10,000 characters.

- **Success Response (HTTP 200 OK):**
  ```json
  {
    "score": 80,
    "category": "High",
    "matchedRules": [
      {
        "id": "MSG_IMPERSONATION",
        "name": "Impersonation of Authority or Institution",
        "weight": 15,
        "matchedText": "CBI Inspector Sharma",
        "explanation": "Claims to originate from law enforcement or a regulatory body."
      },
      {
        "id": "MSG_URGENCY_FEAR",
        "name": "Urgency and Psychological Pressure",
        "weight": 10,
        "matchedText": "immediately",
        "explanation": "Employs urgent deadlines to induce panic."
      },
      {
        "id": "MSG_ARREST_THREAT",
        "name": "Arrest and Legal Action Threat",
        "weight": 20,
        "matchedText": "digital arrest warrant has been issued",
        "explanation": "Threatens digital arrest, warrants, or criminal prosecution."
      },
      {
        "id": "MSG_SECRECY_ISOLATION",
        "name": "Secrecy, Surveillance, and Isolation",
        "weight": 15,
        "matchedText": "Stay on video call",
        "explanation": "Demands isolation or continuous video call surveillance."
      },
      {
        "id": "MSG_PAYMENT_DEMAND",
        "name": "Financial Demand or Safe Account Transfer",
        "weight": 20,
        "matchedText": "transfer Rs 50,000 to the RBI safe verification account",
        "explanation": "Demands money transfer to a supposedly 'safe verification account'."
      }
    ],
    "recommendedAction": "Do not transfer money, do not share any credentials or OTPs, and disconnect any unsolicited call immediately. If threatened with digital arrest, remember that Indian law enforcement does not arrest citizens over video calls. Report to cybercrime.gov.in (National Cyber Crime Reporting Portal) or call 1930.",
    "safeHandlingTip": "Never share OTPs, UPI PINs, or banking passwords with anyone under any circumstances. Official agencies do not issue arrest warrants via WhatsApp or conduct investigations over Skype/video calls.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### B. POST `/api/analyze/url`
Evaluates a URL's structural characteristics offline. **Never sends HTTP packets or performs DNS lookups.**

- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "url": "http://192.168.1.105:8080/secure-banking-portal/online-login-account-update-verification/update.php"
  }
  ```
- **Validation Constraints:**
  - `@NotBlank`: Cannot be null, empty, or whitespace-only.
  - `@Size(max = 2048)`: Maximum 2,048 characters.

- **Success Response (HTTP 200 OK):**
  ```json
  {
    "score": 35,
    "category": "Medium",
    "matchedRules": [
      {
        "id": "URL_NUMERIC_IP",
        "name": "Numeric IP Address Host",
        "weight": 25,
        "matchedText": "192.168.1.105",
        "explanation": "Uses a direct numeric IP address instead of a registered domain."
      },
      {
        "id": "URL_LONG_OR_ENCODED_PATH",
        "name": "Suspicious Long, Encoded, or Executable Path",
        "weight": 10,
        "matchedText": "/secure-banking-portal/online-login-account-update-verificat...",
        "explanation": "Contains an unusually long path used to obfuscate destinations."
      }
    ],
    "recommendedAction": "Exercise strong caution. Do not click links, open attachments, or take hurried actions. Independently verify the claim by contacting the organization through their official phone number or website.",
    "safeHandlingTip": "Do not click unverified links received in SMS or chat messages. Type the official website address directly into your browser bookmark or address bar.",
    "disclaimer": "This result is advisory and does not prove that the message or URL is malicious or safe. Always verify communications independently."
  }
  ```

---

### C. GET `/api/permissions`
Returns the complete curated catalog of 20 sensitive Android permissions.

- **Request Headers:** _None_
- **Request Body:** _None_
- **Success Response (HTTP 200 OK):**
  ```json
  [
    {
      "permission": "READ_SMS",
      "name": "Read SMS Messages",
      "description": "Allows an application to read SMS messages stored on your device or SIM card.",
      "commonLegitimateUse": "Dedicated SMS client applications (e.g., Google Messages) or two-factor authentication handlers.",
      "securityRisk": "Malicious financial trojans and spyware intercept 2FA OTP codes and banking transaction alerts.",
      "recommendation": "DENY",
      "explanation": "High-risk permission. Modern apps should use Google SMS Retriever API instead."
    }
  ]
  ```

---

### D. POST `/api/permissions/check`
Evaluates a list of selected Android permissions and provides Allow, Deny, or Review guidance.

- **Request Headers:** `Content-Type: application/json`
- **Request Body:**
  ```json
  {
    "permissions": ["READ_SMS", "CAMERA", "CUSTOM_UNKNOWN_PERMISSION"]
  }
  ```
- **Success Response (HTTP 200 OK):**
  ```json
  {
    "results": [
      {
        "permission": "READ_SMS",
        "name": "Read SMS Messages",
        "recommendation": "DENY",
        "explanation": "High-risk permission. Deny unless the app is your primary SMS client."
      },
      {
        "permission": "CAMERA",
        "name": "Camera Access",
        "recommendation": "REVIEW",
        "explanation": "Review whether photo or video capture is essential for the application."
      },
      {
        "permission": "CUSTOM_UNKNOWN_PERMISSION",
        "name": "CUSTOM_UNKNOWN_PERMISSION",
        "recommendation": "REVIEW",
        "explanation": "Review the application's stated functionality, source, and publisher before granting this uncataloged permission."
      }
    ],
    "mandatoryWarning": "Permissions alone do not establish that an application is malicious. Consider the app's functionality, developer and source before making a decision."
  }
  ```

---

## 3. Error Handling

Invalid requests return a standard `ErrorResponse`:
```json
{
  "status": 400,
  "error": "text: Message text cannot be empty or blank",
  "timestamp": "2026-11-20T05:30:00.000Z"
}
```

HTTP Status Codes:
- `400 Bad Request`: Validation failure, empty input, oversized length, or malformed JSON.
- `500 Internal Server Error`: Unhandled server exception (sanitized generic message).
