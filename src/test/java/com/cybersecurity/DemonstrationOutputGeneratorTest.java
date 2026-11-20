package com.cybersecurity;

import com.cybersecurity.config.PermissionConfiguration;
import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.PermissionResult;
import com.cybersecurity.model.PermissionsConfig;
import com.cybersecurity.model.RulesConfig;
import com.cybersecurity.service.MessageAnalyzer;
import com.cybersecurity.service.PermissionService;
import com.cybersecurity.service.ScoringEngine;
import com.cybersecurity.service.UrlAnalyzer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Demonstration Output Generator & Verifier")
class DemonstrationOutputGeneratorTest {

    private MessageAnalyzer messageAnalyzer;
    private UrlAnalyzer urlAnalyzer;
    private PermissionService permissionService;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        RuleConfiguration ruleConfig = new RuleConfiguration();
        RulesConfig rules = ruleConfig.rulesConfig(objectMapper);
        ScoringEngine scoringEngine = new ScoringEngine(rules);
        messageAnalyzer = new MessageAnalyzer(scoringEngine, rules);
        urlAnalyzer = new UrlAnalyzer(scoringEngine, rules);

        PermissionConfiguration permConfig = new PermissionConfiguration();
        PermissionsConfig perms = permConfig.permissionsConfig(objectMapper);
        permissionService = new PermissionService(perms);
    }

    @Test
    @DisplayName("Generate Real Demonstration Outputs for Messages, URLs, and Permissions")
    void testDemonstrationScenarios() throws Exception {
        System.out.println("=== DEMONSTRATION A: MESSAGE ANALYZER OUTPUTS ===");
        String[] messages = {
            // 1. Govt Impersonation
            "Dear Citizen, this is Officer Sharma from Delhi Police and Central Bureau of Investigation regarding an ongoing financial fraud case.",
            // 2. Digital Arrest Threat
            "You are placed under digital arrest by Mumbai Cyber Crime Branch. Do not disconnect Skype video call or leave the room until investigation clears.",
            // 3. Urgent Account Suspension
            "Your SBI net banking profile has expired and will be blocked within 24 hours immediately unless profile is re-activated.",
            // 4. Payment Demand
            "Pay pending traffic violation penalty of Rs 25,000 immediately via UPI to avoid non-bailable arrest warrant.",
            // 5. OTP / Credential Request
            "Dear customer, your credit card is blocked. Kindly share the 6-digit OTP and CVV sent to your mobile to verify your card details.",
            // 6. Benign Security Notification
            "CERT-In Advisory CIAD-2024-0012: Multiple vulnerabilities in web browsers. Please update software. Legitimate agencies never demand funds or video calls."
        };

        for (int i = 0; i < messages.length; i++) {
            AnalysisResult res = messageAnalyzer.analyze(messages[i]);
            System.out.println("--- MSG EXAMPLE " + (i + 1) + " ---");
            System.out.println("Input: " + messages[i]);
            System.out.println("Score: " + res.getScore() + " | Category: " + res.getCategory());
            System.out.println("Matched Rules Count: " + res.getMatchedRules().size());
            res.getMatchedRules().forEach(r -> System.out.println("  - " + r.getId() + " (" + r.getWeight() + "): " + r.getExplanation()));
            System.out.println("JSON: " + objectMapper.writeValueAsString(res));
            assertNotNull(res);
        }

        System.out.println("\n=== DEMONSTRATION B: URL ANALYZER OUTPUTS ===");
        String[] urls = {
            // 1. Numeric IP Host
            "http://192.168.1.100/secure/banking/login",
            // 2. Misleading Subdomain
            "https://sbi.co.in.security-update.com/login",
            // 3. Look-alike Domain
            "https://paypa1-security.com/signin",
            // 4. Excessive Hyphens
            "https://hdfc-net-banking-verify-login.com/portal",
            // 5. Suspicious Authority @
            "https://secure-login@phishing-server.com/auth",
            // 6. URL Shortener
            "https://bit.ly/3xY9zQp",
            // 7. Benign Conventional URL
            "https://www.onlinesbi.sbi/portal"
        };

        for (int i = 0; i < urls.length; i++) {
            AnalysisResult res = urlAnalyzer.analyze(urls[i]);
            System.out.println("--- URL EXAMPLE " + (i + 1) + " ---");
            System.out.println("Input: " + urls[i]);
            System.out.println("Score: " + res.getScore() + " | Category: " + res.getCategory());
            System.out.println("Matched Rules Count: " + res.getMatchedRules().size());
            res.getMatchedRules().forEach(r -> System.out.println("  - " + r.getId() + " (" + r.getWeight() + "): " + r.getExplanation()));
            System.out.println("JSON: " + objectMapper.writeValueAsString(res));
            assertNotNull(res);
        }

        System.out.println("\n=== DEMONSTRATION C: ANDROID PERMISSION OUTPUTS ===");
        List<List<String>> permGroups = Arrays.asList(
            // 1. SMS
            Arrays.asList("android.permission.READ_SMS", "android.permission.RECEIVE_SMS"),
            // 2. Location
            Arrays.asList("android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"),
            // 3. Camera / Mic
            Arrays.asList("android.permission.CAMERA", "android.permission.RECORD_AUDIO"),
            // 4. Contacts
            Arrays.asList("android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"),
            // 5. Accessibility
            Collections.singletonList("android.permission.BIND_ACCESSIBILITY_SERVICE"),
            // 6. Unknown
            Collections.singletonList("android.permission.CUSTOM_THIRD_PARTY_SERVICE")
        );

        for (int i = 0; i < permGroups.size(); i++) {
            List<String> req = permGroups.get(i);
            PermissionResult res = permissionService.checkPermissions(req);
            System.out.println("--- PERMISSION GROUP " + (i + 1) + " ---");
            System.out.println("Requested: " + req);
            System.out.println("Total Returned: " + res.getResults().size());
            res.getResults().forEach(p -> System.out.println("  - " + p.getPermission() + " -> " + p.getRecommendation() + " (Risk: " + p.getSecurityRisk() + ")"));
            System.out.println("JSON: " + objectMapper.writeValueAsString(res));
            assertNotNull(res);
        }
    }
}
