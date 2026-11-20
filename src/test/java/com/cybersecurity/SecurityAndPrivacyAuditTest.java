package com.cybersecurity;

import com.cybersecurity.config.PermissionConfiguration;
import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.controller.AnalysisController;
import com.cybersecurity.exception.GlobalExceptionHandler;
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
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Comprehensive System Security & Privacy Audit Tests")
class SecurityAndPrivacyAuditTest {

    private MockMvc mockMvc;
    private MessageAnalyzer messageAnalyzer;
    private UrlAnalyzer urlAnalyzer;
    private PermissionService permissionService;
    private ScoringEngine scoringEngine;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        RulesConfig rules = new RuleConfiguration().rulesConfig(objectMapper);
        PermissionsConfig perms = new PermissionConfiguration().permissionsConfig(objectMapper);

        scoringEngine = new ScoringEngine(rules);
        messageAnalyzer = new MessageAnalyzer(scoringEngine, rules);
        urlAnalyzer = new UrlAnalyzer(scoringEngine, rules);
        permissionService = new PermissionService(perms);

        AnalysisController controller = new AnalysisController(messageAnalyzer, urlAnalyzer, permissionService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("Audit: Oversized message input (>10,000 characters) is rejected with HTTP 400")
    void testOversizedMessageRejected() throws Exception {
        String oversized = "A".repeat(10001);
        String payload = "{\"text\": \"" + oversized + "\"}";

        mockMvc.perform(post("/api/analyze/message")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("Audit: Oversized URL input (>2,048 characters) is rejected with HTTP 400")
    void testOversizedUrlRejected() throws Exception {
        String oversized = "http://example.com/" + "a".repeat(2050);
        String payload = "{\"url\": \"" + oversized + "\"}";

        mockMvc.perform(post("/api/analyze/url")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("Audit: Offline URL analyzer never throws on fictional or unresolvable domains")
    void testOfflineUrlExecutionSafety() {
        String[] testUrls = {
                "http://totally-fictional-domain-999888777666.xyz/login",
                "https://non-existent-bank-gateway.invalid:8443/test",
                "ftp://malicious-ftp-payload.attacker.org/file.exe",
                "http://user:pass@192.168.1.1:8080/secure/../admin",
                "://completely-malformed-uri-syntax",
                "http://[::1]:8080/login"
        };

        for (String url : testUrls) {
            assertDoesNotThrow(() -> {
                AnalysisResult result = urlAnalyzer.analyze(url);
                assertNotNull(result, "Result must not be null for: " + url);
                assertTrue(result.getScore() >= 0 && result.getScore() <= 100);
                assertNotNull(result.getDisclaimer(), "Disclaimer must always be present");
            });
        }
    }

    @Test
    @DisplayName("Audit: Determinism and idempotency of analysis services")
    void testAnalysisDeterminism() {
        String text = "CBI officer: digital arrest warrant issued against you. Pay Rs 50,000 immediately.";
        AnalysisResult res1 = messageAnalyzer.analyze(text);
        AnalysisResult res2 = messageAnalyzer.analyze(text);

        assertEquals(res1.getScore(), res2.getScore(), "Scores must be identical for identical inputs");
        assertEquals(res1.getCategory(), res2.getCategory(), "Risk categories must be identical");
        assertEquals(res1.getMatchedRules().size(), res2.getMatchedRules().size(), "Rule count must be identical");
    }

    @Test
    @DisplayName("Audit: Unknown permission safely defaults to REVIEW with explanation")
    void testUnknownPermissionDefaultGuidance() {
        PermissionResult result = permissionService.checkPermissions(
                Collections.singletonList("com.custom.malicious.BACKDOOR_SERVICE"));

        assertNotNull(result);
        assertEquals(1, result.getResults().size());
        assertEquals("REVIEW", result.getResults().get(0).getRecommendation());
        assertNotNull(result.getMandatoryWarning());
    }

    @Test
    @DisplayName("Audit: Cumulative scoring is strictly bounded at [0, 100]")
    void testScoreStrictlyBounded() {
        String maximumThreatText = "This is CBI Police Cyber Crime customs officer. You are under digital arrest. " +
                "Arrest warrant fir lodged for money laundering. Do not tell anyone, stay on skype video call. " +
                "Transfer Rs 1,00,000 security deposit to safe account immediately or be arrested today. " +
                "Enter your OTP password and net banking pin right now.";

        AnalysisResult result = messageAnalyzer.analyze(maximumThreatText);
        assertTrue(result.getScore() <= 100, "Score must never exceed 100, got: " + result.getScore());
        assertEquals(100, result.getScore(), "Extensive threats must cap at 100");
        assertEquals("High", result.getCategory());
        assertNotNull(result.getDisclaimer());
    }
}
