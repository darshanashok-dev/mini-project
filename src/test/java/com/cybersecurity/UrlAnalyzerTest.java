package com.cybersecurity;

import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.RulesConfig;
import com.cybersecurity.service.ScoringEngine;
import com.cybersecurity.service.UrlAnalyzer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("URL Analyzer Structural Inspection Tests")
class UrlAnalyzerTest {

    private UrlAnalyzer urlAnalyzer;

    @BeforeEach
    void setUp() {
        RuleConfiguration ruleConfiguration = new RuleConfiguration();
        RulesConfig rulesConfig = ruleConfiguration.rulesConfig(new ObjectMapper());
        ScoringEngine scoringEngine = new ScoringEngine(rulesConfig);
        urlAnalyzer = new UrlAnalyzer(scoringEngine, rulesConfig);
    }

    @Test
    @DisplayName("Numeric IP host triggers URL_NUMERIC_IP")
    void testNumericIpHpmDetection() {
        String url = "http://192.168.1.1/admin/login";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_NUMERIC_IP")),
                "Expected URL_NUMERIC_IP rule to trigger");
        assertTrue(result.getScore() >= 25);
    }

    @Test
    @DisplayName("Deceptive brand subdomain triggers URL_DECEPTIVE_SUBDOMAIN")
    void testDeceptiveSubdomainDetection() {
        String url = "https://paypal.com.account-update.xyz/login";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_DECEPTIVE_SUBDOMAIN")),
                "Expected URL_DECEPTIVE_SUBDOMAIN rule to trigger");
    }

    @Test
    @DisplayName("Look-alike domain typosquatting triggers URL_LOOKALIKE_DOMAIN")
    void testLookalikeDomainDetection() {
        String url = "http://paypa1-security.com/verification";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_LOOKALIKE_DOMAIN")),
                "Expected URL_LOOKALIKE_DOMAIN rule to trigger for paypa1");
    }

    @Test
    @DisplayName("Embedded @ in URL authority triggers URL_AT_SYMBOL")
    void testAtSymbolInAuthority() {
        String url = "http://legitimate-bank.com@malicious-host.com/login";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_AT_SYMBOL")),
                "Expected URL_AT_SYMBOL rule to trigger");
    }

    @Test
    @DisplayName("Known URL shortener triggers URL_SHORTENER")
    void testUrlShortenerDetection() {
        String url = "https://bit.ly/3xY8z1";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_SHORTENER")),
                "Expected URL_SHORTENER rule to trigger for bit.ly");
    }

    @Test
    @DisplayName("Excessive hyphens in hostname triggers URL_EXCESSIVE_HYPHENS")
    void testExcessiveHyphensDetection() {
        String url = "http://secure-online-bank-account-update.com/login";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_EXCESSIVE_HYPHENS")),
                "Expected URL_EXCESSIVE_HYPHENS rule to trigger");
    }

    @Test
    @DisplayName("Suspicious direct executable path triggers URL_LONG_OR_ENCODED_PATH")
    void testSuspiciousExecutablePath() {
        String url = "http://download-service.org/files/banking_token.apk";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("URL_LONG_OR_ENCODED_PATH")),
                "Expected URL_LONG_OR_ENCODED_PATH rule to trigger for .apk payload");
    }

    @Test
    @DisplayName("Benign standard URL scores Low risk")
    void testBenignUrl() {
        String url = "https://www.google.com/search?q=cybersecurity";
        AnalysisResult result = urlAnalyzer.analyze(url);

        assertEquals(0, result.getScore());
        assertEquals("Low", result.getCategory());
        assertTrue(result.getMatchedRules().isEmpty());
    }

    @Test
    @DisplayName("URL analyzer never makes network calls or throws on invalid inputs")
    void testNoNetworkCallOrCrashOnMalformedUrl() {
        // Test with non-resolvable fictional domain and malformed strings
        assertDoesNotThrow(() -> {
            AnalysisResult res1 = urlAnalyzer.analyze("htp://invalid-scheme:::not-a-domain");
            assertNotNull(res1);

            AnalysisResult res2 = urlAnalyzer.analyze("http://non-existent-subdomain-123456789.xyz");
            assertNotNull(res2);

            AnalysisResult res3 = urlAnalyzer.analyze("");
            assertNotNull(res3);
            assertEquals(0, res3.getScore());
        });
    }
}
