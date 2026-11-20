package com.cybersecurity;

import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.MatchedRule;
import com.cybersecurity.model.RulesConfig;
import com.cybersecurity.service.MessageAnalyzer;
import com.cybersecurity.service.ScoringEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Message Analyzer Detection Tests")
class MessageAnalyzerTest {

    private MessageAnalyzer messageAnalyzer;

    @BeforeEach
    void setUp() {
        RuleConfiguration ruleConfiguration = new RuleConfiguration();
        RulesConfig rulesConfig = ruleConfiguration.rulesConfig(new ObjectMapper());
        ScoringEngine scoringEngine = new ScoringEngine(rulesConfig);
        messageAnalyzer = new MessageAnalyzer(scoringEngine, rulesConfig);
    }

    @Test
    @DisplayName("Impersonation rule triggers on law enforcement / authority claims")
    void testImpersonationDetection() {
        String msg = "This is Inspector Sharma from Central Bureau of Investigation and CBI.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_IMPERSONATION")),
                "Expected MSG_IMPERSONATION to trigger");
        assertEquals(15, result.getScore());
    }

    @Test
    @DisplayName("Urgency / Fear rule triggers on immediate deadline threats")
    void testUrgencyDetection() {
        String msg = "Your SIM card will be deactivated within 24 hours without delay.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_URGENCY_FEAR")),
                "Expected MSG_URGENCY_FEAR to trigger");
        assertEquals(10, result.getScore());
    }

    @Test
    @DisplayName("Arrest threat rule triggers on arrest warrants or money laundering claims")
    void testArrestThreatDetection() {
        String msg = "A non-bailable arrest warrant has been issued against you for money laundering.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_ARREST_THREAT")),
                "Expected MSG_ARREST_THREAT to trigger");
        assertEquals(20, result.getScore());
    }

    @Test
    @DisplayName("Secrecy / Isolation rule triggers on demands to stay on video call or maintain secrecy")
    void testSecrecyIsolationDetection() {
        String msg = "Do not tell anyone about this call, keep this confidential and stay on Skype video call.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_SECRECY_ISOLATION")),
                "Expected MSG_SECRECY_ISOLATION to trigger");
        assertEquals(15, result.getScore());
    }

    @Test
    @DisplayName("Payment demand rule triggers on requests for security deposits or safe accounts")
    void testPaymentDemandDetection() {
        String msg = "You must transfer money to the RBI safe verification account immediately.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_PAYMENT_DEMAND")),
                "Expected MSG_PAYMENT_DEMAND to trigger");
    }

    @Test
    @DisplayName("Credential request triggers when asking to share OTP or password")
    void testCredentialRequestDetection() {
        String msg = "Please enter your OTP and update your password to unfreeze your bank account.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertTrue(result.getMatchedRules().stream().anyMatch(r -> r.getId().equals("MSG_CREDENTIAL_REQUEST")),
                "Expected MSG_CREDENTIAL_REQUEST to trigger");
    }

    @Test
    @DisplayName("Legitimate bank security advisory does NOT trigger credential theft (Context-Aware)")
    void testBenignSecurityAdvisoryOtpExclusion() {
        String msg = "Security Alert: Never share your OTP, PIN or password with anyone. Bank will never ask for your OTP.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        // Should NOT trigger MSG_CREDENTIAL_REQUEST because it is an explicit safety advisory
        boolean credentialTriggered = result.getMatchedRules().stream()
                .anyMatch(r -> r.getId().equals("MSG_CREDENTIAL_REQUEST"));
        assertFalse(credentialTriggered, "Legitimate safety warning 'never share OTP' must not trigger credential theft rule");
    }

    @Test
    @DisplayName("Full Digital Arrest scam script triggers High risk score")
    void testFullDigitalArrestScamScript() {
        String scamScript = "This is Officer Verma from Cyber Crime Police and CBI. "
                + "A parcel containing narcotics was seized by customs under your name. "
                + "A case has been filed and an arrest warrant is issued. "
                + "Do not tell anyone and stay on video call in a closed room. "
                + "You must transfer Rs 50,000 security deposit to the safe verification account immediately.";

        AnalysisResult result = messageAnalyzer.analyze(scamScript);

        assertTrue(result.getScore() >= 66, "Full digital arrest script must score High (>= 66), got: " + result.getScore());
        assertEquals("High", result.getCategory());
        assertTrue(result.getMatchedRules().size() >= 4, "Should match at least 4 scam indicators");
    }

    @Test
    @DisplayName("Repeated appearances of the same indicator count only once")
    void testRuleCountedOnceDespiteRepeatedKeywords() {
        String msg = "Urgent! Urgent! Immediately within 24 hours immediately action required!";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        long count = result.getMatchedRules().stream().filter(r -> r.getId().equals("MSG_URGENCY_FEAR")).count();
        assertEquals(1, count, "MSG_URGENCY_FEAR should be counted exactly once");
        assertEquals(10, result.getScore());
    }

    @Test
    @DisplayName("Benign conversational message scores 0 and Low risk")
    void testBenignMessage() {
        String msg = "Hey John, are we still meeting for lunch at 1 PM today? Let me know.";
        AnalysisResult result = messageAnalyzer.analyze(msg);

        assertEquals(0, result.getScore());
        assertEquals("Low", result.getCategory());
        assertTrue(result.getMatchedRules().isEmpty());
    }
}
