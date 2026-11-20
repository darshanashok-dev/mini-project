package com.cybersecurity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Frontend Assets & Security Integration Tests")
class FrontendIntegrationTest {

    @Test
    @DisplayName("Verify index.html exists, contains required titles, hero and privacy warnings")
    void testIndexHtmlIntegrity() throws Exception {
        InputStream is = getClass().getResourceAsStream("/static/index.html");
        assertNotNull(is, "static/index.html must exist on classpath");

        String html = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        // Core required text elements
        assertTrue(html.contains("Cybersecurity Awareness Platform"), "Must contain platform title");
        assertTrue(html.contains("Stay Alert. Stay Protected."), "Must contain hero heading");
        assertTrue(html.contains("Understand suspicious messages, inspect potentially deceptive links and learn how application permissions affect your privacy."),
                "Must contain hero subtitle");
        assertTrue(html.contains("Never enter confidential information, passwords, OTPs, banking details or private personal data."),
                "Must contain verbatim privacy warning");
        assertTrue(html.contains("The submitted URL is inspected as text only. The application does not open or visit the destination."),
                "Must contain prominent URL offline warning");
        assertTrue(html.contains("Permissions alone do not establish that an application is malicious. Consider the app's functionality, developer and source before making a decision."),
                "Must contain Android permission context warning");

        // Module presence
        assertTrue(html.contains("id=\"tab-message\""), "Must contain Message Analyzer module");
        assertTrue(html.contains("id=\"tab-url\""), "Must contain URL Analyzer module");
        assertTrue(html.contains("id=\"tab-permission\""), "Must contain Android Permission Analyzer module");

        // Character counter limits
        assertTrue(html.contains("maxlength=\"10000\""), "Message input must have 10,000 char limit");
        assertTrue(html.contains("maxlength=\"2048\""), "URL input must have 2,048 char limit");
    }

    @Test
    @DisplayName("Verify style.css exists and defines cybersecurity dark theme and responsive layout")
    void testStyleCssIntegrity() throws Exception {
        InputStream is = getClass().getResourceAsStream("/static/css/style.css");
        assertNotNull(is, "static/css/style.css must exist on classpath");

        String css = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        assertTrue(css.contains("--bg-primary: #0a0f1d"), "Must define dark navy primary background");
        assertTrue(css.contains("--accent-cyan: #00d2ff"), "Must define cyan accent color");
        assertTrue(css.contains("--risk-low"), "Must define Low risk styling");
        assertTrue(css.contains("--risk-medium"), "Must define Medium risk styling");
        assertTrue(css.contains("--risk-high"), "Must define High risk styling");
        assertTrue(css.contains("@media (max-width: 768px)"), "Must contain responsive media queries");
        assertTrue(css.contains(".score-meter-bar"), "Must contain score meter visualization styles");
    }

    @Test
    @DisplayName("Verify app.js strictly follows privacy constraints, uses Fetch API, and avoids unsafe innerHTML")
    void testAppJsSecurityAndPrivacy() throws Exception {
        InputStream is = getClass().getResourceAsStream("/static/js/app.js");
        assertNotNull(is, "static/js/app.js must exist on classpath");

        String js = new String(is.readAllBytes(), StandardCharsets.UTF_8);

        // API Endpoint integration
        assertTrue(js.contains("'/api/analyze/message'"), "Must integrate with message analysis endpoint");
        assertTrue(js.contains("'/api/analyze/url'"), "Must integrate with URL analysis endpoint");
        assertTrue(js.contains("'/api/permissions'"), "Must integrate with permissions catalog endpoint");
        assertTrue(js.contains("'/api/permissions/check'"), "Must integrate with permissions check endpoint");

        // Privacy: zero storage
        assertFalse(js.contains("localStorage"), "Frontend must NEVER use localStorage");
        assertFalse(js.contains("sessionStorage"), "Frontend must NEVER use sessionStorage");
        assertFalse(js.contains("document.cookie"), "Frontend must NEVER use document.cookie");
        assertFalse(js.contains("indexedDB"), "Frontend must NEVER use indexedDB");

        // Input clearing after analysis
        assertTrue(js.contains("inputMessage.value = ''"), "Must clear message input after analysis");
        assertTrue(js.contains("inputUrl.value = ''"), "Must clear URL input after analysis");

        // Safe DOM manipulation
        assertTrue(js.contains("document.createElement"), "Must use safe DOM createElement");
        assertTrue(js.contains("textContent"), "Must use textContent for untrusted data");
    }
}
