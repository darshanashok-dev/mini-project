package com.cybersecurity;

import com.cybersecurity.config.PermissionConfiguration;
import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.controller.AnalysisController;
import com.cybersecurity.exception.GlobalExceptionHandler;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName("Analysis Controller REST API Tests")
class ControllerTest {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        ObjectMapper objectMapper = new ObjectMapper();
        RuleConfiguration ruleConfig = new RuleConfiguration();
        RulesConfig rules = ruleConfig.rulesConfig(objectMapper);
        PermissionConfiguration permConfig = new PermissionConfiguration();
        PermissionsConfig perms = permConfig.permissionsConfig(objectMapper);

        ScoringEngine scoringEngine = new ScoringEngine(rules);
        MessageAnalyzer messageAnalyzer = new MessageAnalyzer(scoringEngine, rules);
        UrlAnalyzer urlAnalyzer = new UrlAnalyzer(scoringEngine, rules);
        PermissionService permissionService = new PermissionService(perms);

        AnalysisController controller = new AnalysisController(messageAnalyzer, urlAnalyzer, permissionService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("POST /api/analyze/message with valid payload returns HTTP 200")
    void testAnalyzeMessageSuccess() throws Exception {
        String jsonPayload = "{\"text\": \"Meeting tomorrow at 10 AM in Conference Room B.\"}";

        mockMvc.perform(post("/api/analyze/message")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(0))
                .andExpect(jsonPath("$.category").value("Low"))
                .andExpect(jsonPath("$.disclaimer").exists());
    }

    @Test
    @DisplayName("POST /api/analyze/message with blank text returns HTTP 400 Bad Request")
    void testAnalyzeMessageBlank() throws Exception {
        String jsonPayload = "{\"text\": \"   \"}";

        mockMvc.perform(post("/api/analyze/message")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.error").exists());
    }

    @Test
    @DisplayName("POST /api/analyze/url with valid payload returns HTTP 200")
    void testAnalyzeUrlSuccess() throws Exception {
        String jsonPayload = "{\"url\": \"http://192.168.1.1/login\"}";

        mockMvc.perform(post("/api/analyze/url")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.score").value(25))
                .andExpect(jsonPath("$.category").value("Low"))
                .andExpect(jsonPath("$.matchedRules[0].id").value("URL_NUMERIC_IP"));
    }

    @Test
    @DisplayName("POST /api/analyze/url with empty string returns HTTP 400 Bad Request")
    void testAnalyzeUrlEmpty() throws Exception {
        String jsonPayload = "{\"url\": \"\"}";

        mockMvc.perform(post("/api/analyze/url")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    @DisplayName("GET /api/permissions returns permission catalog")
    void testListPermissions() throws Exception {
        mockMvc.perform(get("/api/permissions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].permission").exists())
                .andExpect(jsonPath("$[0].recommendation").exists());
    }

    @Test
    @DisplayName("POST /api/permissions/check returns analyzed recommendations")
    void testCheckPermissions() throws Exception {
        String jsonPayload = "{\"permissions\": [\"READ_SMS\", \"CAMERA\"]}";

        mockMvc.perform(post("/api/permissions/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.results[0].permission").value("READ_SMS"))
                .andExpect(jsonPath("$.results[0].recommendation").value("DENY"))
                .andExpect(jsonPath("$.results[1].permission").value("CAMERA"))
                .andExpect(jsonPath("$.results[1].recommendation").value("REVIEW"))
                .andExpect(jsonPath("$.mandatoryWarning").exists());
    }
}
