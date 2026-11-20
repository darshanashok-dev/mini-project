package com.cybersecurity.controller;

import com.cybersecurity.model.*;
import com.cybersecurity.service.MessageAnalyzer;
import com.cybersecurity.service.PermissionService;
import com.cybersecurity.service.UrlAnalyzer;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // Permissive CORS for academic/local environments
public class AnalysisController {

    private static final Logger logger = LoggerFactory.getLogger(AnalysisController.class);

    private final MessageAnalyzer messageAnalyzer;
    private final UrlAnalyzer urlAnalyzer;
    private final PermissionService permissionService;

    public AnalysisController(MessageAnalyzer messageAnalyzer,
                              UrlAnalyzer urlAnalyzer,
                              PermissionService permissionService) {
        this.messageAnalyzer = messageAnalyzer;
        this.urlAnalyzer = urlAnalyzer;
        this.permissionService = permissionService;
    }

    /**
     * Endpoint 1: Message Analysis
     * Evaluates message text against rule sets. Input content is never logged or stored.
     */
    @PostMapping("/analyze/message")
    public ResponseEntity<AnalysisResult> analyzeMessage(@Valid @RequestBody MessageAnalysisRequest request) {
        logger.info("Received message analysis request (length: {} chars)",
                (request.getText() != null) ? request.getText().length() : 0);

        AnalysisResult result = messageAnalyzer.analyze(request.getText());
        return ResponseEntity.ok(result);
    }

    /**
     * Endpoint 2: URL Analysis
     * Structural inspection only. Destination is NEVER requested, fetched, or resolved.
     */
    @PostMapping("/analyze/url")
    public ResponseEntity<AnalysisResult> analyzeUrl(@Valid @RequestBody UrlAnalysisRequest request) {
        logger.info("Received URL analysis request (length: {} chars)",
                (request.getUrl() != null) ? request.getUrl().length() : 0);

        AnalysisResult result = urlAnalyzer.analyze(request.getUrl());
        return ResponseEntity.ok(result);
    }

    /**
     * Endpoint 3: List Known Permissions
     * Returns catalog of sensitive Android permissions.
     */
    @GetMapping("/permissions")
    public ResponseEntity<List<PermissionInfo>> listPermissions() {
        logger.info("Received request to list sensitive permissions catalog");
        List<PermissionInfo> permissions = permissionService.getAllPermissions();
        return ResponseEntity.ok(permissions);
    }

    /**
     * Endpoint 4: Check Selected Permissions
     * Analyzes selected permissions and provides explainable recommendations.
     */
    @PostMapping("/permissions/check")
    public ResponseEntity<PermissionResult> checkPermissions(@Valid @RequestBody PermissionRequest request) {
        logger.info("Received permission check request (count: {})",
                (request.getPermissions() != null) ? request.getPermissions().size() : 0);

        PermissionResult result = permissionService.checkPermissions(request.getPermissions());
        return ResponseEntity.ok(result);
    }
}
