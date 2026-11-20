package com.cybersecurity;

import com.cybersecurity.config.PermissionConfiguration;
import com.cybersecurity.model.PermissionInfo;
import com.cybersecurity.model.PermissionResult;
import com.cybersecurity.model.PermissionsConfig;
import com.cybersecurity.service.PermissionService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Android Permission Guidance Service Tests")
class PermissionServiceTest {

    private PermissionService permissionService;

    @BeforeEach
    void setUp() {
        PermissionConfiguration permissionConfiguration = new PermissionConfiguration();
        PermissionsConfig config = permissionConfiguration.permissionsConfig(new ObjectMapper());
        permissionService = new PermissionService(config);
    }

    @Test
    @DisplayName("Catalog loads all sensitive permissions")
    void testGetAllPermissions() {
        List<PermissionInfo> all = permissionService.getAllPermissions();
        assertNotNull(all);
        assertTrue(all.size() >= 15, "Catalog should have at least 15 sensitive permissions");

        assertTrue(all.stream().anyMatch(p -> p.getPermission().equals("READ_SMS")));
        assertTrue(all.stream().anyMatch(p -> p.getPermission().equals("BIND_ACCESSIBILITY_SERVICE")));
        assertTrue(all.stream().anyMatch(p -> p.getPermission().equals("CAMERA")));
    }

    @Test
    @DisplayName("High risk permissions recommend DENY")
    void testDenyRecommendations() {
        PermissionResult result = permissionService.checkPermissions(
                Arrays.asList("READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW")
        );

        assertNotNull(result);
        assertEquals(3, result.getResults().size());

        for (PermissionInfo info : result.getResults()) {
            assertEquals("DENY", info.getRecommendation(),
                    info.getPermission() + " should have DENY recommendation");
        }
    }

    @Test
    @DisplayName("Context-dependent permissions recommend REVIEW")
    void testReviewRecommendations() {
        PermissionResult result = permissionService.checkPermissions(
                Arrays.asList("CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION")
        );

        assertNotNull(result);
        for (PermissionInfo info : result.getResults()) {
            assertEquals("REVIEW", info.getRecommendation(),
                    info.getPermission() + " should recommend REVIEW");
        }
    }

    @Test
    @DisplayName("Unrecognized permission defaults safely to REVIEW")
    void testUnknownPermissionDefaultsToReview() {
        PermissionResult result = permissionService.checkPermissions(
                Collections.singletonList("COM.VENDOR.CUSTOM_UNKNOWN_PERMISSION")
        );

        assertNotNull(result);
        assertEquals(1, result.getResults().size());
        PermissionInfo unknown = result.getResults().get(0);

        assertEquals("COM.VENDOR.CUSTOM_UNKNOWN_PERMISSION", unknown.getPermission());
        assertEquals("REVIEW", unknown.getRecommendation(), "Unknown permission must default safely to REVIEW");
        assertNotNull(unknown.getExplanation());
    }

    @Test
    @DisplayName("Mandatory warning is included with permission results")
    void testMandatoryWarningPresent() {
        PermissionResult result = permissionService.checkPermissions(Collections.singletonList("READ_SMS"));

        assertNotNull(result.getMandatoryWarning());
        assertTrue(result.getMandatoryWarning().contains("Permissions alone never prove that an application is malware"),
                "Mandatory warning must be included");
    }

    @Test
    @DisplayName("Permission name normalizes prefixes like android.permission.")
    void testNormalizationOfAndroidPermissionPrefix() {
        PermissionResult result = permissionService.checkPermissions(
                Collections.singletonList("android.permission.READ_SMS")
        );

        assertEquals(1, result.getResults().size());
        assertEquals("READ_SMS", result.getResults().get(0).getPermission());
        assertEquals("DENY", result.getResults().get(0).getRecommendation());
    }
}
