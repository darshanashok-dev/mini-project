package com.cybersecurity.service;

import com.cybersecurity.model.PermissionInfo;
import com.cybersecurity.model.PermissionResult;
import com.cybersecurity.model.PermissionsConfig;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class PermissionService {

    private final PermissionsConfig permissionsConfig;
    private final Map<String, PermissionInfo> permissionMap;

    public PermissionService(PermissionsConfig permissionsConfig) {
        this.permissionsConfig = permissionsConfig;
        this.permissionMap = new LinkedHashMap<>();

        if (permissionsConfig != null && permissionsConfig.getPermissions() != null) {
            for (PermissionInfo p : permissionsConfig.getPermissions()) {
                String key = normalizePermission(p.getPermission());
                this.permissionMap.put(key, p);
            }
        }
    }

    /**
     * Returns the catalog of all sensitive permissions and guidance.
     */
    public List<PermissionInfo> getAllPermissions() {
        if (permissionsConfig != null && permissionsConfig.getPermissions() != null) {
            return Collections.unmodifiableList(permissionsConfig.getPermissions());
        }
        return Collections.emptyList();
    }

    /**
     * Checks requested permissions and returns explainable recommendations.
     * Provides safe default of REVIEW for any unknown permission.
     */
    public PermissionResult checkPermissions(List<String> requestedPermissions) {
        List<PermissionInfo> results = new ArrayList<>();
        String warning = (permissionsConfig != null && permissionsConfig.getMandatoryWarning() != null)
                ? permissionsConfig.getMandatoryWarning()
                : "Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source.";

        if (requestedPermissions == null || requestedPermissions.isEmpty()) {
            return new PermissionResult(results, warning);
        }

        // Deduplicate requested permissions preserving order
        Set<String> seen = new LinkedHashSet<>();
        for (String raw : requestedPermissions) {
            if (raw == null || raw.isBlank()) continue;
            String normalized = normalizePermission(raw);
            if (!seen.add(normalized)) continue;

            PermissionInfo known = permissionMap.get(normalized);
            if (known != null) {
                results.add(known);
            } else {
                // Safe default fallback for unrecognized permission
                PermissionInfo defaultInfo = createUnknownFallback(raw);
                results.add(defaultInfo);
            }
        }

        return new PermissionResult(results, warning);
    }

    public String getMandatoryWarning() {
        return (permissionsConfig != null && permissionsConfig.getMandatoryWarning() != null)
                ? permissionsConfig.getMandatoryWarning()
                : "Permissions alone never prove that an application is malware. Evaluate permissions in the context of the application's intended functionality, developer and source.";
    }

    private String normalizePermission(String permission) {
        String p = permission.trim().toUpperCase(Locale.ROOT);
        if (p.startsWith("ANDROID.PERMISSION.")) {
            return p.substring("ANDROID.PERMISSION.".length());
        }
        return p;
    }

    private PermissionInfo createUnknownFallback(String rawName) {
        PermissionInfo template = (permissionsConfig != null) ? permissionsConfig.getDefaultUnknownPermission() : null;
        if (template != null) {
            return new PermissionInfo(
                    rawName,
                    rawName,
                    template.getDescription(),
                    template.getCommonLegitimateUse(),
                    template.getSecurityRisk(),
                    "REVIEW",
                    template.getExplanation()
            );
        }
        return new PermissionInfo(
                rawName,
                rawName,
                "Permission not found in curated high-risk catalog.",
                "Application may require this for specific functionality.",
                "Unknown or uncatalogued permission.",
                "REVIEW",
                "Review the application's stated functionality and publisher reputation."
        );
    }
}
