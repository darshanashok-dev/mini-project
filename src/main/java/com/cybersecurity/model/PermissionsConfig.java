package com.cybersecurity.model;

import java.util.ArrayList;
import java.util.List;

public class PermissionsConfig {

    private String mandatoryWarning;
    private PermissionInfo defaultUnknownPermission;
    private List<PermissionInfo> permissions = new ArrayList<>();

    public String getMandatoryWarning() {
        return mandatoryWarning;
    }

    public void setMandatoryWarning(String mandatoryWarning) {
        this.mandatoryWarning = mandatoryWarning;
    }

    public PermissionInfo getDefaultUnknownPermission() {
        return defaultUnknownPermission;
    }

    public void setDefaultUnknownPermission(PermissionInfo defaultUnknownPermission) {
        this.defaultUnknownPermission = defaultUnknownPermission;
    }

    public List<PermissionInfo> getPermissions() {
        return permissions;
    }

    public void setPermissions(List<PermissionInfo> permissions) {
        this.permissions = permissions;
    }
}
