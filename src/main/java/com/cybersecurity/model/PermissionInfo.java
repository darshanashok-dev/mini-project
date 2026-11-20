package com.cybersecurity.model;

public class PermissionInfo {

    private String permission;
    private String name;
    private String description;
    private String commonLegitimateUse;
    private String securityRisk;
    private String recommendation; // "ALLOW", "DENY", "REVIEW"
    private String explanation;

    public PermissionInfo() {
    }

    public PermissionInfo(String permission, String name, String description,
                          String commonLegitimateUse, String securityRisk,
                          String recommendation, String explanation) {
        this.permission = permission;
        this.name = name;
        this.description = description;
        this.commonLegitimateUse = commonLegitimateUse;
        this.securityRisk = securityRisk;
        this.recommendation = recommendation;
        this.explanation = explanation;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCommonLegitimateUse() {
        return commonLegitimateUse;
    }

    public void setCommonLegitimateUse(String commonLegitimateUse) {
        this.commonLegitimateUse = commonLegitimateUse;
    }

    public String getSecurityRisk() {
        return securityRisk;
    }

    public void setSecurityRisk(String securityRisk) {
        this.securityRisk = securityRisk;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }
}
