package com.cybersecurity.model;

import java.util.ArrayList;
import java.util.List;

public class PermissionResult {

    private List<PermissionInfo> results = new ArrayList<>();
    private String mandatoryWarning;

    public PermissionResult() {
    }

    public PermissionResult(List<PermissionInfo> results, String mandatoryWarning) {
        this.results = (results != null) ? results : new ArrayList<>();
        this.mandatoryWarning = mandatoryWarning;
    }

    public List<PermissionInfo> getResults() {
        return results;
    }

    public void setResults(List<PermissionInfo> results) {
        this.results = results;
    }

    public String getMandatoryWarning() {
        return mandatoryWarning;
    }

    public void setMandatoryWarning(String mandatoryWarning) {
        this.mandatoryWarning = mandatoryWarning;
    }
}
