package com.cybersecurity.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class UrlAnalysisRequest {

    @NotBlank(message = "URL cannot be empty or blank")
    @Size(max = 2048, message = "URL exceeds maximum allowed length of 2,048 characters")
    private String url;

    public UrlAnalysisRequest() {
    }

    public UrlAnalysisRequest(String url) {
        this.url = url;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
