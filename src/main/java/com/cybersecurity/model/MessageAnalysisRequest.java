package com.cybersecurity.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class MessageAnalysisRequest {

    @NotBlank(message = "Message text cannot be empty or blank")
    @Size(max = 10000, message = "Message text exceeds maximum allowed length of 10,000 characters")
    private String text;

    public MessageAnalysisRequest() {
    }

    public MessageAnalysisRequest(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }
}
