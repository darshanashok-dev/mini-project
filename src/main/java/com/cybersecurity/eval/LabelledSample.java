package com.cybersecurity.eval;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class LabelledSample {

    private String id;
    private String type; // "message" or "url"

    @JsonAlias({"actualClassification", "classification"})
    private String label; // "SUSPICIOUS" or "BENIGN"

    private String source;

    @JsonAlias({"content", "sampleText", "inputContent"})
    private String text;

    private String explanation;

    public LabelledSample() {
    }

    public LabelledSample(String id, String type, String label, String source, String text, String explanation) {
        this.id = id;
        this.type = type;
        this.label = label;
        this.source = source;
        this.text = text;
        this.explanation = explanation;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }
}
