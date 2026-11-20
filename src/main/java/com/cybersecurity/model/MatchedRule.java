package com.cybersecurity.model;

import java.util.Objects;

public class MatchedRule {

    private String id;
    private String name;
    private int weight;
    private String matchedText;
    private String explanation;

    public MatchedRule() {
    }

    public MatchedRule(String id, String name, int weight, String matchedText, String explanation) {
        this.id = id;
        this.name = name;
        this.weight = weight;
        this.matchedText = matchedText;
        this.explanation = explanation;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getWeight() {
        return weight;
    }

    public void setWeight(int weight) {
        this.weight = weight;
    }

    public String getMatchedText() {
        return matchedText;
    }

    public void setMatchedText(String matchedText) {
        this.matchedText = matchedText;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MatchedRule that = (MatchedRule) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
