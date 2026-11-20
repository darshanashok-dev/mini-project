package com.cybersecurity.model;

import java.util.ArrayList;
import java.util.List;

public class AnalysisResult {

    private int score;
    private String category;
    private List<MatchedRule> matchedRules = new ArrayList<>();
    private String recommendedAction;
    private String safeHandlingTip;
    private String disclaimer;

    public AnalysisResult() {
    }

    public AnalysisResult(int score, String category, List<MatchedRule> matchedRules,
                          String recommendedAction, String safeHandlingTip, String disclaimer) {
        this.score = score;
        this.category = category;
        this.matchedRules = (matchedRules != null) ? matchedRules : new ArrayList<>();
        this.recommendedAction = recommendedAction;
        this.safeHandlingTip = safeHandlingTip;
        this.disclaimer = disclaimer;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public List<MatchedRule> getMatchedRules() {
        return matchedRules;
    }

    public void setMatchedRules(List<MatchedRule> matchedRules) {
        this.matchedRules = matchedRules;
    }

    public String getRecommendedAction() {
        return recommendedAction;
    }

    public void setRecommendedAction(String recommendedAction) {
        this.recommendedAction = recommendedAction;
    }

    public String getSafeHandlingTip() {
        return safeHandlingTip;
    }

    public void setSafeHandlingTip(String safeHandlingTip) {
        this.safeHandlingTip = safeHandlingTip;
    }

    public String getDisclaimer() {
        return disclaimer;
    }

    public void setDisclaimer(String disclaimer) {
        this.disclaimer = disclaimer;
    }
}
