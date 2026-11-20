package com.cybersecurity.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RulesConfig {

    private Thresholds thresholds = new Thresholds();
    private Limits limits = new Limits();
    private List<KnownBrand> knownBrands = new ArrayList<>();
    private List<String> knownShorteners = new ArrayList<>();
    private List<MessageRuleDef> messageRules = new ArrayList<>();
    private List<UrlRuleDef> urlRules = new ArrayList<>();
    private String disclaimer;
    private Map<String, String> recommendedActions = new HashMap<>();
    private Map<String, String> safeHandlingTips = new HashMap<>();

    public static class Thresholds {
        private int lowMax = 30;
        private int mediumMax = 65;
        private int highMax = 100;

        public int getLowMax() { return lowMax; }
        public void setLowMax(int lowMax) { this.lowMax = lowMax; }
        public int getMediumMax() { return mediumMax; }
        public void setMediumMax(int mediumMax) { this.mediumMax = mediumMax; }
        public int getHighMax() { return highMax; }
        public void setHighMax(int highMax) { this.highMax = highMax; }
    }

    public static class Limits {
        private int maxMessageLength = 10000;
        private int maxUrlLength = 2048;

        public int getMaxMessageLength() { return maxMessageLength; }
        public void setMaxMessageLength(int maxMessageLength) { this.maxMessageLength = maxMessageLength; }
        public int getMaxUrlLength() { return maxUrlLength; }
        public void setMaxUrlLength(int maxUrlLength) { this.maxUrlLength = maxUrlLength; }
    }

    public static class KnownBrand {
        private String name;
        private String officialDomain;

        public KnownBrand() {}
        public KnownBrand(String name, String officialDomain) {
            this.name = name;
            this.officialDomain = officialDomain;
        }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getOfficialDomain() { return officialDomain; }
        public void setOfficialDomain(String officialDomain) { this.officialDomain = officialDomain; }
    }

    public static class MessageRuleDef {
        private String id;
        private String name;
        private String category;
        private int weight;
        private List<String> patterns = new ArrayList<>();
        private List<String> benignExceptions = new ArrayList<>();
        private String explanation;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
        public List<String> getPatterns() { return patterns; }
        public void setPatterns(List<String> patterns) { this.patterns = patterns; }
        public List<String> getBenignExceptions() { return benignExceptions; }
        public void setBenignExceptions(List<String> benignExceptions) { this.benignExceptions = benignExceptions; }
        public String getExplanation() { return explanation; }
        public void setExplanation(String explanation) { this.explanation = explanation; }
    }

    public static class UrlRuleDef {
        private String id;
        private String name;
        private int weight;
        private String explanation;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public int getWeight() { return weight; }
        public void setWeight(int weight) { this.weight = weight; }
        public String getExplanation() { return explanation; }
        public void setExplanation(String explanation) { this.explanation = explanation; }
    }

    public Thresholds getThresholds() { return thresholds; }
    public void setThresholds(Thresholds thresholds) { this.thresholds = thresholds; }
    public Limits getLimits() { return limits; }
    public void setLimits(Limits limits) { this.limits = limits; }
    public List<KnownBrand> getKnownBrands() { return knownBrands; }
    public void setKnownBrands(List<KnownBrand> knownBrands) { this.knownBrands = knownBrands; }
    public List<String> getKnownShorteners() { return knownShorteners; }
    public void setKnownShorteners(List<String> knownShorteners) { this.knownShorteners = knownShorteners; }
    public List<MessageRuleDef> getMessageRules() { return messageRules; }
    public void setMessageRules(List<MessageRuleDef> messageRules) { this.messageRules = messageRules; }
    public List<UrlRuleDef> getUrlRules() { return urlRules; }
    public void setUrlRules(List<UrlRuleDef> urlRules) { this.urlRules = urlRules; }
    public String getDisclaimer() { return disclaimer; }
    public void setDisclaimer(String disclaimer) { this.disclaimer = disclaimer; }
    public Map<String, String> getRecommendedActions() { return recommendedActions; }
    public void setRecommendedActions(Map<String, String> recommendedActions) { this.recommendedActions = recommendedActions; }
    public Map<String, String> getSafeHandlingTips() { return safeHandlingTips; }
    public void setSafeHandlingTips(Map<String, String> safeHandlingTips) { this.safeHandlingTips = safeHandlingTips; }
}
