package com.cybersecurity.service;

import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.MatchedRule;
import com.cybersecurity.model.RulesConfig;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class ScoringEngine {

    private final RulesConfig rulesConfig;

    public ScoringEngine(RulesConfig rulesConfig) {
        this.rulesConfig = rulesConfig;
    }

    /**
     * Calculates the aggregate risk score:
     * S = min(100, sum of weights of all matched unique rules)
     * Each individual rule is counted only once per submission.
     */
    public int calculateScore(Collection<MatchedRule> matchedRules) {
        if (matchedRules == null || matchedRules.isEmpty()) {
            return 0;
        }

        // Deduplicate rules by their ID
        Map<String, Integer> uniqueWeights = new HashMap<>();
        for (MatchedRule rule : matchedRules) {
            if (rule != null && rule.getId() != null) {
                uniqueWeights.put(rule.getId(), rule.getWeight());
            }
        }

        int totalWeight = uniqueWeights.values().stream().mapToInt(Integer::intValue).sum();
        return Math.min(100, Math.max(0, totalWeight));
    }

    /**
     * Categorizes score into Low, Medium, or High according to exact thresholds:
     * 0–30: Low
     * 31–65: Medium
     * 66–100: High
     */
    public String determineCategory(int score) {
        int lowMax = (rulesConfig != null && rulesConfig.getThresholds() != null)
                ? rulesConfig.getThresholds().getLowMax() : 30;
        int mediumMax = (rulesConfig != null && rulesConfig.getThresholds() != null)
                ? rulesConfig.getThresholds().getMediumMax() : 65;

        if (score <= lowMax) {
            return "Low";
        } else if (score <= mediumMax) {
            return "Medium";
        } else {
            return "High";
        }
    }

    /**
     * Builds the complete AnalysisResult model.
     *
     * @param matchedRules list of detected rules
     * @param analysisType "message" or "url"
     * @return fully populated AnalysisResult
     */
    public AnalysisResult buildResult(List<MatchedRule> matchedRules, String analysisType) {
        // Deduplicate matchedRules by rule ID preserving order
        Map<String, MatchedRule> distinctMap = new LinkedHashMap<>();
        if (matchedRules != null) {
            for (MatchedRule r : matchedRules) {
                if (r != null && r.getId() != null) {
                    distinctMap.putIfAbsent(r.getId(), r);
                }
            }
        }
        List<MatchedRule> uniqueRules = new ArrayList<>(distinctMap.values());

        int score = calculateScore(uniqueRules);
        String category = determineCategory(score);

        String recommendedAction = getRecommendedAction(category);
        String safeHandlingTip = getSafeHandlingTip(analysisType);
        String disclaimer = (rulesConfig != null && rulesConfig.getDisclaimer() != null)
                ? rulesConfig.getDisclaimer()
                : "This result is advisory and does not prove that the message or URL is malicious or safe.";

        return new AnalysisResult(
                score,
                category,
                uniqueRules,
                recommendedAction,
                safeHandlingTip,
                disclaimer
        );
    }

    public String getRecommendedAction(String category) {
        if (rulesConfig != null && rulesConfig.getRecommendedActions() != null) {
            String key = category.toLowerCase(Locale.ROOT);
            if (rulesConfig.getRecommendedActions().containsKey(key)) {
                return rulesConfig.getRecommendedActions().get(key);
            }
        }

        switch (category) {
            case "High":
                return "Do not transfer money or share personal information. Report to authorities immediately.";
            case "Medium":
                return "Exercise strong caution. Independently verify claims through official contact channels.";
            case "Low":
            default:
                return "No standard indicators detected based on configured rules. Continue practicing security hygiene.";
        }
    }

    public String getSafeHandlingTip(String analysisType) {
        if (rulesConfig != null && rulesConfig.getSafeHandlingTips() != null) {
            String key = analysisType.toLowerCase(Locale.ROOT);
            if (rulesConfig.getSafeHandlingTips().containsKey(key)) {
                return rulesConfig.getSafeHandlingTips().get(key);
            }
        }
        return "Verify claims independently through official channels and never share OTPs or credentials.";
    }

    public RulesConfig getRulesConfig() {
        return rulesConfig;
    }
}
