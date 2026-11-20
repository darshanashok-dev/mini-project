package com.cybersecurity.service;

import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.MatchedRule;
import com.cybersecurity.model.RulesConfig;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MessageAnalyzer {

    private final ScoringEngine scoringEngine;
    private final List<CompiledMessageRule> compiledRules;

    private static class CompiledMessageRule {
        final RulesConfig.MessageRuleDef definition;
        final List<Pattern> patterns;
        final List<Pattern> benignExceptionPatterns;

        CompiledMessageRule(RulesConfig.MessageRuleDef definition) {
            this.definition = definition;
            this.patterns = new ArrayList<>();
            this.benignExceptionPatterns = new ArrayList<>();

            if (definition.getPatterns() != null) {
                for (String p : definition.getPatterns()) {
                    this.patterns.add(Pattern.compile(p, Pattern.CASE_INSENSITIVE));
                }
            }
            if (definition.getBenignExceptions() != null) {
                for (String bp : definition.getBenignExceptions()) {
                    this.benignExceptionPatterns.add(Pattern.compile(bp, Pattern.CASE_INSENSITIVE));
                }
            }
        }
    }

    public MessageAnalyzer(ScoringEngine scoringEngine, RulesConfig rulesConfig) {
        this.scoringEngine = scoringEngine;
        this.compiledRules = new ArrayList<>();

        if (rulesConfig != null && rulesConfig.getMessageRules() != null) {
            for (RulesConfig.MessageRuleDef ruleDef : rulesConfig.getMessageRules()) {
                this.compiledRules.add(new CompiledMessageRule(ruleDef));
            }
        }
    }

    /**
     * Analyzes incoming message text against compiled detection rules.
     * Evaluates context to prevent false positives on legitimate security warnings.
     *
     * @param text raw input message
     * @return explainable AnalysisResult
     */
    public AnalysisResult analyze(String text) {
        if (text == null || text.isBlank()) {
            return scoringEngine.buildResult(Collections.emptyList(), "message");
        }

        List<MatchedRule> matchedRules = new ArrayList<>();

        for (CompiledMessageRule rule : compiledRules) {
            // Check if message matches any benign advisory exception for this rule
            boolean isBenignException = false;
            for (Pattern exceptionPattern : rule.benignExceptionPatterns) {
                if (exceptionPattern.matcher(text).find()) {
                    isBenignException = true;
                    break;
                }
            }

            if (isBenignException) {
                // Rule suppressed due to legitimate advisory context (e.g. "Never share your OTP")
                continue;
            }

            // Test detection patterns
            for (Pattern pattern : rule.patterns) {
                Matcher matcher = pattern.matcher(text);
                if (matcher.find()) {
                    String snippet = extractSnippet(text, matcher.start(), matcher.end());
                    matchedRules.add(new MatchedRule(
                            rule.definition.getId(),
                            rule.definition.getName(),
                            rule.definition.getWeight(),
                            snippet,
                            rule.definition.getExplanation()
                    ));
                    break; // Count each rule at most once per submission
                }
            }
        }

        return scoringEngine.buildResult(matchedRules, "message");
    }

    /**
     * Extracts a contextual snippet around the matched region.
     */
    private String extractSnippet(String text, int start, int end) {
        int contextRadius = 25;
        int snippetStart = Math.max(0, start - contextRadius);
        int snippetEnd = Math.min(text.length(), end + contextRadius);

        String prefix = (snippetStart > 0) ? "..." : "";
        String suffix = (snippetEnd < text.length()) ? "..." : "";

        return prefix + text.substring(snippetStart, snippetEnd).trim() + suffix;
    }
}
