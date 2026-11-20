package com.cybersecurity;

import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.MatchedRule;
import com.cybersecurity.model.RulesConfig;
import com.cybersecurity.service.ScoringEngine;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Scoring Engine Specification Tests")
class ScoringEngineTest {

    private ScoringEngine scoringEngine;
    private RulesConfig rulesConfig;

    @BeforeEach
    void setUp() {
        RuleConfiguration ruleConfiguration = new RuleConfiguration();
        rulesConfig = ruleConfiguration.rulesConfig(new ObjectMapper());
        scoringEngine = new ScoringEngine(rulesConfig);
    }

    @Test
    @DisplayName("Zero score when no rules match")
    void testZeroScore() {
        int score = scoringEngine.calculateScore(Collections.emptyList());
        assertEquals(0, score, "Score should be 0 when no rules matched");

        String category = scoringEngine.determineCategory(score);
        assertEquals("Low", category, "Score of 0 must fall in Low category");
    }

    @Test
    @DisplayName("Normal weighted addition of distinct rules")
    void testNormalWeightedAddition() {
        List<MatchedRule> rules = Arrays.asList(
                new MatchedRule("RULE_A", "Rule A", 15, "evidence 1", "explanation 1"),
                new MatchedRule("RULE_B", "Rule B", 20, "evidence 2", "explanation 2")
        );
        int score = scoringEngine.calculateScore(rules);
        assertEquals(35, score, "Score should be 15 + 20 = 35");

        String category = scoringEngine.determineCategory(score);
        assertEquals("Medium", category, "Score 35 must fall in Medium category");
    }

    @Test
    @DisplayName("Duplicate rules are counted only once")
    void testDuplicateRuleDeduplication() {
        List<MatchedRule> rules = Arrays.asList(
                new MatchedRule("RULE_A", "Rule A", 15, "evidence 1", "explanation 1"),
                new MatchedRule("RULE_A", "Rule A", 15, "evidence 2", "explanation 1"),
                new MatchedRule("RULE_B", "Rule B", 20, "evidence 3", "explanation 2")
        );
        int score = scoringEngine.calculateScore(rules);
        assertEquals(35, score, "Duplicate rule RULE_A should be counted only once (15 + 20 = 35)");
    }

    @Test
    @DisplayName("Score is strictly capped at maximum of 100")
    void testScoreCappedAt100() {
        List<MatchedRule> rules = Arrays.asList(
                new MatchedRule("R1", "Rule 1", 30, "e1", "x1"),
                new MatchedRule("R2", "Rule 2", 30, "e2", "x2"),
                new MatchedRule("R3", "Rule 3", 30, "e3", "x3"),
                new MatchedRule("R4", "Rule 4", 30, "e4", "x4")
        );
        int score = scoringEngine.calculateScore(rules);
        assertEquals(100, score, "Sum of 120 must be capped at 100");
        assertEquals("High", scoringEngine.determineCategory(score));
    }

    @Test
    @DisplayName("Exact boundary values: 30 is Low, 31 is Medium, 65 is Medium, 66 is High")
    void testExactCategoryBoundaries() {
        // Boundary: 30 -> Low
        assertEquals("Low", scoringEngine.determineCategory(30), "Score 30 must be Low");

        // Boundary: 31 -> Medium
        assertEquals("Medium", scoringEngine.determineCategory(31), "Score 31 must be Medium");

        // Boundary: 65 -> Medium
        assertEquals("Medium", scoringEngine.determineCategory(65), "Score 65 must be Medium");

        // Boundary: 66 -> High
        assertEquals("High", scoringEngine.determineCategory(66), "Score 66 must be High");

        // Edge checks
        assertEquals("Low", scoringEngine.determineCategory(0), "Score 0 must be Low");
        assertEquals("High", scoringEngine.determineCategory(100), "Score 100 must be High");
    }

    @Test
    @DisplayName("Result construction populates safe action, handling tip, and disclaimer")
    void testBuildResult() {
        List<MatchedRule> rules = Collections.singletonList(
                new MatchedRule("MSG_ARREST_THREAT", "Arrest Threat", 20, "warrant issued", "threatens arrest")
        );
        AnalysisResult result = scoringEngine.buildResult(rules, "message");

        assertNotNull(result);
        assertEquals(20, result.getScore());
        assertEquals("Low", result.getCategory());
        assertEquals(1, result.getMatchedRules().size());
        assertNotNull(result.getRecommendedAction());
        assertNotNull(result.getSafeHandlingTip());
        assertNotNull(result.getDisclaimer());
        assertTrue(result.getDisclaimer().contains("advisory"), "Disclaimer must state that results are advisory");
    }
}
