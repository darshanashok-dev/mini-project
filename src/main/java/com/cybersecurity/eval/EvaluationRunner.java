package com.cybersecurity.eval;

import com.cybersecurity.config.RuleConfiguration;
import com.cybersecurity.model.AnalysisResult;
import com.cybersecurity.model.RulesConfig;
import com.cybersecurity.service.MessageAnalyzer;
import com.cybersecurity.service.ScoringEngine;
import com.cybersecurity.service.UrlAnalyzer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class EvaluationRunner {

    private final MessageAnalyzer messageAnalyzer;
    private final UrlAnalyzer urlAnalyzer;
    private final ObjectMapper objectMapper;

    public EvaluationRunner() {
        this.objectMapper = new ObjectMapper();
        RuleConfiguration ruleConfig = new RuleConfiguration();
        RulesConfig rules = ruleConfig.rulesConfig(objectMapper);
        ScoringEngine scoringEngine = new ScoringEngine(rules);
        this.messageAnalyzer = new MessageAnalyzer(scoringEngine, rules);
        this.urlAnalyzer = new UrlAnalyzer(scoringEngine, rules);
    }

    public EvaluationRunner(MessageAnalyzer messageAnalyzer, UrlAnalyzer urlAnalyzer) {
        this.objectMapper = new ObjectMapper();
        this.messageAnalyzer = messageAnalyzer;
        this.urlAnalyzer = urlAnalyzer;
    }

    public static void main(String[] args) {
        try {
            System.out.println("================================================================================");
            System.out.println("  Cybersecurity Awareness Platform - Benchmark Evaluation Runner");
            System.out.println("================================================================================\n");
            EvaluationRunner runner = new EvaluationRunner();
            String datasetPath = (args.length > 0) ? args[0] : "evaluation/dataset.json";
            runner.runEvaluation(datasetPath);
        } catch (Exception e) {
            System.err.println("Evaluation harness failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    public EvaluationMetrics runEvaluation(String datasetPath) throws Exception {
        long totalHarnessStartTime = System.nanoTime();
        List<LabelledSample> samples = loadDataset(datasetPath);

        System.out.println("Application Name        : Cybersecurity Awareness Platform");
        System.out.println("Dataset Filename        : " + datasetPath);
        System.out.println("Dataset Size            : " + samples.size() + " samples");
        System.out.println("Scoring Classification  : Low (0-30), Medium (31-65), High (66-100)");
        System.out.println("Prediction Rules        : Low -> BENIGN, Medium -> SUSPICIOUS, High -> SUSPICIOUS");

        EvaluationMetrics overallMetrics = new EvaluationMetrics();
        EvaluationMetrics messageMetrics = new EvaluationMetrics();
        EvaluationMetrics urlMetrics = new EvaluationMetrics();

        List<Double> responseTimesMs = new ArrayList<>();
        double maxTimeMs = 0.0;

        System.out.println("\n--------------------------------------------------------------------------------");
        System.out.printf("%-12s | %-8s | %-11s | %-8s | %-6s | %-8s\n",
                "Sample ID", "Type", "GroundTruth", "Score", "Risk", "Time (ms)");
        System.out.println("--------------------------------------------------------------------------------");

        for (LabelledSample sample : samples) {
            long startTime = System.nanoTime();
            AnalysisResult result;

            String sampleContent = (sample.getText() != null) ? sample.getText() : sample.getId();

            if ("url".equalsIgnoreCase(sample.getType())) {
                result = urlAnalyzer.analyze(sampleContent);
            } else {
                result = messageAnalyzer.analyze(sampleContent);
            }

            long elapsedNanos = System.nanoTime() - startTime;
            double elapsedMs = elapsedNanos / 1_000_000.0;
            responseTimesMs.add(elapsedMs);
            if (elapsedMs > maxTimeMs) {
                maxTimeMs = elapsedMs;
            }

            // Standard academic prediction rule:
            // - Low = Predicted BENIGN
            // - Medium = Predicted SUSPICIOUS
            // - High = Predicted SUSPICIOUS
            boolean actualSuspicious = "suspicious".equalsIgnoreCase(sample.getLabel());
            boolean predictedSuspicious = "Medium".equalsIgnoreCase(result.getCategory())
                    || "High".equalsIgnoreCase(result.getCategory());

            overallMetrics.record(actualSuspicious, predictedSuspicious);
            if ("url".equalsIgnoreCase(sample.getType())) {
                urlMetrics.record(actualSuspicious, predictedSuspicious);
            } else {
                messageMetrics.record(actualSuspicious, predictedSuspicious);
            }

            System.out.printf("%-12s | %-8s | %-11s | %-8d | %-6s | %-8.3f\n",
                    sample.getId(),
                    sample.getType(),
                    sample.getLabel().toUpperCase(),
                    result.getScore(),
                    result.getCategory(),
                    elapsedMs);
        }

        double meanTimeMs = responseTimesMs.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
        overallMetrics.setMeanResponseTimeMs(meanTimeMs);
        overallMetrics.setMaxResponseTimeMs(maxTimeMs);

        messageMetrics.setMeanResponseTimeMs(
                responseTimesMs.stream().limit(12).mapToDouble(Double::doubleValue).average().orElse(0.0));
        messageMetrics.setMaxResponseTimeMs(
                responseTimesMs.stream().limit(12).mapToDouble(Double::doubleValue).max().orElse(0.0));

        urlMetrics.setMeanResponseTimeMs(
                responseTimesMs.stream().skip(12).mapToDouble(Double::doubleValue).average().orElse(0.0));
        urlMetrics.setMaxResponseTimeMs(
                responseTimesMs.stream().skip(12).mapToDouble(Double::doubleValue).max().orElse(0.0));

        double totalHarnessTimeMs = (System.nanoTime() - totalHarnessStartTime) / 1_000_000.0;

        System.out.println();
        System.out.println(overallMetrics.formatReport("OVERALL PERFORMANCE SUMMARY"));
        System.out.println(messageMetrics.formatReport("MESSAGE ANALYZER BREAKDOWN"));
        System.out.println(urlMetrics.formatReport("URL ANALYZER BREAKDOWN"));
        System.out.printf("Total Evaluation Execution Time: %.2f ms\n", totalHarnessTimeMs);
        System.out.println("================================================================================\n");

        return overallMetrics;
    }

    public List<LabelledSample> loadDataset(String datasetPath) throws Exception {
        File file = new File(datasetPath);
        JsonNode rootNode;

        if (file.exists()) {
            rootNode = objectMapper.readTree(file);
        } else {
            // Attempt loading from classpath
            try (InputStream is = getClass().getClassLoader().getResourceAsStream("examples.json")) {
                if (is != null) {
                    rootNode = objectMapper.readTree(is);
                } else {
                    throw new IllegalArgumentException("Dataset file not found at " + datasetPath + " or on classpath.");
                }
            }
        }

        JsonNode samplesNode = rootNode.get("samples");
        List<LabelledSample> list = new ArrayList<>();
        if (samplesNode != null && samplesNode.isArray()) {
            for (JsonNode sn : samplesNode) {
                LabelledSample sample = objectMapper.treeToValue(sn, LabelledSample.class);
                if (sample.getText() == null && sn.has("content")) {
                    sample.setText(sn.get("content").asText());
                }
                if (sample.getLabel() == null && sn.has("actualClassification")) {
                    sample.setLabel(sn.get("actualClassification").asText());
                }
                list.add(sample);
            }
        }
        return list;
    }
}
