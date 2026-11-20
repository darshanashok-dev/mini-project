package com.cybersecurity;

import com.cybersecurity.eval.EvaluationMetrics;
import com.cybersecurity.eval.EvaluationRunner;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Evaluation Harness Automation Tests")
class EvaluationRunnerTest {

    @Test
    @DisplayName("Run evaluation harness on benchmark dataset and verify accuracy and response times")
    void testEvaluationHarnessExecution() throws Exception {
        EvaluationRunner runner = new EvaluationRunner();
        EvaluationMetrics metrics = runner.runEvaluation("evaluation/dataset.json");

        assertNotNull(metrics);
        assertTrue(metrics.getTotalSamples() >= 20, "Dataset should have at least 20 samples");
        assertTrue(metrics.getPrecision() >= 0.85, "Precision should exceed 85%, got: " + metrics.getPrecision());
        assertTrue(metrics.getRecall() >= 0.85, "Recall should exceed 85%, got: " + metrics.getRecall());
        assertTrue(metrics.getMeanResponseTimeMs() < 1000.0,
                "Mean response time must be under 1000ms (1 second), got: " + metrics.getMeanResponseTimeMs() + "ms");
    }
}
