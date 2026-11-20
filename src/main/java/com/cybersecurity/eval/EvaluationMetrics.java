package com.cybersecurity.eval;

public class EvaluationMetrics {

    private int totalSamples;
    private int truePositives;
    private int falsePositives;
    private int trueNegatives;
    private int falseNegatives;

    private double meanResponseTimeMs;
    private double maxResponseTimeMs;

    public EvaluationMetrics() {
    }

    public void record(boolean actualSuspicious, boolean predictedSuspicious) {
        totalSamples++;
        if (actualSuspicious && predictedSuspicious) {
            truePositives++;
        } else if (!actualSuspicious && predictedSuspicious) {
            falsePositives++;
        } else if (!actualSuspicious && !predictedSuspicious) {
            trueNegatives++;
        } else {
            falseNegatives++;
        }
    }

    public double getPrecision() {
        int denominator = truePositives + falsePositives;
        return (denominator == 0) ? 0.0 : (double) truePositives / denominator;
    }

    public double getRecall() {
        int denominator = truePositives + falseNegatives;
        return (denominator == 0) ? 0.0 : (double) truePositives / denominator;
    }

    public double getFalsePositiveRate() {
        int denominator = falsePositives + trueNegatives;
        return (denominator == 0) ? 0.0 : (double) falsePositives / denominator;
    }

    public double getAccuracy() {
        if (totalSamples == 0) return 0.0;
        return (double) (truePositives + trueNegatives) / totalSamples;
    }

    public int getCorrectPredictions() {
        return truePositives + trueNegatives;
    }

    public int getIncorrectPredictions() {
        return falsePositives + falseNegatives;
    }

    public int getTotalSamples() { return totalSamples; }
    public int getTruePositives() { return truePositives; }
    public int getFalsePositives() { return falsePositives; }
    public int getTrueNegatives() { return trueNegatives; }
    public int getFalseNegatives() { return falseNegatives; }
    public double getMeanResponseTimeMs() { return meanResponseTimeMs; }
    public void setMeanResponseTimeMs(double meanResponseTimeMs) { this.meanResponseTimeMs = meanResponseTimeMs; }
    public double getMaxResponseTimeMs() { return maxResponseTimeMs; }
    public void setMaxResponseTimeMs(double maxResponseTimeMs) { this.maxResponseTimeMs = maxResponseTimeMs; }

    public String formatReport(String title) {
        StringBuilder sb = new StringBuilder();
        sb.append("================================================================================\n");
        sb.append(String.format(" %s\n", title));
        sb.append("================================================================================\n");
        sb.append(String.format(" Total Samples Analyzed : %d\n", totalSamples));
        sb.append(String.format(" Correct Predictions    : %d (%.2f%%)\n", getCorrectPredictions(), getAccuracy() * 100));
        sb.append(String.format(" Incorrect Predictions  : %d (%.2f%%)\n", getIncorrectPredictions(), (1.0 - getAccuracy()) * 100));
        sb.append(String.format(" True Positives (TP)    : %d\n", truePositives));
        sb.append(String.format(" False Positives (FP)   : %d\n", falsePositives));
        sb.append(String.format(" True Negatives (TN)    : %d\n", trueNegatives));
        sb.append(String.format(" False Negatives (FN)   : %d\n", falseNegatives));
        sb.append("--------------------------------------------------------------------------------\n");
        sb.append(String.format(" Accuracy               : %.2f%%\n", getAccuracy() * 100));
        sb.append(String.format(" Precision              : %.2f%%\n", getPrecision() * 100));
        sb.append(String.format(" Recall (Sensitivity)   : %.2f%%\n", getRecall() * 100));
        sb.append(String.format(" False Positive Rate    : %.2f%%\n", getFalsePositiveRate() * 100));
        sb.append("--------------------------------------------------------------------------------\n");
        sb.append(String.format(" Mean Response Time     : %.3f ms\n", meanResponseTimeMs));
        sb.append(String.format(" Max Response Time      : %.3f ms\n", maxResponseTimeMs));
        sb.append("================================================================================\n");
        return sb.toString();
    }
}
