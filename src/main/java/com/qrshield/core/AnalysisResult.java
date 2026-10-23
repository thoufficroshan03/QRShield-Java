package com.qrshield.core;

import java.util.List;

/** The structured result returned by the analyzer (same fields as the Python version). */
public record AnalysisResult(String originalUrl, String normalizedUrl, boolean valid, String error,
                             Integer riskScore, String riskLevel, String summary, List<Indicator> indicators,
                             List<String> recommendations, String analysisTimestamp,
                             String threatIntelligenceStatus, String threatIntelligenceDetail) {}
