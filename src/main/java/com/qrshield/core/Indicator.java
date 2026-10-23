package com.qrshield.core;

/** One explainable finding. "source" is "heuristic" or "threat_intelligence". */
public record Indicator(String key, String name, String explanation, int contribution,
                        String severity, String evidence, String recommendation, String source) {}
