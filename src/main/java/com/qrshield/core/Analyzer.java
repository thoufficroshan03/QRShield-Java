package com.qrshield.core;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Main URL analysis engine. Plain Java (no Spring), so it is easy to test and explain in a viva. */
public final class Analyzer {
    private Analyzer() {}

    private static String summary(int score, String level, int count) {
        if (level.equals("High Risk")) return "Score " + score + "/100: many strong warning signs were found (" + count + " indicators). Do not open this link unless you can verify it.";
        if (level.equals("Medium Risk")) return "Score " + score + "/100: some suspicious characteristics were found (" + count + " indicators). Verify the sender and the address before opening.";
        if (count > 0) return "Score " + score + "/100: few risk indicators were found. This is not a guarantee of safety.";
        return "Score " + score + "/100: the implemented checks found no risk indicators. This is not a guarantee of safety.";
    }

    public static AnalysisResult analyze(String raw, int maxLength, Map<String, Integer> weights,
                                         RiskScorer.Thresholds thresholds, ThreatIntelProvider provider) {
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        UrlValidator.ValidationResult check = UrlValidator.validate(raw, maxLength);
        String original = raw == null ? "" : raw;
        if (!check.valid()) {
            return new AnalysisResult(original, null, false, check.error(), null, null, check.error(),
                    List.of(), List.of(), now, ThreatIntelProvider.NOT_CONFIGURED, "");
        }
        ParsedUrl parsed = check.parsed();
        RiskScorer.Scored scored = RiskScorer.score(parsed, weights, thresholds);
        List<Indicator> indicators = new ArrayList<>(scored.indicators());
        int score = scored.score();
        String level = scored.level();

        // Optional external lookup: a failure here never stops the local analysis.
        ThreatIntelProvider.TiResult ti;
        if (provider == null) {
            ti = new ThreatIntelProvider.TiResult(ThreatIntelProvider.NOT_CONFIGURED,
                    "No threat-intelligence provider is configured.", "");
        } else {
            try {
                ti = provider.check(parsed.normalized());
            } catch (RuntimeException e) {
                ti = new ThreatIntelProvider.TiResult(ThreatIntelProvider.UNAVAILABLE, "Provider unavailable.", provider.name());
            }
        }
        if (ThreatIntelProvider.CONFIRMED.equals(ti.status())) {
            indicators.add(new Indicator("provider_match", "Confirmed match in threat-intelligence feed",
                    "An external provider lists this URL as dangerous.", 0, "High", ti.detail(),
                    "Do not open this link.", "threat_intelligence"));
            score = Math.max(score, 90); // a verified finding overrides the heuristic score
            level = RiskScorer.riskLevel(score, thresholds);
        }

        List<String> recommendations = new ArrayList<>();
        for (Indicator i : indicators) if (!recommendations.contains(i.recommendation())) recommendations.add(i.recommendation());
        recommendations.add("Never enter passwords or payment details after following an unexpected link.");

        return new AnalysisResult(original, parsed.normalized(), true, null, Math.max(0, Math.min(100, score)), level,
                summary(score, level, indicators.size()), List.copyOf(indicators), List.copyOf(recommendations),
                now, ti.status(), ti.detail());
    }
}
