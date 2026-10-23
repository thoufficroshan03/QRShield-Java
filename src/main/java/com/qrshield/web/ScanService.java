package com.qrshield.web;

import com.qrshield.core.AnalysisResult;
import com.qrshield.core.Analyzer;
import com.qrshield.core.Privacy;
import com.qrshield.core.RiskScorer;
import com.qrshield.data.ScanRepository;
import com.qrshield.data.ScanView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

/** One code path shared by /scan and /qr-scanner: analyze -> redact -> store. */
@Service
public class ScanService {
    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    public record Outcome(AnalysisResult analysis, Long scanId, String warning) {}

    private final ScanRepository repository;
    private final QrShieldProperties props;
    private final AppConfig.ProviderHolder providerHolder;

    public ScanService(ScanRepository repository, QrShieldProperties props, AppConfig.ProviderHolder providerHolder) {
        this.repository = repository;
        this.props = props;
        this.providerHolder = providerHolder;
    }

    public AnalysisResult run(String raw) {
        return Analyzer.analyze(raw, props.getMaxUrlLength(), props.getWeights(),
                new RiskScorer.Thresholds(props.getThresholdMedium(), props.getThresholdHigh()),
                providerHolder.provider());
    }

    public ScanView toView(AnalysisResult a, Long id, String inputType) {
        String shown = a.normalizedUrl() != null ? Privacy.redactUrl(a.normalizedUrl())
                : (a.originalUrl().length() > 200 ? a.originalUrl().substring(0, 200) : a.originalUrl());
        return new ScanView(id, inputType, shown, a.riskScore(), a.riskLevel(), a.summary(), a.indicators(),
                a.recommendations(), a.threatIntelligenceStatus(), a.threatIntelligenceDetail(), a.analysisTimestamp());
    }

    /** A database failure never loses the analysis: the warning is shown instead. */
    public Outcome analyzeAndStore(String raw, String inputType, boolean save) {
        AnalysisResult analysis = run(raw);
        if (!analysis.valid() || !save) return new Outcome(analysis, null, null);
        try {
            long id = repository.save(toView(analysis, null, inputType), Privacy.fingerprint(analysis.normalizedUrl()));
            return new Outcome(analysis, id, null);
        } catch (DataAccessException e) {
            log.error("Could not save scan", e);
            return new Outcome(analysis, null, "The analysis finished but could not be saved to history.");
        }
    }
}
