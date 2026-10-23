package com.qrshield.data;

import com.qrshield.core.Indicator;
import java.util.List;

/** One scan as shown on pages and stored in the database. id is null when the scan was not saved. */
public record ScanView(Long id, String inputType, String displayUrl, Integer riskScore, String riskLevel,
                       String summary, List<Indicator> indicators, List<String> recommendations,
                       String tiStatus, String tiDetail, String createdAt) {}
