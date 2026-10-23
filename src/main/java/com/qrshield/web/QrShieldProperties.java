package com.qrshield.web;

import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Settings bound from application.properties (prefix "qrshield"). */
@ConfigurationProperties(prefix = "qrshield")
public class QrShieldProperties {
    private int maxUrlLength = 2048;
    private int thresholdMedium = 25;
    private int thresholdHigh = 60;
    private long maxImagePixels = 12_000_000L;
    private int pageSize = 10;
    private String tmpDir = "instance/tmp";
    private String tiProvider = "none";
    private String safeBrowsingApiKey = "";
    private int tiTimeoutSeconds = 5;
    private Map<String, Integer> weights = new HashMap<>(); // optional overrides of rule weights

    public int getMaxUrlLength() { return maxUrlLength; }
    public void setMaxUrlLength(int v) { this.maxUrlLength = v; }
    public int getThresholdMedium() { return thresholdMedium; }
    public void setThresholdMedium(int v) { this.thresholdMedium = v; }
    public int getThresholdHigh() { return thresholdHigh; }
    public void setThresholdHigh(int v) { this.thresholdHigh = v; }
    public long getMaxImagePixels() { return maxImagePixels; }
    public void setMaxImagePixels(long v) { this.maxImagePixels = v; }
    public int getPageSize() { return pageSize; }
    public void setPageSize(int v) { this.pageSize = v; }
    public String getTmpDir() { return tmpDir; }
    public void setTmpDir(String v) { this.tmpDir = v; }
    public String getTiProvider() { return tiProvider; }
    public void setTiProvider(String v) { this.tiProvider = v; }
    public String getSafeBrowsingApiKey() { return safeBrowsingApiKey; }
    public void setSafeBrowsingApiKey(String v) { this.safeBrowsingApiKey = v; }
    public int getTiTimeoutSeconds() { return tiTimeoutSeconds; }
    public void setTiTimeoutSeconds(int v) { this.tiTimeoutSeconds = v; }
    public Map<String, Integer> getWeights() { return weights; }
    public void setWeights(Map<String, Integer> v) { this.weights = v; }
}
