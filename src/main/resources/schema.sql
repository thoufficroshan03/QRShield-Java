CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_type TEXT NOT NULL CHECK (input_type IN ('url', 'qr')),
    redacted_url TEXT NOT NULL,
    url_hash TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL,
    analysis_summary TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    recommendations_json TEXT NOT NULL,
    threat_intelligence_status TEXT NOT NULL,
    threat_intelligence_detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans (risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_url_hash ON scans (url_hash);
