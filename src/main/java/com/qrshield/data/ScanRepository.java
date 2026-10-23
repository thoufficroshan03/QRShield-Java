package com.qrshield.data;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.qrshield.core.Indicator;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

/** All SQL lives here. Every value is bound as a parameter (never concatenated into the SQL text). */
@Repository
public class ScanRepository {
    public static final List<String> LEVELS = List.of("Low Risk", "Medium Risk", "High Risk");

    public record ScanPage(List<ScanView> rows, long total) {}
    public record Stats(long total, Map<String, Long> byLevel, Map<String, Long> byType, List<ScanView> recent,
                        List<String> trendLabels, List<Long> trendValues) {}

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper = new ObjectMapper();

    public ScanRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    private String toJson(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException e) { throw new IllegalStateException(e); }
    }

    private final RowMapper<ScanView> rowMapper = (rs, i) -> {
        try {
            return new ScanView(rs.getLong("id"), rs.getString("input_type"), rs.getString("redacted_url"),
                    rs.getInt("risk_score"), rs.getString("risk_level"), rs.getString("analysis_summary"),
                    mapper.readValue(rs.getString("indicators_json"), new TypeReference<List<Indicator>>() {}),
                    mapper.readValue(rs.getString("recommendations_json"), new TypeReference<List<String>>() {}),
                    rs.getString("threat_intelligence_status"), rs.getString("threat_intelligence_detail"),
                    rs.getString("created_at"));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Corrupt stored scan", e);
        }
    };

    public long save(ScanView v, String urlHash) {
        Long id = jdbc.queryForObject(
                "INSERT INTO scans (input_type, redacted_url, url_hash, risk_score, risk_level, analysis_summary, "
                + "indicators_json, recommendations_json, threat_intelligence_status, threat_intelligence_detail, created_at) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING id",
                Long.class, v.inputType(), v.displayUrl(), urlHash, v.riskScore(), v.riskLevel(), v.summary(),
                toJson(v.indicators()), toJson(v.recommendations()), v.tiStatus(), v.tiDetail(), v.createdAt());
        return id == null ? -1 : id;
    }

    public Optional<ScanView> find(long id) {
        @SuppressWarnings("null") // Spring JDBC RowMapper param not annotated @NonNull in library
        var rows = jdbc.query("SELECT * FROM scans WHERE id = ?", rowMapper, id);
        return rows.stream().findFirst();
    }

    private static boolean validDate(String text) {
        try { LocalDate.parse(text); return true; } catch (DateTimeParseException | NullPointerException e) { return false; }
    }

    /** Filters are validated first, then bound as parameters. */
    public ScanPage list(String level, String from, String to, int page, int perPage) {
        List<String> clauses = new ArrayList<>();
        List<Object> params = new ArrayList<>();
        if (LEVELS.contains(level)) { clauses.add("risk_level = ?"); params.add(level); }
        if (validDate(from)) { clauses.add("substr(created_at, 1, 10) >= ?"); params.add(from); }
        if (validDate(to)) { clauses.add("substr(created_at, 1, 10) <= ?"); params.add(to); }
        String where = clauses.isEmpty() ? "" : " WHERE " + String.join(" AND ", clauses);
        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM scans" + where, Long.class, params.toArray());
        List<Object> pageParams = new ArrayList<>(params);
        pageParams.add(perPage);
        pageParams.add((long) (Math.max(page, 1) - 1) * perPage);
        @SuppressWarnings("null") // Spring JDBC RowMapper param not annotated @NonNull in library
        List<ScanView> rows = jdbc.query("SELECT * FROM scans" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                rowMapper, pageParams.toArray());
        return new ScanPage(rows, total == null ? 0 : total);
    }

    public Stats stats(int days) {
        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM scans", Long.class);
        Map<String, Long> byLevel = new LinkedHashMap<>();
        LEVELS.forEach(l -> byLevel.put(l, 0L));
        for (Map<String, Object> row : jdbc.queryForList("SELECT risk_level AS k, COUNT(*) AS n FROM scans GROUP BY risk_level")) {
            byLevel.put((String) row.get("k"), ((Number) row.get("n")).longValue());
        }
        Map<String, Long> byType = new LinkedHashMap<>();
        byType.put("url", 0L);
        byType.put("qr", 0L);
        for (Map<String, Object> row : jdbc.queryForList("SELECT input_type AS k, COUNT(*) AS n FROM scans GROUP BY input_type")) {
            byType.put((String) row.get("k"), ((Number) row.get("n")).longValue());
        }
        LocalDate today = LocalDate.now(ZoneOffset.UTC);
        LocalDate start = today.minusDays(days - 1L);
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Map<String, Object> row : jdbc.queryForList(
                "SELECT substr(created_at, 1, 10) AS d, COUNT(*) AS n FROM scans "
                + "WHERE substr(created_at, 1, 10) >= ? GROUP BY d", start.toString())) {
            counts.put((String) row.get("d"), ((Number) row.get("n")).longValue());
        }
        List<String> labels = new ArrayList<>();
        List<Long> values = new ArrayList<>();
        for (int i = 0; i < days; i++) {
            String d = start.plusDays(i).toString();
            labels.add(d);
            values.add(counts.getOrDefault(d, 0L));
        }
        @SuppressWarnings("null") // Spring JDBC RowMapper param not annotated @NonNull in library
        List<ScanView> recent = jdbc.query("SELECT * FROM scans ORDER BY id DESC LIMIT 5", rowMapper);
        return new Stats(total == null ? 0 : total, byLevel, byType, recent, labels, values);
    }

    public void clear() { jdbc.update("DELETE FROM scans"); }
}
