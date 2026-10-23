package com.qrshield.core;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Redacts URLs before storage: credentials/fragment are already removed by the validator,
 * every query VALUE becomes [redacted] (keys kept) and token-like path segments are masked.
 * This reduces, but does NOT guarantee removal of, sensitive data.
 */
public final class Privacy {
    private static final int MAX_STORED_LENGTH = 500;
    private static final Pattern TOKEN_CHARS = Pattern.compile("[A-Za-z0-9_\\-=.%]+");
    private Privacy() {}

    static boolean looksLikeToken(String segment) {
        if (segment == null || !TOKEN_CHARS.matcher(segment).matches()) return false;
        boolean hasDigit = segment.chars().anyMatch(Character::isDigit);
        return segment.length() >= 32 || (segment.length() >= 20 && hasDigit);
    }

    public static String redactUrl(String normalized) {
        int schemeEnd = normalized.indexOf("://") + 3;
        int pathStart = normalized.indexOf('/', schemeEnd);
        int queryStart = normalized.indexOf('?');
        String origin = pathStart < 0 ? normalized : normalized.substring(0, pathStart);
        String path = pathStart < 0 ? "" : normalized.substring(pathStart, queryStart < 0 ? normalized.length() : queryStart);
        String query = queryStart < 0 ? "" : normalized.substring(queryStart + 1);

        String[] segments = path.split("/", -1);
        for (int i = 0; i < segments.length; i++) if (looksLikeToken(segments[i])) segments[i] = "[redacted]";
        StringBuilder out = new StringBuilder(origin).append(String.join("/", segments));

        if (!query.isEmpty()) {
            StringBuilder q = new StringBuilder();
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eq = pair.indexOf('=');
                String key = eq < 0 ? pair : pair.substring(0, eq);
                if (key.length() > 40) key = key.substring(0, 40);
                if (q.length() > 0) q.append('&');
                q.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append("=[redacted]");
            }
            if (q.length() > 0) out.append('?').append(q);
        }
        return out.length() > MAX_STORED_LENGTH ? out.substring(0, MAX_STORED_LENGTH) : out.toString();
    }

    /** SHA-256 of the normalized URL, used to recognise repeated scans. */
    public static String fingerprint(String normalized) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
