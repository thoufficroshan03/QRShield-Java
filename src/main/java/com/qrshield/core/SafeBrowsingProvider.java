package com.qrshield.core;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Google Safe Browsing v4 lookup. The URL STRING is sent to Google; this class never visits the URL.
 * Any failure (timeout, rate limit, bad response) becomes "unavailable" and never throws.
 * "no_match" is not proof that a URL is safe.
 */
public class SafeBrowsingProvider implements ThreatIntelProvider {
    private static final Pattern THREAT_TYPE = Pattern.compile("\"threatType\"\\s*:\\s*\"([A-Z_]+)\"");
    private final String apiKey;
    private final Duration timeout;
    private final String endpoint;
    private final HttpClient client;

    public SafeBrowsingProvider(String apiKey, Duration timeout) {
        this(apiKey, timeout, "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=");
    }

    /** Endpoint is injectable so tests can point to a local fake server. */
    public SafeBrowsingProvider(String apiKey, Duration timeout, String endpoint) {
        this.apiKey = apiKey;
        this.timeout = timeout;
        this.endpoint = endpoint;
        this.client = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    @Override public String name() { return "Google Safe Browsing"; }

    static String jsonEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    @Override
    public TiResult check(String url) {
        String body = "{\"client\":{\"clientId\":\"qrshield\",\"clientVersion\":\"1.0\"},\"threatInfo\":{"
                + "\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],"
                + "\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],"
                + "\"threatEntries\":[{\"url\":\"" + jsonEscape(url) + "\"}]}}";
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint + apiKey)).timeout(timeout)
                    .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 429) return new TiResult(UNAVAILABLE, "Provider unavailable: rate limit reached", name());
            if (response.statusCode() != 200) return new TiResult(UNAVAILABLE, "Provider unavailable: HTTP error " + response.statusCode(), name());
            if (response.body().contains("\"matches\"")) {
                Set<String> kinds = new TreeSet<>();
                Matcher m = THREAT_TYPE.matcher(response.body());
                while (m.find()) kinds.add(m.group(1));
                return new TiResult(CONFIRMED, "Listed by provider as: " + (kinds.isEmpty() ? "UNKNOWN" : String.join(", ", kinds)), name());
            }
            return new TiResult(NO_MATCH, "The provider reported no match. This does not prove the URL is safe.", name());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new TiResult(UNAVAILABLE, "Provider unavailable (interrupted)", name());
        } catch (IOException | RuntimeException e) {
            return new TiResult(UNAVAILABLE, "Provider unavailable (network error or timeout)", name());
        }
    }
}
