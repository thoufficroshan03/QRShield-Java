package com.qrshield.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Pure-Java tests of the analysis engine (no Spring, no network except a local fake server). */
@SuppressWarnings("null") // third-party Hamcrest/functional-interface @NonNull annotations absent in library sources
class CoreTest {
    private static final RiskScorer.Thresholds T = RiskScorer.Thresholds.defaults();

    private static RiskScorer.Scored run(String url) {
        return RiskScorer.score(UrlValidator.validate(url, 2048).parsed(), null, T);
    }

    private static Set<String> keys(String url) {
        return run(url).indicators().stream().map(Indicator::key).collect(Collectors.toSet());
    }

    // ---------------------------------------------------------------- validator
    @Test void validHttpsAndHttp() {
        var r = UrlValidator.validate("https://www.example.com/path?a=1#frag", 2048);
        assertTrue(r.valid());
        assertEquals("https", r.parsed().scheme());
        assertFalse(r.parsed().normalized().contains("#"));
        assertEquals("http", UrlValidator.validate("http://example.com", 2048).parsed().scheme());
    }

    @Test void emptyAndMalformedAreRejected() {
        for (String bad : new String[]{"", "   ", null, "http://", "https:///path", "http://exa mple.com",
                "http://-bad-.com", "http://exa%6dple.com", "example.com", "http:example.com"}) {
            assertFalse(UrlValidator.validate(bad, 2048).valid(), "should reject: " + bad);
        }
    }

    @Test void unsupportedSchemesAreRejected() {
        for (String bad : new String[]{"javascript:alert(1)", "file:///etc/passwd", "data:text/html,hi", "ftp://example.com"}) {
            var r = UrlValidator.validate(bad, 2048);
            assertFalse(r.valid());
            assertTrue(r.error().toLowerCase().contains("scheme"));
        }
    }

    @Test void credentialsDetectedAndStripped() {
        var r = UrlValidator.validate("http://paypal.com@evil.example/login", 2048);
        assertTrue(r.valid() && r.parsed().hasCredentials());
        assertFalse(r.parsed().normalized().contains("@"));
    }

    @Test void tooLongAndBadPorts() {
        assertFalse(UrlValidator.validate("http://example.com/" + "a".repeat(3000), 2048).valid());
        for (String port : new String[]{"0", "70000", "abc"}) {
            assertFalse(UrlValidator.validate("http://example.com:" + port + "/", 2048).valid());
        }
    }

    @Test void ipHostsAndPunycode() {
        assertTrue(UrlValidator.validate("http://192.168.0.1/x", 2048).parsed().isIp());
        assertTrue(UrlValidator.validate("http://2130706433/", 2048).parsed().ipLike());
        assertTrue(UrlValidator.validate("http://[::1]:8080/", 2048).parsed().isIp());
        var idn = UrlValidator.validate("http://b\u00fccher.example/", 2048);
        assertTrue(idn.valid() && idn.parsed().host().startsWith("xn--"));
    }

    // ---------------------------------------------------------------- scorer
    @Test void plainHttpsIsLowAndHttpAloneIsNotHigh() {
        var s = run("https://www.example.com/");
        assertEquals(0, s.score());
        assertEquals("Low Risk", s.level());
        assertEquals(10, run("http://example.com/").score());
        assertEquals("Low Risk", run("http://example.com/").level());
    }

    @Test void individualIndicators() {
        assertTrue(keys("http://192.168.1.5/login").contains("ip_host"));
        assertTrue(keys("https://example.com:4444/").contains("unusual_port"));
        assertTrue(keys("https://bit.ly/abc").contains("shortener"));
        assertTrue(keys("http://xn--pypal-4ve.com/").contains("punycode"));
        assertTrue(keys("https://example.com/setup.exe").contains("executable_download"));
        assertTrue(keys("https://a@example.com/").contains("credentials"));
        assertTrue(keys("https://example.com/%41%42%43%44%45").contains("heavy_encoding"));
    }

    @Test void lookalikeBrandDomainsAreFlaggedAsRisky() {
        assertTrue(keys("https://paypa1.com/login").contains("lookalike_domain"));
        assertTrue(keys("https://g00gle.com/").contains("lookalike_domain"));
        assertTrue(run("https://paypa1.com/login").score() >= 35);
        assertEquals("Medium Risk", run("https://paypa1.com/login").level());
        assertFalse(keys("https://www.paypal.com/signin").contains("lookalike_domain"));
    }

    @Test void suspiciousHostnameStructure() {
        Set<String> k = keys("https://paypal.com.secure-login.verify-account.evil.xyz/");
        assertTrue(k.containsAll(Set.of("brand_misuse", "many_subdomains", "keyword_combo")));
    }

    @Test void legitimateLookingUrlsAreNotOverFlagged() {
        assertFalse(keys("https://www.paypal.com/signin").contains("brand_misuse"));
        assertFalse(keys("https://business.example.com/").contains("brand_misuse"));
        assertFalse(keys("https://example.com/login").contains("keyword_combo"));
        assertTrue(keys("https://example.com/secure/login/verify").contains("keyword_combo"));
    }

    @Test void noDuplicatesSumAndCap() {
        var s = run("http://1.2.3.4:9999/login/verify/account/setup.exe?next=http://x@y");
        List<String> names = s.indicators().stream().map(Indicator::key).toList();
        assertEquals(names.size(), Set.copyOf(names).size());
        assertEquals(100, s.score());
        assertEquals("High Risk", s.level());
        var two = run("http://example.com:4444/");
        assertEquals(two.score(), two.indicators().stream().mapToInt(Indicator::contribution).sum());
    }

    @Test void boundariesAndConfigurableValues() {
        int[][] cases = {{0, 0}, {24, 0}, {25, 1}, {59, 1}, {60, 2}, {100, 2}};
        String[] names = {"Low Risk", "Medium Risk", "High Risk"};
        for (int[] c : cases) assertEquals(names[c[1]], RiskScorer.riskLevel(c[0], T));
        var p = UrlValidator.validate("http://example.com/", 2048).parsed();
        assertEquals("High Risk", RiskScorer.score(p, null, new RiskScorer.Thresholds(5, 9)).level());
        assertEquals(0, RiskScorer.score(p, Map.of("no_https", 0), T).score());
    }

    @Test void deterministic() {
        assertEquals(run("http://1.2.3.4/login").score(), run("http://1.2.3.4/login").score());
        assertEquals(run("http://1.2.3.4/login").indicators(), run("http://1.2.3.4/login").indicators());
    }

    // ---------------------------------------------------------------- analyzer / privacy
    @Test void analyzerStructureAndInvalidInput() {
        var good = Analyzer.analyze("https://example.com/", 2048, null, T, null);
        assertTrue(good.valid());
        assertEquals(ThreatIntelProvider.NOT_CONFIGURED, good.threatIntelligenceStatus());
        assertTrue(good.summary().contains("not a guarantee"));
        var bad = Analyzer.analyze("javascript:alert(1)", 2048, null, T, null);
        assertFalse(bad.valid());
        assertTrue(bad.riskScore() == null);
    }

    @Test void privacyRedaction() {
        String r = Privacy.redactUrl(UrlValidator.validate(
                "https://example.com/reset/abcdef1234567890abcdef12?token=SECRET&x=1#frag", 2048).parsed().normalized());
        assertFalse(r.contains("SECRET"));
        assertFalse(r.contains("abcdef1234567890abcdef12"));
        assertTrue(r.contains("token=[redacted]") && r.contains("x=[redacted]"));
        assertEquals(64, Privacy.fingerprint("x").length());
    }

    // ---------------------------------------------------------------- threat intelligence
    private static ThreatIntelProvider fake(ThreatIntelProvider.TiResult result, boolean explode) {
        return new ThreatIntelProvider() {
            public String name() { return "fake"; }
            public TiResult check(String url) {
                if (explode) throw new IllegalStateException("boom");
                return result;
            }
        };
    }

    @Test void providerBehaviourInAnalyzer() {
        var confirmed = Analyzer.analyze("https://example.com/", 2048, null, T,
                fake(new ThreatIntelProvider.TiResult(ThreatIntelProvider.CONFIRMED, "MALWARE", "fake"), false));
        assertEquals("High Risk", confirmed.riskLevel());
        var noMatch = Analyzer.analyze("https://example.com/", 2048, null, T,
                fake(new ThreatIntelProvider.TiResult(ThreatIntelProvider.NO_MATCH, "", "fake"), false));
        assertEquals(0, noMatch.riskScore().intValue());
        var broken = Analyzer.analyze("http://1.2.3.4/", 2048, null, T, fake(null, true));
        assertEquals(ThreatIntelProvider.UNAVAILABLE, broken.threatIntelligenceStatus());
        assertTrue(broken.riskScore().intValue() >= 30);
    }

    private static HttpServer server(int status, String body) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/", ex -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) ex.getResponseBody().write(bytes);
            ex.close();
        });
        s.start();
        return s;
    }

    @Test void safeBrowsingAgainstLocalFakeServer() throws Exception {
        for (Object[] c : new Object[][]{{200, "{}", ThreatIntelProvider.NO_MATCH},
                {200, "{\"matches\":[{\"threatType\":\"MALWARE\"}]}", ThreatIntelProvider.CONFIRMED},
                {429, "", ThreatIntelProvider.UNAVAILABLE}, {500, "", ThreatIntelProvider.UNAVAILABLE}}) {
            HttpServer s = server((Integer) c[0], (String) c[1]);
            try {
                var p = new SafeBrowsingProvider("KEY", Duration.ofSeconds(3),
                        "http://127.0.0.1:" + s.getAddress().getPort() + "/?key=");
                assertEquals(c[2], p.check("http://x.com/").status());
            } finally { s.stop(0); }
        }
        var unreachable = new SafeBrowsingProvider("KEY", Duration.ofMillis(500), "http://127.0.0.1:1/?key=");
        assertEquals(ThreatIntelProvider.UNAVAILABLE, unreachable.check("http://x.com/").status());
    }
}
