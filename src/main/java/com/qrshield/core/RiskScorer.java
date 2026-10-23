package com.qrshield.core;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Transparent, rule-based scoring. Each rule is a small function that either returns nothing
 * or one Indicator. A rule can add its weight at most ONCE, so duplicates cannot inflate the score.
 * Score = min(100, sum of triggered weights). There is no randomness anywhere.
 */
public final class RiskScorer {
    public record Thresholds(int medium, int high) {
        public static Thresholds defaults() { return new Thresholds(25, 60); }
    }
    public record Scored(int score, String level, List<Indicator> indicators) {}

    @FunctionalInterface
    private interface Rule { Optional<Indicator> apply(ParsedUrl p, int weight); }

    public static final Map<String, Integer> DEFAULT_WEIGHTS = new LinkedHashMap<>();
    static {
        DEFAULT_WEIGHTS.put("no_https", 10);        DEFAULT_WEIGHTS.put("ip_host", 30);
        DEFAULT_WEIGHTS.put("many_subdomains", 15); DEFAULT_WEIGHTS.put("brand_misuse", 25);
        DEFAULT_WEIGHTS.put("credentials", 30);     DEFAULT_WEIGHTS.put("long_url", 8);
        DEFAULT_WEIGHTS.put("heavy_encoding", 10);  DEFAULT_WEIGHTS.put("unusual_port", 12);
        DEFAULT_WEIGHTS.put("punycode", 20);        DEFAULT_WEIGHTS.put("keyword_combo", 20);
        DEFAULT_WEIGHTS.put("shortener", 15);       DEFAULT_WEIGHTS.put("hyphens", 10);
        DEFAULT_WEIGHTS.put("executable_download", 20); DEFAULT_WEIGHTS.put("embedded_url", 8);
        DEFAULT_WEIGHTS.put("lookalike_domain", 35);
    }

    private static final Set<Integer> COMMON_PORTS = Set.of(80, 443, 8080, 8443);
    private static final Set<String> MULTI_PART_TLDS = Set.of("co.uk", "org.uk", "ac.uk", "com.au", "net.au",
            "co.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn", "gov.in", "ac.in", "org.in", "net.in");
    private static final Set<String> BRANDS = new TreeSet<>(Set.of("paypal", "google", "microsoft", "apple",
            "amazon", "facebook", "instagram", "netflix", "whatsapp", "paytm", "phonepe", "sbi", "hdfc", "icici",
            "binance", "coinbase", "metamask", "dhl", "fedex", "linkedin"));
    private static final List<String> KEYWORDS = List.of("login", "signin", "verify", "secure", "account",
            "update", "password", "confirm", "banking", "wallet", "suspend", "unlock", "billing", "payment",
            "otp", "kyc", "reward", "prize");
    private static final Set<String> SHORTENERS = Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
            "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "t.ly", "tiny.cc", "rb.gy", "lnkd.in");
    private static final List<String> RISKY_EXTENSIONS = List.of(".exe", ".apk", ".scr", ".msi", ".bat", ".cmd",
            ".jar", ".vbs", ".ps1");
    private static final Pattern PERCENT = Pattern.compile("%[0-9a-fA-F]{2}");
    private static final Pattern EMBEDDED = Pattern.compile("https?(://|%3a%2f%2f)", Pattern.CASE_INSENSITIVE);

    private static final Map<String, Rule> RULES = new LinkedHashMap<>();
    static {
        RULES.put("no_https", (p, w) -> !p.scheme().equals("http") ? Optional.empty() : ind("no_https",
                "Unencrypted HTTP connection",
                "The link uses HTTP, so data sent to the site is not encrypted. (HTTPS alone would not prove a site is legitimate either.)",
                w, "Scheme: http", "Avoid entering passwords or personal data on this site."));

        RULES.put("ip_host", (p, w) -> !(p.isIp() || p.ipLike()) ? Optional.empty() : ind("ip_host",
                "IP address used as hostname",
                "Legitimate services normally use domain names. Raw or obfuscated IP addresses are common in phishing and malware links.",
                w, "Host: " + p.host(), "Do not open it unless you know exactly who owns this address."));

        RULES.put("many_subdomains", (p, w) -> {
            if (isIpHost(p)) return Optional.empty();
            int subs = subdomains(p.host()).size();
            return subs < 3 ? Optional.empty() : ind("many_subdomains", "Unusually many subdomains",
                    "Attackers stack subdomains to push the real domain out of view.", w,
                    subs + " subdomain levels in " + p.host(),
                    "Check the LAST part of the hostname: that is who really owns the site.");
        });

        RULES.put("brand_misuse", (p, w) -> {
            if (isIpHost(p)) return Optional.empty();
            List<String> subs = subdomains(p.host());
            List<String> reg = registrable(p.host());
            String regName = reg.get(0);
            Set<String> subTokens = new TreeSet<>();
            for (String label : subs) subTokens.addAll(List.of(label.split("-")));
            Set<String> regTokens = Set.of(regName.split("-"));
            for (String brand : BRANDS) {
                if (subTokens.contains(brand) || (regTokens.contains(brand) && !regName.equals(brand))) {
                    return ind("brand_misuse", "Well-known brand name in a misleading position",
                            "The hostname contains a famous brand name but the domain that actually owns the site is different.",
                            w, "Brand '" + brand + "' appears, but the real domain is " + String.join(".", reg),
                            "Type the brand's official address yourself instead of using this link.");
                }
            }
            return Optional.empty();
        });

        // Detect typo-squatted domains such as paypa1.com, g00gle-login.example,
        // or amaz0n.example. This compares the registrable domain label, not the path.
        RULES.put("lookalike_domain", (p, w) -> {
            if (isIpHost(p)) return Optional.empty();
            String domainLabel = registrable(p.host()).get(0);
            String normalizedLabel = normalizeLookalike(domainLabel);
            for (String brand : BRANDS) {
                if (domainLabel.equals(brand)) continue; // exact brand domain is not a clone by itself
                int distance = editDistance(normalizedLabel, brand);
                int allowed = brand.length() >= 7 ? 2 : 1;
                if (normalizedLabel.equals(brand) || (Math.min(normalizedLabel.length(), brand.length()) >= 5
                        && distance <= allowed)) {
                    return ind("lookalike_domain", "Domain resembles a well-known brand",
                            "The registered domain is very similar to a known brand name. Clone and typo-squatting sites often change one or two characters to look genuine.",
                            w, "Domain label '" + domainLabel + "' resembles brand '" + brand + "'",
                            "Do not sign in or enter payment details. Open the brand's official website directly.");
                }
            }
            return Optional.empty();
        });

        RULES.put("credentials", (p, w) -> !p.hasCredentials() ? Optional.empty() : ind("credentials",
                "Embedded username/password in the URL",
                "Text before an '@' in the address is treated as a login, and is often used to disguise the real destination.",
                w, "A username (and possibly password) is embedded (value hidden)",
                "Do not open this link; the visible text before '@' is not the site."));

        RULES.put("long_url", (p, w) -> p.normalized().length() <= 100 ? Optional.empty() : ind("long_url",
                "Very long URL",
                "Long URLs can hide the real destination. Many legitimate links are long too, so this is only a weak signal.",
                w, "Length: " + p.normalized().length() + " characters", "Read the hostname carefully."));

        RULES.put("heavy_encoding", (p, w) -> {
            Matcher m = PERCENT.matcher(p.path() + "?" + p.query());
            int count = 0;
            while (m.find()) count++;
            return count < 5 ? Optional.empty() : ind("heavy_encoding", "Heavily percent-encoded URL",
                    "Many %XX sequences can be used to obscure what the link contains.", w,
                    count + " encoded sequences", "Be cautious with links you did not expect.");
        });

        RULES.put("unusual_port", (p, w) -> p.port() == null || COMMON_PORTS.contains(p.port()) ? Optional.empty()
                : ind("unusual_port", "Unusual port number",
                "Normal websites use ports 80/443. Other ports are sometimes used for temporary malicious servers.",
                w, "Port: " + p.port(), "Only continue if you know why this port is used."));

        RULES.put("punycode", (p, w) -> {
            if (isIpHost(p)) return Optional.empty();
            for (String label : p.host().split("\\.")) {
                if (label.startsWith("xn--")) {
                    return ind("punycode", "Internationalized (punycode) hostname",
                            "Look-alike characters from other alphabets can imitate a real domain (a homograph attack). Many legitimate IDNs exist too.",
                            w, "Host shown as: " + p.unicodeHost() + " (encoded: " + p.host() + ")",
                            "Compare the address letter by letter with the site you expect.");
                }
            }
            return Optional.empty();
        });

        RULES.put("keyword_combo", (p, w) -> {
            String text = (p.host() + p.path()).toLowerCase();
            List<String> found = new ArrayList<>();
            for (String k : KEYWORDS) if (text.contains(k)) found.add(k);
            if (found.size() < 2) return Optional.empty();
            int weight = found.size() >= 3 ? w : (int) Math.round(w * 0.6);
            return ind("keyword_combo", "Suspicious keyword combination",
                    "Several account/security words together are typical of phishing pages. One such word on its own is normal and is not flagged.",
                    weight, "Keywords: " + String.join(", ", found),
                    "Go to the service by typing its address yourself.");
        });

        RULES.put("shortener", (p, w) -> {
            for (String s : SHORTENERS) {
                if (p.host().equals(s) || p.host().endsWith("." + s)) {
                    return ind("shortener", "URL-shortening service",
                            "The real destination is hidden behind a short link.", w, "Shortener: " + p.host(),
                            "Use a trusted link-expander before visiting.");
                }
            }
            return Optional.empty();
        });

        RULES.put("hyphens", (p, w) -> {
            if (isIpHost(p)) return Optional.empty();
            String h = p.host().replace("xn--", "");
            long count = h.chars().filter(c -> c == '-').count();
            return count < 3 ? Optional.empty() : ind("hyphens", "Excessive hyphens in hostname",
                    "Long hyphenated hostnames are a common pattern for fake domains.", w,
                    count + " hyphens in " + p.host(), "Check whether you recognise this domain.");
        });

        RULES.put("executable_download", (p, w) -> {
            String path = p.path().toLowerCase();
            for (String ext : RISKY_EXTENSIONS) {
                if (path.endsWith(ext)) {
                    return ind("executable_download", "Link points to an executable/installer file",
                            "Direct links to program files are a common malware delivery method.", w,
                            "Path ends with: " + ext.substring(1), "Only download software from the vendor's official site.");
                }
            }
            return Optional.empty();
        });

        RULES.put("embedded_url", (p, w) -> {
            String target = p.path() + "?" + p.query();
            boolean hit = EMBEDDED.matcher(target).find() || p.path().contains("//") || target.contains("@");
            return !hit ? Optional.empty() : ind("embedded_url", "Another URL or '@' embedded in the path/query",
                    "Redirect-style links can bounce you to a different site. Many legitimate login flows do this too, so the weight is low.",
                    w, "Embedded URL or '@' pattern found (content not displayed)",
                    "Make sure you trust the site that contains the link.");
        });
    }

    private RiskScorer() {}

    static String severityFor(int weight) { return weight >= 25 ? "High" : weight >= 12 ? "Medium" : "Low"; }

    private static Optional<Indicator> ind(String key, String name, String why, int weight, String evidence, String action) {
        return Optional.of(new Indicator(key, name, why, weight, severityFor(weight), evidence, action, "heuristic"));
    }

    private static String normalizeLookalike(String label) {
        // Common digit substitutions used in look-alike domains.
        return label.toLowerCase().replace('0', 'o').replace('1', 'l')
                .replace('3', 'e').replace('4', 'a').replace('5', 's')
                .replace('7', 't');
    }

    private static int editDistance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) previous[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            int[] current = new int[b.length() + 1];
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int substitution = previous[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                current[j] = Math.min(Math.min(previous[j] + 1, current[j - 1] + 1), substitution);
            }
            previous = current;
        }
        return previous[b.length()];
    }

    private static boolean isIpHost(ParsedUrl p) { return p.isIp() || p.ipLike(); }

    private static List<String> registrable(String host) {
        String[] labels = host.split("\\.");
        int size = labels.length >= 3 && MULTI_PART_TLDS.contains(labels[labels.length - 2] + "." + labels[labels.length - 1]) ? 3 : 2;
        size = Math.min(size, labels.length);
        return List.of(labels).subList(labels.length - size, labels.length);
    }

    private static List<String> subdomains(String host) {
        String[] labels = host.split("\\.");
        int regSize = registrable(host).size();
        return List.of(labels).subList(0, Math.max(0, labels.length - regSize));
    }

    public static String riskLevel(int score, Thresholds t) {
        if (score >= t.high()) return "High Risk";
        if (score >= t.medium()) return "Medium Risk";
        return "Low Risk";
    }

    public static Scored score(ParsedUrl parsed, Map<String, Integer> weightOverrides, Thresholds thresholds) {
        Map<String, Integer> weights = new LinkedHashMap<>(DEFAULT_WEIGHTS);
        if (weightOverrides != null) weights.putAll(weightOverrides);
        List<Indicator> indicators = new ArrayList<>();
        int total = 0;
        for (Map.Entry<String, Rule> entry : RULES.entrySet()) {
            Optional<Indicator> found = entry.getValue().apply(parsed, weights.get(entry.getKey()));
            if (found.isPresent() && found.get().contribution() > 0) {
                indicators.add(found.get());
                total += found.get().contribution();
            }
        }
        int score = Math.max(0, Math.min(100, total));
        return new Scored(score, riskLevel(score, thresholds), indicators);
    }
}
