package com.qrshield.core;

import java.net.IDN;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Strict, offline URL validation. The URL is parsed as text and NEVER opened. */
public final class UrlValidator {
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");
    private static final Pattern SCHEME = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.\\-]*):");
    private static final Pattern LABEL = Pattern.compile("^(?!-)[a-z0-9-]{1,63}(?<!-)$");
    private static final Pattern IP_LIKE = Pattern.compile("^(0x[0-9a-f]+|\\d+)(\\.(0x[0-9a-f]+|\\d+))*$", Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4 = Pattern.compile("^(25[0-5]|2[0-4]\\d|1?\\d?\\d)(\\.(25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9a-fA-F:.]+$");

    public record ValidationResult(boolean valid, String error, ParsedUrl parsed) {}

    private UrlValidator() {}

    private static ValidationResult fail(String message) {
        return new ValidationResult(false, message, null);
    }

    public static ValidationResult validate(String raw, int maxLength) {
        if (raw == null || raw.isBlank()) return fail("Please enter a URL.");
        String url = raw.strip();
        if (url.length() > maxLength) return fail("The URL is too long (maximum " + maxLength + " characters).");
        for (char c : url.toCharArray()) {
            if (Character.isISOControl(c) || Character.isWhitespace(c)) {
                return fail("The URL contains spaces or control characters.");
            }
        }

        Matcher m = SCHEME.matcher(url);
        if (!m.find()) return fail("The URL must start with http:// or https://.");
        String scheme = m.group(1).toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            return fail("Unsupported URL scheme '" + scheme + ":'. Only http and https are analyzed.");
        }
        String rest = url.substring(scheme.length() + 1);
        if (!rest.startsWith("//")) return fail("Malformed URL: expected '://' after the scheme.");
        rest = rest.substring(2);

        // Split: authority | path | query (the #fragment is dropped)
        int hash = rest.indexOf('#');
        if (hash >= 0) rest = rest.substring(0, hash);
        int cut = indexOfAny(rest, "/?");
        String authority = cut < 0 ? rest : rest.substring(0, cut);
        String pathAndQuery = cut < 0 ? "" : rest.substring(cut);
        int q = pathAndQuery.indexOf('?');
        String path = q < 0 ? pathAndQuery : pathAndQuery.substring(0, q);
        String query = q < 0 ? "" : pathAndQuery.substring(q + 1);

        int at = authority.lastIndexOf('@');
        boolean hasCredentials = at >= 0;
        String hostPort = hasCredentials ? authority.substring(at + 1) : authority;

        String host;
        String portText = "";
        if (hostPort.startsWith("[")) {
            int end = hostPort.indexOf(']');
            if (end < 0) return fail("Malformed URL (invalid host or port).");
            host = hostPort.substring(1, end);
            String after = hostPort.substring(end + 1);
            if (!after.isEmpty()) {
                if (!after.startsWith(":")) return fail("Malformed URL (invalid host or port).");
                portText = after.substring(1);
            }
        } else {
            int colon = hostPort.lastIndexOf(':');
            host = colon < 0 ? hostPort : hostPort.substring(0, colon);
            if (colon >= 0) portText = hostPort.substring(colon + 1);
        }
        if (host.isEmpty()) return fail("The URL has no hostname.");

        Integer port = null;
        if (!portText.isEmpty()) {
            if (!portText.matches("\\d{1,5}")) return fail("The URL has an invalid port number.");
            port = Integer.parseInt(portText);
            if (port < 1 || port > 65535) return fail("The URL has an invalid port number.");
        }

        host = host.toLowerCase();
        boolean isIp = false, ipLike = false;
        String asciiHost = host;
        if (hostPort.startsWith("[")) {
            if (!host.contains(":") || !IPV6.matcher(host).matches()) return fail("The hostname is not valid.");
            isIp = true;
        } else if (IPV4.matcher(host).matches()) {
            isIp = true;
        } else {
            asciiHost = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
            if (IP_LIKE.matcher(asciiHost).matches()) {
                ipLike = true;
            } else {
                try {
                    asciiHost = IDN.toASCII(asciiHost, IDN.ALLOW_UNASSIGNED).toLowerCase();
                } catch (IllegalArgumentException e) {
                    return fail("The hostname is not valid.");
                }
                if (asciiHost.length() > 253) return fail("The hostname is not valid.");
                for (String label : asciiHost.split("\\.", -1)) {
                    if (!LABEL.matcher(label).matches()) return fail("The hostname is not valid.");
                }
            }
        }

        String unicodeHost = asciiHost;
        if (!isIp && !ipLike) {
            try { unicodeHost = IDN.toUnicode(asciiHost); } catch (RuntimeException ignored) { /* keep ascii */ }
        }

        StringBuilder normalized = new StringBuilder(scheme).append("://");
        normalized.append(isIp && asciiHost.contains(":") ? "[" + asciiHost + "]" : asciiHost);
        if (port != null && !((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443))) {
            normalized.append(':').append(port);
        }
        normalized.append(path.isEmpty() ? "/" : path);
        if (!query.isEmpty()) normalized.append('?').append(query);

        return new ValidationResult(true, null, new ParsedUrl(url, normalized.toString(), scheme, asciiHost,
                unicodeHost, port, hasCredentials, path, query, isIp, ipLike));
    }

    private static int indexOfAny(String s, String chars) {
        for (int i = 0; i < s.length(); i++) if (chars.indexOf(s.charAt(i)) >= 0) return i;
        return -1;
    }
}
