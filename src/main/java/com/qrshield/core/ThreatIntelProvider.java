package com.qrshield.core;

/** Interface for optional external providers. Implement check() to add another provider. */
public interface ThreatIntelProvider {
    String CONFIRMED = "confirmed_match", NO_MATCH = "no_match",
           UNAVAILABLE = "unavailable", NOT_CONFIGURED = "not_configured";

    record TiResult(String status, String detail, String provider) {}

    String name();

    TiResult check(String url);
}
