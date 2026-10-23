package com.qrshield.core;

/** A validated URL split into parts. "normalized" has no credentials and no #fragment. */
public record ParsedUrl(String original, String normalized, String scheme, String host,
                        String unicodeHost, Integer port, boolean hasCredentials,
                        String path, String query, boolean isIp, boolean ipLike) {}
