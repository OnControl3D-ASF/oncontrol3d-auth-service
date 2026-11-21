package com.oncontrol.auth.security.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.charset.StandardCharsets;

/**
 * Shared secrets of the service. Both are validated at construction so a misconfigured
 * deployment fails at startup, not on the first request.
 *
 * @param jwtSecret     HS256 signing key shared with the clinical service (env JWT_SECRET)
 * @param internalToken static token guarding {@code /internal/**} (env AUTH_INTERNAL_TOKEN)
 */
@ConfigurationProperties(prefix = "auth")
public record AuthSecurityProperties(String jwtSecret, String internalToken) {

    /** HMAC-SHA256 requires a key of at least 256 bits. */
    static final int MIN_BYTES = 32;

    public AuthSecurityProperties {
        requireStrong(jwtSecret, "JWT_SECRET", "openssl rand -hex 32");
        requireStrong(internalToken, "AUTH_INTERNAL_TOKEN", "openssl rand -hex 32");
    }

    private static void requireStrong(String value, String envName, String hint) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(envName + " is required and must not be blank");
        }
        if (value.getBytes(StandardCharsets.UTF_8).length < MIN_BYTES) {
            throw new IllegalStateException(
                    envName + " must be at least " + MIN_BYTES + " bytes (256 bits); generate one with: " + hint);
        }
    }
}
