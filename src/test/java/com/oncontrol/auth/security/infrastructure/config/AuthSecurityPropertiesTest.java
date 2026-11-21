package com.oncontrol.auth.security.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Fail-fast rules for the two shared secrets (S-A1-f, A2.2). */
class AuthSecurityPropertiesTest {

    private static final String SECRET = "test-secret-key-with-at-least-256-bits-0123456789";
    private static final String TOKEN = "internal-token-0123456789-0123456789"; // 37 bytes

    @Configuration
    @EnableConfigurationProperties(AuthSecurityProperties.class)
    static class Config {
    }

    private final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(Config.class);

    @Test
    void validSecrets_startAndAreExposed() {
        runner.withPropertyValues("auth.jwt-secret=" + SECRET, "auth.internal-token=" + TOKEN)
                .run(ctx -> {
                    assertThat(ctx).hasNotFailed();
                    AuthSecurityProperties props = ctx.getBean(AuthSecurityProperties.class);
                    assertThat(props.jwtSecret()).isEqualTo(SECRET);
                    assertThat(props.internalToken()).isEqualTo(TOKEN);
                });
    }

    @Test
    void missingJwtSecret_failsStartup() {
        runner.withPropertyValues("auth.internal-token=" + TOKEN)
                .run(ctx -> assertThat(ctx).hasFailed().getFailure().rootCause().hasMessageContaining("JWT_SECRET"));
    }

    @Test
    void blankJwtSecret_failsStartup() {
        runner.withPropertyValues("auth.jwt-secret=   ", "auth.internal-token=" + TOKEN)
                .run(ctx -> assertThat(ctx).hasFailed().getFailure().rootCause().hasMessageContaining("JWT_SECRET"));
    }

    @Test
    void shortJwtSecret_failsStartup() {
        runner.withPropertyValues("auth.jwt-secret=too-short-secret", "auth.internal-token=" + TOKEN)
                .run(ctx -> assertThat(ctx).hasFailed().getFailure().rootCause()
                        .hasMessageContaining("JWT_SECRET").hasMessageContaining("32 bytes"));
    }

    @Test
    void jwtSecretOfExactly32Bytes_isAccepted() {
        runner.withPropertyValues("auth.jwt-secret=" + "x".repeat(32), "auth.internal-token=" + TOKEN)
                .run(ctx -> assertThat(ctx).hasNotFailed());
    }

    @Test
    void blankInternalToken_failsStartup() {
        runner.withPropertyValues("auth.jwt-secret=" + SECRET, "auth.internal-token=")
                .run(ctx -> assertThat(ctx).hasFailed().getFailure().rootCause()
                        .hasMessageContaining("AUTH_INTERNAL_TOKEN"));
    }

    @Test
    void shortInternalToken_failsStartup() {
        runner.withPropertyValues("auth.jwt-secret=" + SECRET, "auth.internal-token=short")
                .run(ctx -> assertThat(ctx).hasFailed().getFailure().rootCause()
                        .hasMessageContaining("AUTH_INTERNAL_TOKEN").hasMessageContaining("32 bytes"));
    }

    @Test
    void constructor_rejectsNullValues() {
        assertThatThrownBy(() -> new AuthSecurityProperties(null, TOKEN))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("JWT_SECRET");
        assertThatThrownBy(() -> new AuthSecurityProperties(SECRET, null))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("AUTH_INTERNAL_TOKEN");
    }
}
