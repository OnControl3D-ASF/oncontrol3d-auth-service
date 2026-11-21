package com.oncontrol.auth.security.infrastructure.ratelimit;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** S-A1-e / A1.4 */
class LoginRateLimiterTest {

    private final LoginRateLimiter limiter = new LoginRateLimiter();

    @Test
    void unknownClient_isNotBlocked() {
        assertThat(limiter.isBlocked("10.0.0.1")).isFalse();
    }

    @Test
    void blocksAfterFiveAttemptsInsideWindow() {
        for (int i = 0; i < 4; i++) {
            limiter.recordAttempt("10.0.0.1");
        }
        assertThat(limiter.isBlocked("10.0.0.1")).isFalse();

        limiter.recordAttempt("10.0.0.1");
        assertThat(limiter.isBlocked("10.0.0.1")).isTrue();
    }

    @Test
    void limitsArePerClient() {
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt("10.0.0.1");
        }
        assertThat(limiter.isBlocked("10.0.0.1")).isTrue();
        assertThat(limiter.isBlocked("10.0.0.2")).isFalse();
    }

    @Test
    void resetClearsAttempts() {
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt("10.0.0.1");
        }
        limiter.reset("10.0.0.1");

        assertThat(limiter.isBlocked("10.0.0.1")).isFalse();
    }

    @Test
    void trackedKeys_neverExceedTheCap() {
        for (int i = 0; i < 10_050; i++) {
            limiter.recordAttempt("client-" + i);
        }

        assertThat(limiter.trackedKeys()).isLessThanOrEqualTo(10_000).isGreaterThan(9_000);
    }

    @Test
    void whenCapIsHit_theNewestClientIsStillTracked() {
        for (int i = 0; i < 10_000; i++) {
            limiter.recordAttempt("client-" + i);
        }
        for (int i = 0; i < 5; i++) {
            limiter.recordAttempt("late-client");
        }

        assertThat(limiter.isBlocked("late-client")).isTrue();
    }
}
