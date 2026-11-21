package com.oncontrol.auth.security.infrastructure.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * In-memory sliding-window rate limiter for login: at most {@link #MAX_ATTEMPTS} attempts per
 * {@link #WINDOW} per client key (IP). State is per instance (the effective limit multiplies by the
 * replica count; the edge rate limit covers that) and bounded to {@link #MAX_TRACKED_KEYS} keys.
 */
@Component
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS = 5;
    private static final Duration WINDOW = Duration.ofMinutes(1);
    static final int MAX_TRACKED_KEYS = 10_000;

    private final Map<String, Deque<Instant>> attemptsByKey = new ConcurrentHashMap<>();

    /** True if the key already exhausted its attempts inside the window. */
    public boolean isBlocked(String key) {
        Deque<Instant> attempts = attemptsByKey.get(key);
        if (attempts == null) {
            return false;
        }
        prune(attempts);
        return attempts.size() >= MAX_ATTEMPTS;
    }

    /** Registers one attempt for the key. Call before validating credentials. */
    public void recordAttempt(String key) {
        if (!attemptsByKey.containsKey(key) && attemptsByKey.size() >= MAX_TRACKED_KEYS) {
            makeRoom();
        }
        Deque<Instant> attempts = attemptsByKey.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
        prune(attempts);
        attempts.addLast(Instant.now());
    }

    /** Clears the key after a successful login so legit users are not penalized. */
    public void reset(String key) {
        attemptsByKey.remove(key);
    }

    int trackedKeys() {
        return attemptsByKey.size();
    }

    private void prune(Deque<Instant> attempts) {
        Instant cutoff = Instant.now().minus(WINDOW);
        while (true) {
            Instant first = attempts.peekFirst();
            if (first == null || first.isAfter(cutoff)) {
                return;
            }
            attempts.pollFirst();
        }
    }

    /** Drops expired keys; if every key is still live, drops the one idle the longest. */
    private void makeRoom() {
        Instant cutoff = Instant.now().minus(WINDOW);
        attemptsByKey.entrySet().removeIf(e -> {
            Instant last = e.getValue().peekLast();
            return last == null || last.isBefore(cutoff);
        });
        if (attemptsByKey.size() >= MAX_TRACKED_KEYS) {
            attemptsByKey.entrySet().stream()
                    .min(Comparator.comparing(e -> {
                        Instant last = e.getValue().peekLast();
                        return last == null ? Instant.MIN : last;
                    }))
                    .ifPresent(e -> attemptsByKey.remove(e.getKey()));
        }
    }
}
