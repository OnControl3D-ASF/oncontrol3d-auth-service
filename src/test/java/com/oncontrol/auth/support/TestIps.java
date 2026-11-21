package com.oncontrol.auth.support;

import java.util.concurrent.atomic.AtomicInteger;

/** Unique client IPs so the in-memory rate limiter never leaks state between tests. */
public final class TestIps {

    private static final AtomicInteger COUNTER = new AtomicInteger();

    private TestIps() {
    }

    public static String fresh() {
        int n = COUNTER.incrementAndGet();
        return "198.51." + (n / 250) + "." + (n % 250 + 1);
    }
}
