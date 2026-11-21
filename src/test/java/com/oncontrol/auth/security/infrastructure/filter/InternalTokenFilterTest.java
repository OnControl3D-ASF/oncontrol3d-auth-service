package com.oncontrol.auth.security.infrastructure.filter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/** S-A2-a, A2.2: constant-time shared-token check, only for /internal/**. */
class InternalTokenFilterTest {

    private static final String TOKEN = "test-internal-token-with-at-least-32-bytes-0123";
    private final InternalTokenFilter filter = new InternalTokenFilter(TOKEN);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private Authentication run(String path, String headerName, String headerValue) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        request.setRequestURI(path);
        if (headerName != null) {
            request.addHeader(headerName, headerValue);
        }
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(request, new MockHttpServletResponse(), chain);
        assertThat(chain.getRequest()).as("chain must always continue").isNotNull();
        return SecurityContextHolder.getContext().getAuthentication();
    }

    @Test
    void validToken_authenticatesAsInternalService() throws Exception {
        Authentication auth = run("/internal/accounts", "X-Internal-Token", TOKEN);

        assertThat(auth).isNotNull();
        assertThat(auth.isAuthenticated()).isTrue();
        assertThat(auth.getAuthorities()).extracting(Object::toString).containsExactly("ROLE_INTERNAL");
    }

    @Test
    void missingHeader_doesNotAuthenticate() throws Exception {
        assertThat(run("/internal/accounts", null, null)).isNull();
    }

    @Test
    void wrongToken_doesNotAuthenticate() throws Exception {
        assertThat(run("/internal/accounts", "X-Internal-Token", TOKEN + "x")).isNull();
        assertThat(run("/internal/accounts", "X-Internal-Token", "short")).isNull();
        assertThat(run("/internal/accounts", "X-Internal-Token", "")).isNull();
    }

    @Test
    void endUserBearerToken_isNotAValidInternalCredential() throws Exception {
        assertThat(run("/internal/accounts", "Authorization", "Bearer " + TOKEN)).isNull();
    }

    @Test
    void otherPaths_areIgnoredEvenWithAValidToken() throws Exception {
        assertThat(run("/api/auth/login", "X-Internal-Token", TOKEN)).isNull();
        assertThat(run("/api/auth/internal/accounts", "X-Internal-Token", TOKEN)).isNull();
    }
}
