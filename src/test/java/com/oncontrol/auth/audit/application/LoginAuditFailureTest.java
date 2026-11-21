package com.oncontrol.auth.audit.application;

import com.oncontrol.auth.accounts.application.service.LoginService;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.infrastructure.controller.AuthController;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginRequest;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginResponse;
import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.audit.domain.repository.AuditEventRepository;
import com.oncontrol.auth.security.infrastructure.config.AuthSecurityProperties;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import com.oncontrol.auth.security.infrastructure.ratelimit.LoginRateLimiter;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Clock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A3.2: a broken audit store must never break login. */
class LoginAuditFailureTest {

    @Test
    void login_succeeds_evenWhenTheAuditWriteFails() {
        LoginService loginService = mock(LoginService.class);
        Account account = Account.create("dr@clinic.com", "hash", Role.DOCTOR, 1L, 5L, 7L, null);
        when(loginService.authenticate("dr@clinic.com", "pw")).thenReturn(account);
        AuditEventRepository brokenRepository = mock(AuditEventRepository.class);
        doThrow(new IllegalStateException("audit db down")).when(brokenRepository).save(any());
        JwtIssuer issuer = new JwtIssuer(new AuthSecurityProperties(
                "test-secret-key-with-at-least-256-bits-0123456789",
                "test-internal-token-with-at-least-32-bytes-0123"), Clock.systemUTC());
        AuthController controller = new AuthController(loginService, issuer, new LoginRateLimiter(),
                new AuditService(brokenRepository, Clock.systemUTC()));

        ResponseEntity<?> response = controller.login(new LoginRequest("dr@clinic.com", "pw"), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(((LoginResponse) response.getBody()).role()).isEqualTo("DOCTOR");
    }
}
