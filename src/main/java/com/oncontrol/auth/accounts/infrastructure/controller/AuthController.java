package com.oncontrol.auth.accounts.infrastructure.controller;

import com.oncontrol.auth.accounts.application.service.InvalidCredentialsException;
import com.oncontrol.auth.accounts.application.service.LoginService;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginRequest;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginResponse;
import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.audit.domain.model.AuditEventType;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import com.oncontrol.auth.security.infrastructure.ratelimit.LoginRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    static final String RATE_LIMITED_MESSAGE = "Demasiados intentos. Espera un minuto e inténtalo de nuevo.";

    private final LoginService loginService;
    private final JwtIssuer jwtIssuer;
    private final LoginRateLimiter rateLimiter;
    private final AuditService audit;

    public AuthController(LoginService loginService, JwtIssuer jwtIssuer, LoginRateLimiter rateLimiter,
                          AuditService audit) {
        this.loginService = loginService;
        this.jwtIssuer = jwtIssuer;
        this.rateLimiter = rateLimiter;
        this.audit = audit;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest http) {
        String client = clientKey(http);
        String attemptedEmail = Account.normalize(request.email());
        if (rateLimiter.isBlocked(client)) {
            audit.record(AuditEventType.LOGIN_RATE_LIMITED, attemptedEmail, null, null, client);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("message", RATE_LIMITED_MESSAGE));
        }
        rateLimiter.recordAttempt(client);

        Account account;
        try {
            account = loginService.authenticate(request.email(), request.password());
        } catch (InvalidCredentialsException e) {
            Account known = e.account().orElse(null);
            audit.record(AuditEventType.LOGIN_FAILED, attemptedEmail, known == null ? null : known.getId(),
                    known == null ? null : known.getOrganizationId(), client);
            throw e;
        }
        rateLimiter.reset(client);
        audit.record(AuditEventType.LOGIN_SUCCEEDED, account.getEmail(), account.getId(), account.getOrganizationId(), client);
        return ResponseEntity.ok(LoginResponse.of(jwtIssuer.issue(account), account));
    }

    /** First X-Forwarded-For hop (edge/proxy) or the socket address. */
    private static String clientKey(HttpServletRequest http) {
        String forwarded = http.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return http.getRemoteAddr();
    }
}
