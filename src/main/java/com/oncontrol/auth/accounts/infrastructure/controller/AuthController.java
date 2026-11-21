package com.oncontrol.auth.accounts.infrastructure.controller;

import com.oncontrol.auth.accounts.application.service.InvalidCredentialsException;
import com.oncontrol.auth.accounts.application.service.LoginService;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginRequest;
import com.oncontrol.auth.accounts.infrastructure.dto.LoginResponse;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import com.oncontrol.auth.security.infrastructure.ratelimit.LoginRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
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

    public AuthController(LoginService loginService, JwtIssuer jwtIssuer, LoginRateLimiter rateLimiter) {
        this.loginService = loginService;
        this.jwtIssuer = jwtIssuer;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletRequest http) {
        String client = clientKey(http);
        if (rateLimiter.isBlocked(client)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("message", RATE_LIMITED_MESSAGE));
        }
        rateLimiter.recordAttempt(client);

        Account account = loginService.authenticate(request.email(), request.password());
        rateLimiter.reset(client);
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

    @ExceptionHandler(InvalidCredentialsException.class)
    ResponseEntity<Map<String, String>> invalidCredentials(InvalidCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", e.getMessage()));
    }
}
