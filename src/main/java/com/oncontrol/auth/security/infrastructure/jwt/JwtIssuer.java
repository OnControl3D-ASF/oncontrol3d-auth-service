package com.oncontrol.auth.security.infrastructure.jwt;

import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.security.infrastructure.config.AuthSecurityProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/**
 * Issues the HS256 tokens consumed by the clinical service. The claim set is a contract:
 * {@code sub, iss, role, organizationId, profileId, doctorProfileId, patientProfileId, iat, exp}.
 * Ids that do not apply to the role are omitted (readers see null). No credentials ever go in.
 */
@Component
public class JwtIssuer {

    public static final String ISSUER = "oncontrol3d-auth";
    static final Duration VALIDITY = Duration.ofHours(24);

    private final SecretKey key;
    private final Clock clock;

    public JwtIssuer(AuthSecurityProperties properties, Clock clock) {
        this.key = Keys.hmacShaKeyFor(properties.jwtSecret().getBytes(StandardCharsets.UTF_8));
        this.clock = clock;
    }

    public IssuedToken issue(Account account) {
        Instant now = clock.instant();
        String token = Jwts.builder()
                .subject(account.getEmail())
                .issuer(ISSUER)
                .claim("role", account.getRole().name())
                .claim("organizationId", account.getOrganizationId())
                .claim("profileId", account.getProfileId())
                .claim("doctorProfileId", account.getDoctorProfileId())
                .claim("patientProfileId", account.getPatientProfileId())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(VALIDITY)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
        return new IssuedToken(token, VALIDITY.toSeconds());
    }
}
