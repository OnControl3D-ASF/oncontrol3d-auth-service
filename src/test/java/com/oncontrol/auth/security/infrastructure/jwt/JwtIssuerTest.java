package com.oncontrol.auth.security.infrastructure.jwt;

import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.security.infrastructure.config.AuthSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Token contract: S-A1-a, S-A1-b, S-A1-c (A1.3 / A1.3b / A1.3c). */
class JwtIssuerTest {

    private static final String SECRET = "test-secret-key-with-at-least-256-bits-0123456789";
    private static final String TOKEN = "test-internal-token-with-at-least-32-bytes-0123";
    private static final Instant NOW = Instant.parse("2026-11-21T10:00:00Z");

    private final SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    private final JwtIssuer issuer = new JwtIssuer(
            new AuthSecurityProperties(SECRET, TOKEN), Clock.fixed(NOW, ZoneOffset.UTC));

    private Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    private static Long id(Claims claims, String name) {
        Object value = claims.get(name);
        return value == null ? null : ((Number) value).longValue();
    }

    @Test
    void organizationToken_hasOrganizationIdAndNoProfileIds() {
        Account org = Account.create("Org@Clinic.com", "hash", Role.ORGANIZATION, 1L, null, null, null);

        IssuedToken issued = issuer.issue(org);
        Claims claims = parse(issued.token());

        assertThat(claims.getSubject()).isEqualTo("org@clinic.com");
        assertThat(claims.getIssuer()).isEqualTo("oncontrol3d-auth");
        assertThat(claims.get("role")).isEqualTo("ORGANIZATION");
        assertThat(id(claims, "organizationId")).isEqualTo(1L);
        assertThat(id(claims, "profileId")).isNull();
        assertThat(id(claims, "doctorProfileId")).isNull();
        assertThat(id(claims, "patientProfileId")).isNull();
    }

    @Test
    void doctorToken_carriesDoctorIdsAndNoPatientId() {
        Account doctor = Account.create("dr@clinic.com", "hash", Role.DOCTOR, 1L, 5L, 7L, null);

        Claims claims = parse(issuer.issue(doctor).token());

        assertThat(claims.get("role")).isEqualTo("DOCTOR");
        assertThat(id(claims, "organizationId")).isEqualTo(1L);
        assertThat(id(claims, "profileId")).isEqualTo(5L);
        assertThat(id(claims, "doctorProfileId")).isEqualTo(7L);
        assertThat(id(claims, "patientProfileId")).isNull();
    }

    @Test
    void patientToken_carriesPatientAndDoctorIds() {
        Account patient = Account.create("pat@clinic.com", "hash", Role.PATIENT, 1L, 9L, 7L, 12L);

        Claims claims = parse(issuer.issue(patient).token());

        assertThat(claims.get("role")).isEqualTo("PATIENT");
        assertThat(id(claims, "organizationId")).isEqualTo(1L);
        assertThat(id(claims, "profileId")).isEqualTo(9L);
        assertThat(id(claims, "doctorProfileId")).isEqualTo(7L);
        assertThat(id(claims, "patientProfileId")).isEqualTo(12L);
    }

    @Test
    void claimSet_isExactlyTheContract_andNeverContainsCredentials() {
        Account patient = Account.create("pat@clinic.com", "super-secret-hash", Role.PATIENT, 1L, 9L, 7L, 12L);

        Claims claims = parse(issuer.issue(patient).token());

        assertThat(claims.keySet()).isEqualTo(Set.of(
                "sub", "iss", "role", "organizationId", "profileId", "doctorProfileId", "patientProfileId",
                "iat", "exp"));
        assertThat(claims.toString()).doesNotContain("super-secret-hash");
    }

    @Test
    void expiresIn24Hours_andReportsSeconds() {
        Account org = Account.create("org@clinic.com", "hash", Role.ORGANIZATION, 1L, null, null, null);

        IssuedToken issued = issuer.issue(org);
        Claims claims = parse(issued.token());

        assertThat(claims.getIssuedAt().toInstant()).isEqualTo(NOW);
        assertThat(claims.getExpiration().toInstant()).isEqualTo(NOW.plusSeconds(86_400));
        assertThat(issued.expiresInSeconds()).isEqualTo(86_400L);
    }

    @Test
    void tokenSignedByIssuer_isRejectedWithAnotherKey() {
        Account account = Account.create("org@clinic.com", "hash", Role.ORGANIZATION, 1L, null, null, null);
        String token = issuer.issue(account).token();
        SecretKey other = Keys.hmacShaKeyFor("another-secret-key-with-at-least-256-bits-9876543210".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> Jwts.parser().verifyWith(other).build().parseSignedClaims(token))
                .isInstanceOf(io.jsonwebtoken.security.SignatureException.class);
    }
}
