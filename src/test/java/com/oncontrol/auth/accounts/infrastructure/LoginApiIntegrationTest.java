package com.oncontrol.auth.accounts.infrastructure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import com.oncontrol.auth.support.IntegrationTest;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** REQ-A1 over HTTP against a real PostgreSQL: S-A1-a/b/c/d/e/h and A1.6. */
@IntegrationTest
@ExtendWith(OutputCaptureExtension.class)
class LoginApiIntegrationTest {

    private static final String SECRET = "test-secret-key-with-at-least-256-bits-0123456789";

    @Autowired MockMvc mockMvc;
    @Autowired AccountRepository accounts;
    @Autowired PasswordEncoder encoder;
    @Autowired ObjectMapper json;

    @BeforeEach
    void clean() {
        accounts.deleteAll();
    }

    private static String freshIp() {
        return "203.0." + (UUID.randomUUID().getLeastSignificantBits() & 0xff) + "." + (UUID.randomUUID().getMostSignificantBits() & 0xff);
    }

    private Account save(String email, String password, Role role, Long org, Long profile, Long doctor, Long patient) {
        return accounts.save(Account.create(email, encoder.encode(password), role, org, profile, doctor, patient));
    }

    private MvcResult login(String ip, String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login")
                .header("X-Forwarded-For", ip)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(java.util.Map.of("email", email, "password", password)))).andReturn();
    }

    @Test
    void organizationLogin_returnsSlimBodyAndVerifiableToken() throws Exception {
        save("org@clinic.com", "Passw0rd!", Role.ORGANIZATION, 1L, null, null, null);

        MvcResult result = login(freshIp(), "org@clinic.com", "Passw0rd!");

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.fieldNames()).toIterable().containsExactlyInAnyOrder(
                "token", "tokenType", "expiresIn", "role", "organizationId", "profileId", "doctorProfileId", "patientProfileId");
        assertThat(body.get("tokenType").asText()).isEqualTo("Bearer");
        assertThat(body.get("expiresIn").asLong()).isEqualTo(86_400L);
        assertThat(body.get("role").asText()).isEqualTo("ORGANIZATION");
        assertThat(body.get("organizationId").asLong()).isEqualTo(1L);
        assertThat(body.get("profileId").isNull()).isTrue();
        Claims claims = Jwts.parser().verifyWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)))
                .build().parseSignedClaims(body.get("token").asText()).getPayload();
        assertThat(claims.getIssuer()).isEqualTo("oncontrol3d-auth");
        assertThat(claims.getSubject()).isEqualTo("org@clinic.com");
    }

    @Test
    void doctorAndPatientLogin_returnTheirIds() throws Exception {
        save("dr@clinic.com", "Passw0rd!", Role.DOCTOR, 1L, 5L, 7L, null);
        save("pat@clinic.com", "Passw0rd!", Role.PATIENT, 1L, 9L, 7L, 12L);

        JsonNode doctor = json.readTree(login(freshIp(), "dr@clinic.com", "Passw0rd!").getResponse().getContentAsString());
        JsonNode patient = json.readTree(login(freshIp(), "pat@clinic.com", "Passw0rd!").getResponse().getContentAsString());

        assertThat(doctor.get("role").asText()).isEqualTo("DOCTOR");
        assertThat(doctor.get("profileId").asLong()).isEqualTo(5L);
        assertThat(doctor.get("doctorProfileId").asLong()).isEqualTo(7L);
        assertThat(doctor.get("patientProfileId").isNull()).isTrue();
        assertThat(patient.get("role").asText()).isEqualTo("PATIENT");
        assertThat(patient.get("patientProfileId").asLong()).isEqualTo(12L);
        assertThat(patient.get("doctorProfileId").asLong()).isEqualTo(7L);
    }

    @Test
    void wrongPassword_unknownEmailAndInactive_returnIdentical401() throws Exception {
        save("dr@clinic.com", "Passw0rd!", Role.DOCTOR, 1L, 5L, 7L, null);
        Account inactive = save("off@clinic.com", "Passw0rd!", Role.DOCTOR, 1L, 6L, 8L, null);
        inactive.deactivate();
        accounts.save(inactive);

        MvcResult wrong = login(freshIp(), "dr@clinic.com", "nope");
        MvcResult unknown = login(freshIp(), "ghost@clinic.com", "Passw0rd!");
        MvcResult off = login(freshIp(), "off@clinic.com", "Passw0rd!");

        for (MvcResult r : new MvcResult[]{wrong, unknown, off}) {
            assertThat(r.getResponse().getStatus()).isEqualTo(401);
            assertThat(r.getResponse().getContentAsString()).isEqualTo("{\"message\":\"Invalid credentials\"}");
        }
    }

    @Test
    void sixthAttemptFromSameIp_isRateLimited_andOtherIpIsUnaffected() throws Exception {
        save("dr@clinic.com", "Passw0rd!", Role.DOCTOR, 1L, 5L, 7L, null);
        String ip = freshIp();
        for (int i = 0; i < 5; i++) {
            assertThat(login(ip, "dr@clinic.com", "bad").getResponse().getStatus()).isEqualTo(401);
        }

        MvcResult sixth = login(ip, "dr@clinic.com", "Passw0rd!");
        MvcResult otherIp = login(freshIp(), "dr@clinic.com", "Passw0rd!");

        assertThat(sixth.getResponse().getStatus()).isEqualTo(429);
        assertThat(json.readTree(sixth.getResponse().getContentAsString()).get("message").asText()).isNotBlank();
        assertThat(otherIp.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void successfulLogin_resetsTheCounter() throws Exception {
        save("dr@clinic.com", "Passw0rd!", Role.DOCTOR, 1L, 5L, 7L, null);
        String ip = freshIp();
        for (int i = 0; i < 4; i++) {
            login(ip, "dr@clinic.com", "bad");
        }
        assertThat(login(ip, "dr@clinic.com", "Passw0rd!").getResponse().getStatus()).isEqualTo(200);

        for (int i = 0; i < 4; i++) {
            assertThat(login(ip, "dr@clinic.com", "bad").getResponse().getStatus()).isEqualTo(401);
        }
    }

    @Test
    void rateLimitKey_isTheFirstForwardedForHop() throws Exception {
        String first = freshIp();
        for (int i = 0; i < 5; i++) {
            login(first + ", 10.1.1.1", "x@clinic.com", "bad");
        }

        assertThat(login(first + ", 10.2.2.2", "x@clinic.com", "bad").getResponse().getStatus()).isEqualTo(429);
    }

    @Test
    void missingBody_fields_are401NotServerError() throws Exception {
        mockMvc.perform(post("/api/auth/login").header("X-Forwarded-For", freshIp())
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Invalid credentials"));
    }

    @Test
    void organizationRegistration_doesNotExistInAuth() throws Exception {
        mockMvc.perform(post("/api/auth/register/organization")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound());
    }

    @Test
    void passwordAndHash_neverAppearInResponsesOrLogs(CapturedOutput output) throws Exception {
        Account saved = save("dr@clinic.com", "Sup3r-Secret-Pw", Role.DOCTOR, 1L, 5L, 7L, null);

        MvcResult ok = login(freshIp(), "dr@clinic.com", "Sup3r-Secret-Pw");
        MvcResult bad = login(freshIp(), "dr@clinic.com", "Wr0ng-Secret-Pw");

        for (MvcResult r : new MvcResult[]{ok, bad}) {
            assertThat(r.getResponse().getContentAsString())
                    .doesNotContain("Sup3r-Secret-Pw").doesNotContain("Wr0ng-Secret-Pw").doesNotContain(saved.getPasswordHash());
        }
        assertThat(output.getAll()).doesNotContain("Sup3r-Secret-Pw").doesNotContain("Wr0ng-Secret-Pw")
                .doesNotContain(saved.getPasswordHash());
    }
}
