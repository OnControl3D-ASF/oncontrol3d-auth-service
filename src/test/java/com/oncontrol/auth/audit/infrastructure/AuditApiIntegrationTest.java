package com.oncontrol.auth.audit.infrastructure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.audit.domain.model.AuditEventType;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import com.oncontrol.auth.support.IntegrationTest;
import com.oncontrol.auth.support.TestIps;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** REQ-A3: audit events (S-A3-a..e) and GET /api/auth/audit. */
@IntegrationTest
class AuditApiIntegrationTest {

    private static final String INTERNAL_TOKEN = "test-internal-token-with-at-least-32-bytes-0123";

    @Autowired MockMvc mockMvc;
    @Autowired AccountRepository accounts;
    @Autowired PasswordEncoder encoder;
    @Autowired JwtIssuer issuer;
    @Autowired AuditService audit;
    @Autowired JdbcTemplate jdbc;
    @Autowired ObjectMapper json;

    @BeforeEach
    void clean() {
        jdbc.update("delete from audit_events");
        accounts.deleteAll();
    }

    private Account save(String email, Role role, Long org, Long profile, Long doctor, Long patient) {
        return accounts.save(Account.create(email, encoder.encode("Passw0rd!"), role, org, profile, doctor, patient));
    }

    private MvcResult login(String ip, String email, String password) throws Exception {
        return mockMvc.perform(post("/api/auth/login").header("X-Forwarded-For", ip)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email", email, "password", password)))).andReturn();
    }

    private List<Map<String, Object>> rows() {
        return jdbc.queryForList("select type, email, account_id, organization_id, client_ip from audit_events order by id");
    }

    private String tokenFor(Account account) {
        return issuer.issue(account).token();
    }

    // ---- S-A3-a / S-A3-b: login events

    @Test
    void successfulLogin_writesLoginSucceededWithAccountAndOrganization() throws Exception {
        Account doctor = save("dr@clinic.com", Role.DOCTOR, 3L, 5L, 7L, null);
        String ip = TestIps.fresh();

        login(ip, "DR@clinic.com", "Passw0rd!");

        assertThat(rows()).hasSize(1);
        Map<String, Object> row = rows().get(0);
        assertThat(row.get("type")).isEqualTo("LOGIN_SUCCEEDED");
        assertThat(row.get("email")).isEqualTo("dr@clinic.com");
        assertThat(row.get("account_id")).isEqualTo(doctor.getId());
        assertThat(((Number) row.get("organization_id")).longValue()).isEqualTo(3L);
        assertThat(row.get("client_ip")).isEqualTo(ip);
    }

    @Test
    void failedLoginForUnknownEmail_keepsTheAttemptedEmailAndNoAccount() throws Exception {
        login(TestIps.fresh(), "Ghost@Clinic.com", "whatever");

        Map<String, Object> row = rows().get(0);
        assertThat(row.get("type")).isEqualTo("LOGIN_FAILED");
        assertThat(row.get("email")).isEqualTo("ghost@clinic.com");
        assertThat(row.get("account_id")).isNull();
        assertThat(row.get("organization_id")).isNull();
    }

    @Test
    void failedLoginForKnownAccount_recordsTheAccountAndItsOrganization() throws Exception {
        Account doctor = save("dr@clinic.com", Role.DOCTOR, 3L, 5L, 7L, null);

        login(TestIps.fresh(), "dr@clinic.com", "wrong");

        Map<String, Object> row = rows().get(0);
        assertThat(row.get("type")).isEqualTo("LOGIN_FAILED");
        assertThat(row.get("account_id")).isEqualTo(doctor.getId());
        assertThat(((Number) row.get("organization_id")).longValue()).isEqualTo(3L);
    }

    @Test
    void sixthAttemptInAMinute_writesLoginRateLimited() throws Exception {
        String ip = TestIps.fresh();
        for (int i = 0; i < 5; i++) {
            login(ip, "ghost@clinic.com", "bad");
        }
        login(ip, "ghost@clinic.com", "bad");

        List<Map<String, Object>> rows = rows();
        assertThat(rows).hasSize(6);
        assertThat(rows.subList(0, 5)).allSatisfy(r -> assertThat(r.get("type")).isEqualTo("LOGIN_FAILED"));
        assertThat(rows.get(5).get("type")).isEqualTo("LOGIN_RATE_LIMITED");
        assertThat(rows.get(5).get("email")).isEqualTo("ghost@clinic.com");
        assertThat(rows.get(5).get("client_ip")).isEqualTo(ip);
    }

    // ---- S-A3-c: provisioning events

    @Test
    void provisioningAndDeprovisioning_writeAccountEvents() throws Exception {
        MvcResult created = mockMvc.perform(post("/internal/accounts").header("X-Internal-Token", INTERNAL_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"Dr@Clinic.com\",\"password\":\"Passw0rd!Passw0rd!\",\"role\":\"DOCTOR\","
                        + "\"organizationId\":4,\"profileId\":5,\"doctorProfileId\":7}")).andReturn();
        long accountId = json.readTree(created.getResponse().getContentAsString()).get("accountId").asLong();
        mockMvc.perform(delete("/internal/accounts/" + accountId).header("X-Internal-Token", INTERNAL_TOKEN))
                .andExpect(status().isNoContent());

        List<Map<String, Object>> rows = rows();
        assertThat(rows).hasSize(2);
        assertThat(rows.get(0).get("type")).isEqualTo("ACCOUNT_PROVISIONED");
        assertThat(rows.get(0).get("email")).isEqualTo("dr@clinic.com");
        assertThat(((Number) rows.get(0).get("account_id")).longValue()).isEqualTo(accountId);
        assertThat(((Number) rows.get(0).get("organization_id")).longValue()).isEqualTo(4L);
        assertThat(rows.get(1).get("type")).isEqualTo("ACCOUNT_DEPROVISIONED");
        assertThat(((Number) rows.get(1).get("account_id")).longValue()).isEqualTo(accountId);
        assertThat(((Number) rows.get(1).get("organization_id")).longValue()).isEqualTo(4L);
    }

    @Test
    void deprovisioningAnUnknownAccount_writesNothing() throws Exception {
        mockMvc.perform(delete("/internal/accounts/424242").header("X-Internal-Token", INTERNAL_TOKEN))
                .andExpect(status().isNoContent());

        assertThat(rows()).isEmpty();
    }

    // ---- S-A3-d: GET /api/auth/audit

    @Test
    void organization_seesOnlyItsOwnEvents_newestFirst() throws Exception {
        Account orgA = save("a@clinic.com", Role.ORGANIZATION, 1L, null, null, null);
        audit.record(AuditEventType.LOGIN_SUCCEEDED, "first@a.com", 10L, 1L, "10.0.0.1");
        audit.record(AuditEventType.LOGIN_FAILED, "second@a.com", 11L, 1L, "10.0.0.2");
        audit.record(AuditEventType.LOGIN_SUCCEEDED, "other@b.com", 20L, 2L, "10.0.0.3");
        audit.record(AuditEventType.LOGIN_FAILED, "ghost@x.com", null, null, "10.0.0.4");

        MvcResult result = mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + tokenFor(orgA)))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode events = json.readTree(result.getResponse().getContentAsString());
        assertThat(events).hasSize(2);
        assertThat(events.get(0).get("email").asText()).isEqualTo("second@a.com");
        assertThat(events.get(1).get("email").asText()).isEqualTo("first@a.com");
        assertThat(events.get(0).get("type").asText()).isEqualTo("LOGIN_FAILED");
        assertThat(events.get(0).get("organizationId").asLong()).isEqualTo(1L);
        assertThat(events.get(0).get("clientIp").asText()).isEqualTo("10.0.0.2");
        assertThat(events.get(0).has("occurredAt")).isTrue();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("other@b.com").doesNotContain("ghost@x.com");
    }

    @Test
    void anotherOrganization_neverSeesTheEventsOfOrgA() throws Exception {
        audit.record(AuditEventType.LOGIN_SUCCEEDED, "only@a.com", 10L, 1L, "10.0.0.1");
        Account orgB = save("b@clinic.com", Role.ORGANIZATION, 2L, null, null, null);

        MvcResult result = mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + tokenFor(orgB)))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(json.readTree(result.getResponse().getContentAsString())).isEmpty();
    }

    @Test
    void sizeParameter_limitsTheResult_andDefaultsTo50() throws Exception {
        Account orgA = save("a@clinic.com", Role.ORGANIZATION, 1L, null, null, null);
        for (int i = 0; i < 60; i++) {
            audit.record(AuditEventType.LOGIN_SUCCEEDED, "u" + i + "@a.com", 10L, 1L, "10.0.0.1");
        }
        String bearer = "Bearer " + tokenFor(orgA);

        JsonNode defaultSize = json.readTree(mockMvc.perform(get("/api/auth/audit").header("Authorization", bearer))
                .andReturn().getResponse().getContentAsString());
        JsonNode three = json.readTree(mockMvc.perform(get("/api/auth/audit?size=3").header("Authorization", bearer))
                .andReturn().getResponse().getContentAsString());
        JsonNode clamped = json.readTree(mockMvc.perform(get("/api/auth/audit?size=100000").header("Authorization", bearer))
                .andReturn().getResponse().getContentAsString());

        assertThat(defaultSize).hasSize(50);
        assertThat(three).hasSize(3);
        assertThat(three.get(0).get("email").asText()).isEqualTo("u59@a.com");
        assertThat(clamped).hasSize(60);
    }

    @Test
    void doctorAndPatientTokens_areForbidden() throws Exception {
        Account doctor = save("dr@clinic.com", Role.DOCTOR, 1L, 5L, 7L, null);
        Account patient = save("pat@clinic.com", Role.PATIENT, 1L, 9L, 7L, 12L);

        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + tokenFor(doctor)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + tokenFor(patient)))
                .andExpect(status().isForbidden());
    }

    @Test
    void missingOrInvalidToken_isUnauthorized() throws Exception {
        mockMvc.perform(get("/api/auth/audit")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer garbage")).andExpect(status().isUnauthorized());

        String foreign = Jwts.builder().subject("a@clinic.com").issuer("oncontrol3d-auth").claim("role", "ORGANIZATION")
                .claim("organizationId", 1)
                .signWith(Keys.hmacShaKeyFor("another-secret-key-with-at-least-256-bits-9876543210".getBytes(StandardCharsets.UTF_8)))
                .compact();
        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + foreign)).andExpect(status().isUnauthorized());

        String expired = Jwts.builder().subject("a@clinic.com").issuer("oncontrol3d-auth").claim("role", "ORGANIZATION")
                .claim("organizationId", 1).expiration(new Date(System.currentTimeMillis() - 60_000))
                .signWith(Keys.hmacShaKeyFor("test-secret-key-with-at-least-256-bits-0123456789".getBytes(StandardCharsets.UTF_8)))
                .compact();
        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + expired)).andExpect(status().isUnauthorized());
    }

    @Test
    void tokenFromAnotherIssuer_isUnauthorized() throws Exception {
        String clinicalToken = Jwts.builder().subject("a@clinic.com").issuer("oncontrol3d-clinical")
                .claim("role", "ORGANIZATION").claim("organizationId", 1)
                .signWith(Keys.hmacShaKeyFor("test-secret-key-with-at-least-256-bits-0123456789".getBytes(StandardCharsets.UTF_8)))
                .compact();

        mockMvc.perform(get("/api/auth/audit").header("Authorization", "Bearer " + clinicalToken))
                .andExpect(status().isUnauthorized());
    }

    // ---- S-A3-e: append-only

    @Test
    void auditEvents_havingNoWritePathInTheApi() throws Exception {
        Account orgA = save("a@clinic.com", Role.ORGANIZATION, 1L, null, null, null);
        audit.record(AuditEventType.LOGIN_SUCCEEDED, "u@a.com", 10L, 1L, "10.0.0.1");
        String bearer = "Bearer " + tokenFor(orgA);

        mockMvc.perform(post("/api/auth/audit").header("Authorization", bearer)).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(put("/api/auth/audit").header("Authorization", bearer)).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(patch("/api/auth/audit").header("Authorization", bearer)).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(delete("/api/auth/audit").header("Authorization", bearer)).andExpect(status().isMethodNotAllowed());
        mockMvc.perform(delete("/api/auth/audit/1").header("Authorization", bearer)).andExpect(status().isNotFound());

        assertThat(rows()).hasSize(1);
    }
}
