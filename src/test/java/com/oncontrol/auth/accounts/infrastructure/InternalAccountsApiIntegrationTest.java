package com.oncontrol.auth.accounts.infrastructure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import com.oncontrol.auth.support.IntegrationTest;
import com.oncontrol.auth.support.TestIps;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** REQ-A2: internal provisioning API (S-A2-a, S-A2-b, S-A2-f). */
@IntegrationTest
class InternalAccountsApiIntegrationTest {

    private static final String INTERNAL_TOKEN = "test-internal-token-with-at-least-32-bytes-0123";

    @Autowired MockMvc mockMvc;
    @Autowired AccountRepository accounts;
    @Autowired PasswordEncoder encoder;
    @Autowired JwtIssuer issuer;
    @Autowired ObjectMapper json;

    @BeforeEach
    void clean() {
        accounts.deleteAll();
    }

    private static Map<String, Object> doctorBody(String email) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("password", "Passw0rd!Passw0rd!");
        body.put("role", "DOCTOR");
        body.put("organizationId", 1);
        body.put("profileId", 5);
        body.put("doctorProfileId", 7);
        return body;
    }

    private MockHttpServletRequestBuilder provision(Map<String, Object> body) throws Exception {
        return post("/internal/accounts").contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
    }

    private MvcResult withToken(MockHttpServletRequestBuilder request) throws Exception {
        return mockMvc.perform(request.header("X-Internal-Token", INTERNAL_TOKEN)).andReturn();
    }

    @Test
    void withoutOrWithWrongInternalToken_isRejected() throws Exception {
        mockMvc.perform(provision(doctorBody("dr@clinic.com"))).andExpect(status().isUnauthorized());
        mockMvc.perform(provision(doctorBody("dr@clinic.com")).header("X-Internal-Token", "wrong-token-value"))
                .andExpect(status().isUnauthorized());
        assertThat(accounts.count()).isZero();
    }

    @Test
    void endUserJwt_doesNotGrantAccessToTheInternalApi() throws Exception {
        String orgToken = issuer.issue(Account.create("org@clinic.com", "h", Role.ORGANIZATION, 1L, null, null, null)).token();

        mockMvc.perform(provision(doctorBody("dr@clinic.com")).header("Authorization", "Bearer " + orgToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(delete("/internal/accounts/1").header("Authorization", "Bearer " + orgToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validRequest_creates201_storesBcryptHashAndLowerCasedEmail_andTheAccountCanLogIn() throws Exception {
        MvcResult result = withToken(provision(doctorBody("Dr.Who@Clinic.com")));

        assertThat(result.getResponse().getStatus()).isEqualTo(201);
        JsonNode body = json.readTree(result.getResponse().getContentAsString());
        assertThat(body.fieldNames()).toIterable().containsExactly("accountId");
        Account stored = accounts.findById(body.get("accountId").asLong()).orElseThrow();
        assertThat(stored.getEmail()).isEqualTo("dr.who@clinic.com");
        assertThat(stored.getRole()).isEqualTo(Role.DOCTOR);
        assertThat(stored.getOrganizationId()).isEqualTo(1L);
        assertThat(stored.getProfileId()).isEqualTo(5L);
        assertThat(stored.getDoctorProfileId()).isEqualTo(7L);
        assertThat(stored.getPasswordHash()).startsWith("$2").isNotEqualTo("Passw0rd!Passw0rd!");
        assertThat(encoder.matches("Passw0rd!Passw0rd!", stored.getPasswordHash())).isTrue();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("Passw0rd").doesNotContain("$2");

        mockMvc.perform(post("/api/auth/login").header("X-Forwarded-For", TestIps.fresh())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"DR.WHO@clinic.com\",\"password\":\"Passw0rd!Passw0rd!\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void organizationAccount_needsOnlyTheOrganizationId() throws Exception {
        Map<String, Object> org = new LinkedHashMap<>();
        org.put("email", "org@clinic.com");
        org.put("password", "Passw0rd!Passw0rd!");
        org.put("role", "ORGANIZATION");
        org.put("organizationId", 9);

        assertThat(withToken(provision(org)).getResponse().getStatus()).isEqualTo(201);
        assertThat(accounts.findByEmail("org@clinic.com")).get().extracting(Account::getProfileId).isNull();
    }

    @Test
    void patientAccount_storesAllIds() throws Exception {
        Map<String, Object> patient = new LinkedHashMap<>();
        patient.put("email", "pat@clinic.com");
        patient.put("password", "Passw0rd!Passw0rd!");
        patient.put("role", "PATIENT");
        patient.put("organizationId", 1);
        patient.put("profileId", 9);
        patient.put("doctorProfileId", 7);
        patient.put("patientProfileId", 12);

        assertThat(withToken(provision(patient)).getResponse().getStatus()).isEqualTo(201);
        Account stored = accounts.findByEmail("pat@clinic.com").orElseThrow();
        assertThat(stored.getPatientProfileId()).isEqualTo(12L);
        assertThat(stored.getDoctorProfileId()).isEqualTo(7L);
    }

    @Test
    void duplicateEmail_isConflict_caseInsensitive_andKeepsTheOriginalAccount() throws Exception {
        assertThat(withToken(provision(doctorBody("dr@clinic.com"))).getResponse().getStatus()).isEqualTo(201);

        MvcResult duplicate = withToken(provision(doctorBody("DR@Clinic.com")));

        assertThat(duplicate.getResponse().getStatus()).isEqualTo(409);
        assertThat(duplicate.getResponse().getContentAsString()).contains("Email already exists");
        assertThat(accounts.count()).isEqualTo(1);
    }

    @Test
    void invalidPayloads_areBadRequest_andNothingIsStored() throws Exception {
        Map<String, Object> noEmail = doctorBody("x@clinic.com");
        noEmail.put("email", " ");
        Map<String, Object> badEmail = doctorBody("not-an-email");
        Map<String, Object> noPassword = doctorBody("a@clinic.com");
        noPassword.put("password", "");
        Map<String, Object> tooLongPassword = doctorBody("b@clinic.com");
        tooLongPassword.put("password", "p".repeat(73));
        Map<String, Object> noRole = doctorBody("c@clinic.com");
        noRole.remove("role");
        Map<String, Object> unknownRole = doctorBody("d@clinic.com");
        unknownRole.put("role", "ADMIN");
        Map<String, Object> noOrg = doctorBody("e@clinic.com");
        noOrg.remove("organizationId");
        Map<String, Object> doctorWithoutIds = doctorBody("f@clinic.com");
        doctorWithoutIds.remove("doctorProfileId");
        Map<String, Object> orgWithProfileIds = doctorBody("g@clinic.com");
        orgWithProfileIds.put("role", "ORGANIZATION");
        Map<String, Object> patientWithoutPatientId = doctorBody("h@clinic.com");
        patientWithoutPatientId.put("role", "PATIENT");

        for (Map<String, Object> body : java.util.List.of(noEmail, badEmail, noPassword, tooLongPassword, noRole,
                unknownRole, noOrg, doctorWithoutIds, orgWithProfileIds, patientWithoutPatientId)) {
            assertThat(withToken(provision(body)).getResponse().getStatus()).as(body.toString()).isEqualTo(400);
        }
        mockMvc.perform(post("/internal/accounts").header("X-Internal-Token", INTERNAL_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("{not json"))
                .andExpect(status().isBadRequest());
        assertThat(accounts.count()).isZero();
    }

    @Test
    void delete_removesTheAccount_andIsIdempotent() throws Exception {
        Account saved = accounts.save(Account.create("dr@clinic.com", encoder.encode("x"), Role.DOCTOR, 1L, 5L, 7L, null));
        String url = "/internal/accounts/" + saved.getId();

        mockMvc.perform(delete(url).header("X-Internal-Token", INTERNAL_TOKEN)).andExpect(status().isNoContent());
        assertThat(accounts.existsById(saved.getId())).isFalse();
        mockMvc.perform(delete(url).header("X-Internal-Token", INTERNAL_TOKEN)).andExpect(status().isNoContent());
        mockMvc.perform(delete("/internal/accounts/987654").header("X-Internal-Token", INTERNAL_TOKEN))
                .andExpect(status().isNoContent());
    }

    @Test
    void delete_requiresTheInternalToken() throws Exception {
        Account saved = accounts.save(Account.create("dr@clinic.com", encoder.encode("x"), Role.DOCTOR, 1L, 5L, 7L, null));

        mockMvc.perform(delete("/internal/accounts/" + saved.getId())).andExpect(status().isUnauthorized());
        assertThat(accounts.existsById(saved.getId())).isTrue();
    }

    @Test
    void internalApi_doesNotExistUnderApiAuth_evenWithTheToken() throws Exception {
        mockMvc.perform(post("/api/auth/internal/accounts").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(doctorBody("dr@clinic.com")))
                .header("X-Internal-Token", INTERNAL_TOKEN)).andExpect(status().isNotFound());
        assertThat(accounts.count()).isZero();
    }
}
