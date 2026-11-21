package com.oncontrol.auth.accounts.infrastructure.dto;

import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.security.infrastructure.jwt.IssuedToken;

/** Slim login body: the token plus the ids. Clinical profile data is served by clinical's GET /api/me. */
public record LoginResponse(String token, String tokenType, long expiresIn, String role,
                            Long organizationId, Long profileId, Long doctorProfileId, Long patientProfileId) {

    public static LoginResponse of(IssuedToken issued, Account account) {
        return new LoginResponse(issued.token(), "Bearer", issued.expiresInSeconds(), account.getRole().name(),
                account.getOrganizationId(), account.getProfileId(), account.getDoctorProfileId(),
                account.getPatientProfileId());
    }
}
