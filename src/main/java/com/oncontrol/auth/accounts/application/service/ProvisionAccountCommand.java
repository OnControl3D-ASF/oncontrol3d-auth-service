package com.oncontrol.auth.accounts.application.service;

import com.oncontrol.auth.accounts.domain.model.Role;

public record ProvisionAccountCommand(String email, String password, Role role, Long organizationId,
                                      Long profileId, Long doctorProfileId, Long patientProfileId) {

    /** Never print the password, even by accident. */
    @Override
    public String toString() {
        return "ProvisionAccountCommand[email=" + email + ", role=" + role + ", organizationId=" + organizationId + "]";
    }
}
