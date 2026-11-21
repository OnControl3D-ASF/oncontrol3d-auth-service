package com.oncontrol.auth.accounts.infrastructure.dto;

import com.oncontrol.auth.accounts.application.service.ProvisionAccountCommand;
import com.oncontrol.auth.accounts.domain.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record ProvisionAccountRequest(
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank String password,
        @NotNull Role role,
        @NotNull Long organizationId,
        Long profileId,
        Long doctorProfileId,
        Long patientProfileId) {

    public ProvisionAccountCommand toCommand() {
        return new ProvisionAccountCommand(email, password, role, organizationId, profileId, doctorProfileId, patientProfileId);
    }

    /** Never print the password, even by accident. */
    @Override
    public String toString() {
        return "ProvisionAccountRequest[email=" + email + ", role=" + role + "]";
    }
}
