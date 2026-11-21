package com.oncontrol.auth.security.infrastructure.filter;

import com.oncontrol.auth.accounts.domain.model.Role;

/** Principal built from a verified end-user JWT. */
public record AuthenticatedAccount(String email, Role role, Long organizationId) {
}
