package com.oncontrol.auth.audit.infrastructure.controller;

import com.oncontrol.auth.audit.domain.model.AuditEvent;

import java.time.Instant;

public record AuditEventResponse(Long id, Instant occurredAt, String type, String email, Long accountId,
                                 Long organizationId, String clientIp) {

    static AuditEventResponse from(AuditEvent e) {
        return new AuditEventResponse(e.getId(), e.getOccurredAt(), e.getType().name(), e.getEmail(),
                e.getAccountId(), e.getOrganizationId(), e.getClientIp());
    }
}
