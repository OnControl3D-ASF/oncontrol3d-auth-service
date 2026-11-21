package com.oncontrol.auth.audit.domain.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Immutable;

import java.time.Instant;

/** Append-only security event. Never holds passwords or tokens. */
@Entity
@Immutable
@Table(name = "audit_events")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, updatable = false)
    private Instant occurredAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, updatable = false)
    private AuditEventType type;

    /** Account email, or the attempted email for an unknown account. */
    @Column(updatable = false)
    private String email;

    @Column(updatable = false)
    private Long accountId;

    @Column(updatable = false)
    private Long organizationId;

    @Column(length = 64, updatable = false)
    private String clientIp;

    public static AuditEvent of(AuditEventType type, String email, Long accountId, Long organizationId,
                                String clientIp, Instant occurredAt) {
        AuditEvent event = new AuditEvent();
        event.type = type;
        event.email = email;
        event.accountId = accountId;
        event.organizationId = organizationId;
        event.clientIp = clientIp;
        event.occurredAt = occurredAt;
        return event;
    }
}
