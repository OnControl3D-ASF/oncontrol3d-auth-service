package com.oncontrol.auth.audit.application.service;

import com.oncontrol.auth.audit.domain.model.AuditEvent;
import com.oncontrol.auth.audit.domain.model.AuditEventType;
import com.oncontrol.auth.audit.domain.repository.AuditEventRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.List;

@Slf4j
@Service
public class AuditService {

    static final int MAX_EMAIL = 255;
    static final int MAX_IP = 64;
    public static final int DEFAULT_PAGE_SIZE = 50;
    public static final int MAX_PAGE_SIZE = 200;

    private final AuditEventRepository repository;
    private final Clock clock;

    public AuditService(AuditEventRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /**
     * Appends an event. Synchronous but non-blocking for callers: a failure is logged and swallowed so a
     * broken audit store never breaks login or provisioning. Call it outside a caller-owned transaction
     * (a failed write inside one would mark it rollback-only).
     */
    public void record(AuditEventType type, String email, Long accountId, Long organizationId, String clientIp) {
        try {
            repository.save(AuditEvent.of(type, truncate(email, MAX_EMAIL), accountId, organizationId,
                    truncate(clientIp, MAX_IP), clock.instant()));
        } catch (RuntimeException e) {
            log.warn("Audit event {} could not be written: {}", type, e.getClass().getSimpleName());
        }
    }

    /** Newest first, only the given organization's events; size is clamped to 1..{@value #MAX_PAGE_SIZE}. */
    public List<AuditEvent> recentForOrganization(Long organizationId, int size) {
        int bounded = Math.max(1, Math.min(size, MAX_PAGE_SIZE));
        return repository.findByOrganizationIdOrderByOccurredAtDescIdDesc(organizationId, PageRequest.of(0, bounded));
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
