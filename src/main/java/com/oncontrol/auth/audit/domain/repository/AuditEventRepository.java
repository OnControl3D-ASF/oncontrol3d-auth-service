package com.oncontrol.auth.audit.domain.repository;

import com.oncontrol.auth.audit.domain.model.AuditEvent;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.Repository;

import java.util.List;

/** Deliberately NOT a JpaRepository: append and read only, no update or delete operations. */
public interface AuditEventRepository extends Repository<AuditEvent, Long> {

    AuditEvent save(AuditEvent event);

    List<AuditEvent> findByOrganizationIdOrderByOccurredAtDescIdDesc(Long organizationId, Pageable pageable);
}
