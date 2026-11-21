package com.oncontrol.auth.audit.infrastructure.controller;

import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.security.infrastructure.filter.AuthenticatedAccount;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/** Read-only view of the caller's organization events (HU09). SecurityConfig restricts it to ORGANIZATION. */
@RestController
@RequestMapping("/api/auth/audit")
public class AuditController {

    private final AuditService audit;

    public AuditController(AuditService audit) {
        this.audit = audit;
    }

    @GetMapping
    public List<AuditEventResponse> list(@AuthenticationPrincipal AuthenticatedAccount caller,
                                         @RequestParam(defaultValue = "" + AuditService.DEFAULT_PAGE_SIZE) int size) {
        return audit.recentForOrganization(caller.organizationId(), size).stream()
                .map(AuditEventResponse::from).toList();
    }
}
