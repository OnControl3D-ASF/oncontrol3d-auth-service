package com.oncontrol.auth.accounts.infrastructure.controller;

import com.oncontrol.auth.accounts.application.service.AccountProvisioningService;
import com.oncontrol.auth.accounts.infrastructure.dto.ProvisionAccountRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Provisioning API consumed only by the clinical service. Never routed by any edge/proxy. */
@RestController
@RequestMapping("/internal/accounts")
public class InternalAccountController {

    private final AccountProvisioningService provisioning;

    public InternalAccountController(AccountProvisioningService provisioning) {
        this.provisioning = provisioning;
    }

    @PostMapping
    public ResponseEntity<Map<String, Long>> provision(@Valid @RequestBody ProvisionAccountRequest request,
                                                       HttpServletRequest http) {
        long accountId = provisioning.provision(request.toCommand(), http.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("accountId", accountId));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deprovision(@PathVariable long id, HttpServletRequest http) {
        provisioning.deprovision(id, http.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }
}
