package com.oncontrol.auth.accounts.application.service;

import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.audit.domain.model.AuditEventType;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

/**
 * Creates and removes credentials on behalf of the clinical service. Deliberately not
 * {@code @Transactional}: each repository call is its own transaction and the audit write
 * happens after it, so an audit failure can never undo a provisioning.
 */
@Service
public class AccountProvisioningService {

    /** bcrypt only considers the first 72 bytes. */
    static final int MAX_PASSWORD_BYTES = 72;

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final AuditService audit;

    public AccountProvisioningService(AccountRepository accounts, PasswordEncoder passwordEncoder, AuditService audit) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.audit = audit;
    }

    public long provision(ProvisionAccountCommand command, String clientIp) {
        validate(command);
        String email = Account.normalize(command.email());
        if (accounts.findByEmail(email).isPresent()) {
            throw new EmailAlreadyExistsException();
        }
        Account saved;
        try {
            saved = accounts.saveAndFlush(Account.create(email, passwordEncoder.encode(command.password()),
                    command.role(), command.organizationId(), command.profileId(),
                    command.doctorProfileId(), command.patientProfileId()));
        } catch (DataIntegrityViolationException e) {
            // Lost a race against a concurrent request with the same email.
            throw new EmailAlreadyExistsException();
        }
        audit.record(AuditEventType.ACCOUNT_PROVISIONED, saved.getEmail(), saved.getId(), saved.getOrganizationId(), clientIp);
        return saved.getId();
    }

    /** Idempotent: unknown ids are ignored (and not audited). */
    public void deprovision(long accountId, String clientIp) {
        accounts.findById(accountId).ifPresent(account -> {
            accounts.delete(account);
            audit.record(AuditEventType.ACCOUNT_DEPROVISIONED, account.getEmail(), account.getId(),
                    account.getOrganizationId(), clientIp);
        });
    }

    private static void validate(ProvisionAccountCommand c) {
        if (c.password().getBytes(StandardCharsets.UTF_8).length > MAX_PASSWORD_BYTES) {
            throw new InvalidAccountException("password must be at most " + MAX_PASSWORD_BYTES + " bytes");
        }
        switch (c.role()) {
            case ORGANIZATION -> {
                if (c.profileId() != null || c.doctorProfileId() != null || c.patientProfileId() != null) {
                    throw new InvalidAccountException("ORGANIZATION accounts must not carry profile ids");
                }
            }
            case DOCTOR -> {
                if (c.profileId() == null || c.doctorProfileId() == null) {
                    throw new InvalidAccountException("DOCTOR accounts require profileId and doctorProfileId");
                }
            }
            case PATIENT -> {
                if (c.profileId() == null || c.patientProfileId() == null) {
                    throw new InvalidAccountException("PATIENT accounts require profileId and patientProfileId");
                }
            }
        }
    }
}
