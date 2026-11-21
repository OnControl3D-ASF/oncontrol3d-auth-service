package com.oncontrol.auth.audit.application;

import com.oncontrol.auth.audit.application.service.AuditService;
import com.oncontrol.auth.audit.domain.model.AuditEvent;
import com.oncontrol.auth.audit.domain.model.AuditEventType;
import com.oncontrol.auth.audit.domain.repository.AuditEventRepository;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuditServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-21T10:00:00Z");
    private final AuditEventRepository repository = mock(AuditEventRepository.class);
    private final AuditService service = new AuditService(repository, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void record_persistsAnEventWithAllFields() {
        service.record(AuditEventType.LOGIN_SUCCEEDED, "dr@clinic.com", 4L, 1L, "10.0.0.1");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(repository).save(captor.capture());
        AuditEvent event = captor.getValue();
        assertThat(event.getType()).isEqualTo(AuditEventType.LOGIN_SUCCEEDED);
        assertThat(event.getEmail()).isEqualTo("dr@clinic.com");
        assertThat(event.getAccountId()).isEqualTo(4L);
        assertThat(event.getOrganizationId()).isEqualTo(1L);
        assertThat(event.getClientIp()).isEqualTo("10.0.0.1");
        assertThat(event.getOccurredAt()).isEqualTo(NOW);
    }

    @Test
    void record_keepsAttemptedEmailWithoutAccount() {
        service.record(AuditEventType.LOGIN_FAILED, "ghost@clinic.com", null, null, "10.0.0.2");

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("ghost@clinic.com");
        assertThat(captor.getValue().getAccountId()).isNull();
        assertThat(captor.getValue().getOrganizationId()).isNull();
    }

    @Test
    void record_truncatesOversizedAttackerControlledValues() {
        service.record(AuditEventType.LOGIN_FAILED, "a".repeat(1_000), null, null, "9".repeat(500));

        ArgumentCaptor<AuditEvent> captor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).hasSize(255);
        assertThat(captor.getValue().getClientIp()).hasSize(64);
    }

    @Test
    void record_neverThrows_whenThePersistenceFails() {
        doThrow(new IllegalStateException("db down")).when(repository).save(any());

        assertThatCode(() -> service.record(AuditEventType.LOGIN_SUCCEEDED, "a@b.com", 1L, 1L, "10.0.0.1"))
                .doesNotThrowAnyException();
    }
}
