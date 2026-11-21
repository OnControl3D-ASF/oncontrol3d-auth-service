package com.oncontrol.auth.accounts.application;

import com.oncontrol.auth.accounts.application.service.InvalidCredentialsException;
import com.oncontrol.auth.accounts.application.service.LoginService;
import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** S-A1-d: unknown email, wrong password and inactive account are indistinguishable. */
class LoginServiceTest {

    private final PasswordEncoder encoder = new BCryptPasswordEncoder(4);
    private final AccountRepository accounts = mock(AccountRepository.class);
    private LoginService service;

    @BeforeEach
    void setUp() {
        service = new LoginService(accounts, encoder);
    }

    private Account doctor() {
        return Account.create("Dr@Clinic.com", encoder.encode("correct-horse"), Role.DOCTOR, 1L, 5L, 7L, null);
    }

    @Test
    void correctCredentials_returnTheAccount() {
        Account doctor = doctor();
        when(accounts.findByEmail("dr@clinic.com")).thenReturn(Optional.of(doctor));

        assertThat(service.authenticate("dr@clinic.com", "correct-horse")).isSameAs(doctor);
    }

    @Test
    void emailLookup_isCaseInsensitiveAndTrimmed() {
        Account doctor = doctor();
        when(accounts.findByEmail("dr@clinic.com")).thenReturn(Optional.of(doctor));

        assertThat(service.authenticate("  DR@Clinic.COM ", "correct-horse")).isSameAs(doctor);
        verify(accounts).findByEmail("dr@clinic.com");
    }

    @Test
    void unknownEmail_isInvalidCredentials() {
        when(accounts.findByEmail("nobody@clinic.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.authenticate("nobody@clinic.com", "whatever"))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void wrongPassword_isInvalidCredentials() {
        when(accounts.findByEmail("dr@clinic.com")).thenReturn(Optional.of(doctor()));

        assertThatThrownBy(() -> service.authenticate("dr@clinic.com", "wrong"))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void inactiveAccount_isInvalidCredentials_evenWithCorrectPassword() {
        Account doctor = doctor();
        doctor.deactivate();
        when(accounts.findByEmail("dr@clinic.com")).thenReturn(Optional.of(doctor));

        assertThatThrownBy(() -> service.authenticate("dr@clinic.com", "correct-horse"))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void nullOrBlankInput_isInvalidCredentials_withoutTouchingTheRepository() {
        assertThatThrownBy(() -> service.authenticate(null, "x")).isInstanceOf(InvalidCredentialsException.class);
        assertThatThrownBy(() -> service.authenticate("dr@clinic.com", null)).isInstanceOf(InvalidCredentialsException.class);
        assertThatThrownBy(() -> service.authenticate("  ", "x")).isInstanceOf(InvalidCredentialsException.class);
        org.mockito.Mockito.verifyNoInteractions(accounts);
    }

    @Test
    void allFailureModes_shareTheSameMessage() {
        when(accounts.findByEmail("nobody@clinic.com")).thenReturn(Optional.empty());
        when(accounts.findByEmail("dr@clinic.com")).thenReturn(Optional.of(doctor()));

        String unknown = catchMessage("nobody@clinic.com", "x");
        String wrong = catchMessage("dr@clinic.com", "x");

        assertThat(unknown).isEqualTo("Invalid credentials").isEqualTo(wrong);
    }

    private String catchMessage(String email, String password) {
        try {
            service.authenticate(email, password);
            return "no exception";
        } catch (InvalidCredentialsException e) {
            return e.getMessage();
        }
    }
}
