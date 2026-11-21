package com.oncontrol.auth.accounts.application.service;

import com.oncontrol.auth.accounts.domain.model.Account;
import com.oncontrol.auth.accounts.domain.repository.AccountRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class LoginService {

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    /** Compared against when the email is unknown so response time does not reveal which emails exist. */
    private final String timingHash;

    public LoginService(AccountRepository accounts, PasswordEncoder passwordEncoder) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.timingHash = passwordEncoder.encode("timing-equalization-placeholder");
    }

    /** @throws InvalidCredentialsException for any failure, without saying which one */
    public Account authenticate(String email, String rawPassword) {
        if (email == null || email.isBlank() || rawPassword == null || rawPassword.isEmpty()) {
            throw new InvalidCredentialsException();
        }
        Optional<Account> found = accounts.findByEmail(Account.normalize(email));
        boolean matches = passwordEncoder.matches(rawPassword, found.map(Account::getPasswordHash).orElse(timingHash));
        if (found.isEmpty()) {
            throw new InvalidCredentialsException();
        }
        if (!matches || !found.get().isActive()) {
            throw new InvalidCredentialsException(found.get());
        }
        return found.get();
    }
}
