package com.oncontrol.auth.accounts.application.service;

import com.oncontrol.auth.accounts.domain.model.Account;

import java.util.Optional;

/**
 * Unknown email, wrong password and inactive account all surface as this single, identical error
 * (the message never differs). The matched account, when there is one, is carried only so the caller
 * can audit the attempt; it is never part of the response.
 */
public class InvalidCredentialsException extends RuntimeException {

    private final transient Account account;

    public InvalidCredentialsException() {
        this(null);
    }

    public InvalidCredentialsException(Account account) {
        super("Invalid credentials");
        this.account = account;
    }

    public Optional<Account> account() {
        return Optional.ofNullable(account);
    }
}
