package com.oncontrol.auth.accounts.application.service;

/** Unknown email, wrong password and inactive account all surface as this single, identical error. */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid credentials");
    }
}
