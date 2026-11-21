package com.oncontrol.auth.accounts.infrastructure.dto;

public record LoginRequest(String email, String password) {

    /** Never print the password, even by accident. */
    @Override
    public String toString() {
        return "LoginRequest[email=" + email + "]";
    }
}
