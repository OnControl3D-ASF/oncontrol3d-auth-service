package com.oncontrol.auth.security.infrastructure.jwt;

public record IssuedToken(String token, long expiresInSeconds) {
}
