package com.oncontrol.auth.security.infrastructure.filter;

import com.oncontrol.auth.accounts.domain.model.Role;
import com.oncontrol.auth.security.infrastructure.config.AuthSecurityProperties;
import com.oncontrol.auth.security.infrastructure.jwt.JwtIssuer;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Verifies end-user Bearer tokens issued by this service (signature, expiry, issuer). Invalid or
 * missing tokens simply leave the request unauthenticated (401 from the entry point). It never runs
 * for {@code /internal/**}, so an end-user JWT can not reach the internal API.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";
    private final SecretKey key;

    public JwtAuthenticationFilter(AuthSecurityProperties properties) {
        this.key = Keys.hmacShaKeyFor(properties.jwtSecret().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getRequestURI().startsWith("/internal/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER)) {
            authenticate(header.substring(BEARER.length()).trim());
        }
        chain.doFilter(request, response);
    }

    private void authenticate(String token) {
        try {
            Claims claims = Jwts.parser().verifyWith(key).requireIssuer(JwtIssuer.ISSUER).build()
                    .parseSignedClaims(token).getPayload();
            Role role = Role.valueOf(claims.get("role", String.class));
            Number organizationId = claims.get("organizationId", Number.class);
            if (organizationId == null) {
                return;
            }
            AuthenticatedAccount principal = new AuthenticatedAccount(claims.getSubject(), role, organizationId.longValue());
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                    principal, null, AuthorityUtils.createAuthorityList("ROLE_" + role.name())));
        } catch (JwtException | IllegalArgumentException | NullPointerException e) {
            // Unauthenticated: the entry point answers 401.
        }
    }
}
