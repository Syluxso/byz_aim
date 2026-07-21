package com.nyberg.iam.admin;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

public final class AdminAuth {

    private AdminAuth() {}

    public static Jwt requireJwt() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof Jwt jwt)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }
        return jwt;
    }

    public static UUID organizationId(Jwt jwt) {
        String raw = jwt.getClaimAsString("organization_id");
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token missing organization_id");
        }
        return UUID.fromString(raw);
    }

    public static UUID subjectUserId(Jwt jwt) {
        try {
            return UUID.fromString(jwt.getSubject());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token subject is not a user id");
        }
    }
}
