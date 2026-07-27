package com.nyberg.iam.apikey;

import com.nyberg.iam.admin.AdminAuth;
import com.nyberg.iam.dto.TokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;

/**
 * On-demand API keys (appId + secret). Business apps create keys with a service token;
 * callers use {@code Authorization: Bearer byz_sk_…} (static). Resolve exchanges secret → JWT.
 */
@RestController
@RequiredArgsConstructor
public class ApiKeyController {

    private final ApiKeyService apiKeys;

    /** List keys for an org. Platform admin JWT or service token for that org. */
    @GetMapping("/api/v1/orgs/{orgId}/api-keys")
    public List<ApiKeyResponse> list(@PathVariable UUID orgId) {
        requireOrgAccess(orgId);
        return apiKeys.list(orgId);
    }

    /**
     * Create a key for a user or tenant in this org.
     * Caller must be a service token ({@code client_credentials}) or platform admin for that org.
     */
    @PostMapping("/api/v1/orgs/{orgId}/api-keys")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiKeyCreatedResponse create(@PathVariable UUID orgId, @Valid @RequestBody CreateApiKeyRequest req) {
        Jwt jwt = requireOrgAccess(orgId);
        UUID createdByClient = apiKeys.resolveClientUuid(jwt.getClaimAsString("client_id"));
        return apiKeys.create(orgId, req, createdByClient);
    }

    @PostMapping("/api/v1/orgs/{orgId}/api-keys/{id}/rotate")
    public ApiKeyCreatedResponse rotate(@PathVariable UUID orgId, @PathVariable UUID id) {
        requireOrgAccess(orgId);
        return apiKeys.rotate(orgId, id);
    }

    @DeleteMapping("/api/v1/orgs/{orgId}/api-keys/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID orgId, @PathVariable UUID id) {
        requireOrgAccess(orgId);
        apiKeys.revoke(orgId, id);
    }

    /**
     * Exchange a static API secret for a short-lived access JWT.
     * Send {@code Authorization: Bearer byz_sk_…}. No prior login required.
     * Gateway/business apps can call this on each request (or cache the JWT until expiry).
     */
    @PostMapping("/api/v1/api-keys/resolve")
    public TokenResponse resolve(HttpServletRequest request) {
        String secret = bearer(request);
        return apiKeys.exchangeSecretForJwt(secret);
    }

    private Jwt requireOrgAccess(UUID orgId) {
        Jwt jwt = AdminAuth.requireJwt();
        UUID tokenOrg = AdminAuth.organizationId(jwt);
        if (!tokenOrg.equals(orgId)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token organization does not match");
        }
        String grant = jwt.getClaimAsString("grant_type");
        // Service tokens create keys for their org; password/admin user tokens also allowed (you).
        if (grant == null || grant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Missing grant_type");
        }
        return jwt;
    }

    private static String bearer(HttpServletRequest request) {
        String h = request.getHeader("Authorization");
        if (h == null || !h.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bearer API key required");
        }
        String token = h.substring(7).trim();
        if (token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bearer API key required");
        }
        return token;
    }
}
