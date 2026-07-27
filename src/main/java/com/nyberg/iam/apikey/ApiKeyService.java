package com.nyberg.iam.apikey;

import com.nyberg.iam.config.JwtService;
import com.nyberg.iam.domain.ApiKey;
import com.nyberg.iam.domain.Client;
import com.nyberg.iam.domain.TokenEventType;
import com.nyberg.iam.dto.TokenResponse;
import com.nyberg.iam.repository.ApiKeyRepository;
import com.nyberg.iam.repository.ClientRepository;
import com.nyberg.iam.repository.TenantRepository;
import com.nyberg.iam.repository.TokenEventRepository;
import com.nyberg.iam.repository.UserRepository;
import com.nyberg.iam.service.RoleService;
import com.nyberg.iam.domain.TokenEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ApiKeyService {

    public static final String KIND_USER = "user";
    public static final String KIND_TENANT = "tenant";
    public static final String GRANT_USER = "user_api_key";
    public static final String GRANT_TENANT = "tenant_api_key";
    private static final int SECRET_PREFIX_LEN = 12;

    private final ApiKeyRepository apiKeys;
    private final UserRepository users;
    private final TenantRepository tenants;
    private final ClientRepository clients;
    private final TokenEventRepository tokenEvents;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RoleService roleService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Transactional(readOnly = true)
    public List<ApiKeyResponse> list(UUID organizationId) {
        return apiKeys.findByOrganizationIdOrderByCreatedAtDesc(organizationId).stream()
                .map(ApiKeyResponse::from)
                .toList();
    }

    @Transactional
    public ApiKeyCreatedResponse create(UUID organizationId, CreateApiKeyRequest req, UUID createdByClientId) {
        String kind = normalizeKind(req.kind());
        String name = req.name() == null ? "" : req.name().trim();
        if (name.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required");
        }

        UUID userId = null;
        UUID tenantId = null;
        if (KIND_USER.equals(kind)) {
            if (req.userId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "userId is required for kind=user");
            }
            var user = users.findByIdAndOrganizationId(req.userId(), organizationId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found in organization"));
            if (!user.isActive()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User is inactive");
            }
            userId = user.getId();
        } else {
            if (req.tenantId() == null) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenantId is required for kind=tenant");
            }
            var tenant = tenants.findByIdAndOrganizationIdAndActiveTrue(req.tenantId(), organizationId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tenant not found in organization"));
            tenantId = tenant.getId();
        }

        String appId = uniqueAppId();
        String secret = newSecret();
        ApiKey saved = apiKeys.save(ApiKey.builder()
                .organizationId(organizationId)
                .kind(kind)
                .userId(userId)
                .tenantId(tenantId)
                .appId(appId)
                .name(name)
                .secretPrefix(secret.substring(0, SECRET_PREFIX_LEN))
                .secretHash(passwordEncoder.encode(secret))
                .active(true)
                .createdByClientId(createdByClientId)
                .build());

        logEvent(TokenEventType.API_KEY_CREATE, organizationId, userId, createdByClientId);
        return new ApiKeyCreatedResponse(
                saved.getId(),
                saved.getOrganizationId(),
                saved.getKind(),
                saved.getUserId(),
                saved.getTenantId(),
                saved.getAppId(),
                saved.getName(),
                secret
        );
    }

    @Transactional
    public ApiKeyCreatedResponse rotate(UUID organizationId, UUID keyId) {
        ApiKey key = requireActiveKey(organizationId, keyId);
        String secret = newSecret();
        key.setSecretPrefix(secret.substring(0, SECRET_PREFIX_LEN));
        key.setSecretHash(passwordEncoder.encode(secret));
        key.setRevokedAt(null);
        key.setActive(true);
        apiKeys.save(key);
        return new ApiKeyCreatedResponse(
                key.getId(),
                key.getOrganizationId(),
                key.getKind(),
                key.getUserId(),
                key.getTenantId(),
                key.getAppId(),
                key.getName(),
                secret
        );
    }

    @Transactional
    public void revoke(UUID organizationId, UUID keyId) {
        ApiKey key = apiKeys.findByIdAndOrganizationId(keyId, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found"));
        key.setActive(false);
        key.setRevokedAt(Instant.now());
        apiKeys.save(key);
    }

    /**
     * Validate a static Bearer API secret and mint a short-lived JWT for downstream services.
     * End users keep using the same secret on every call; gateway/app may call this to obtain a JWT.
     */
    @Transactional
    public TokenResponse exchangeSecretForJwt(String rawSecret) {
        ApiKey key = findBySecret(rawSecret);
        assertUsable(key);
        key.setLastUsedAt(Instant.now());
        apiKeys.save(key);

        String grant = KIND_USER.equals(key.getKind()) ? GRANT_USER : GRANT_TENANT;
        List<String> roles = List.of();
        if (key.getUserId() != null) {
            roles = roleService.claimsForToken(key.getUserId(), key.getOrganizationId(), key.getTenantId());
        }
        String jwt = jwtService.createApiKeyToken(
                key.getId(),
                key.getOrganizationId(),
                key.getTenantId(),
                key.getUserId(),
                key.getAppId(),
                grant,
                "byz-api",
                roles
        );
        logEvent(TokenEventType.API_KEY_EXCHANGE, key.getOrganizationId(), key.getUserId(), key.getCreatedByClientId());
        return TokenResponse.accessOnly(jwt, jwtService.accessTokenTtlSeconds());
    }

    private ApiKey findBySecret(String rawSecret) {
        if (rawSecret == null || rawSecret.isBlank() || rawSecret.length() < SECRET_PREFIX_LEN) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid API key");
        }
        String prefix = rawSecret.substring(0, SECRET_PREFIX_LEN);
        List<ApiKey> candidates = apiKeys.findBySecretPrefixAndActiveTrue(prefix);
        for (ApiKey candidate : candidates) {
            if (passwordEncoder.matches(rawSecret, candidate.getSecretHash())) {
                return candidate;
            }
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid API key");
    }

    private ApiKey requireActiveKey(UUID organizationId, UUID keyId) {
        ApiKey key = apiKeys.findByIdAndOrganizationId(keyId, organizationId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "API key not found"));
        assertUsable(key);
        return key;
    }

    private void assertUsable(ApiKey key) {
        if (!key.isActive() || key.getRevokedAt() != null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "API key revoked");
        }
        if (KIND_USER.equals(key.getKind())) {
            var user = users.findByIdAndOrganizationId(key.getUserId(), key.getOrganizationId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "API key user missing"));
            if (!user.isActive()) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User inactive");
            }
        } else {
            tenants.findByIdAndOrganizationIdAndActiveTrue(key.getTenantId(), key.getOrganizationId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Tenant inactive"));
        }
    }

    private static String normalizeKind(String kind) {
        if (kind == null || kind.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "kind is required");
        }
        String k = kind.trim().toLowerCase(Locale.ROOT);
        if (!KIND_USER.equals(k) && !KIND_TENANT.equals(k)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "kind must be user or tenant");
        }
        return k;
    }

    private String uniqueAppId() {
        for (int i = 0; i < 8; i++) {
            String appId = "app_" + randomHex(16);
            if (apiKeys.findByAppId(appId).isEmpty()) {
                return appId;
            }
        }
        return "app_" + UUID.randomUUID().toString().replace("-", "");
    }

    private String newSecret() {
        return "byz_sk_" + randomUrl(32);
    }

    private String randomHex(int bytes) {
        byte[] buf = new byte[bytes];
        secureRandom.nextBytes(buf);
        StringBuilder sb = new StringBuilder(bytes * 2);
        for (byte b : buf) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private String randomUrl(int bytes) {
        byte[] buf = new byte[bytes];
        secureRandom.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private void logEvent(TokenEventType type, UUID organizationId, UUID userId, UUID clientId) {
        tokenEvents.save(TokenEvent.builder()
                .eventType(type)
                .organizationId(organizationId)
                .userId(userId)
                .clientId(clientId)
                .build());
    }

    public UUID resolveClientUuid(String clientIdClaim) {
        if (clientIdClaim == null || clientIdClaim.isBlank()) {
            return null;
        }
        return clients.findByClientIdAndActiveTrue(clientIdClaim).map(Client::getId).orElse(null);
    }
}
