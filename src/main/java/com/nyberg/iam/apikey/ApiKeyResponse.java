package com.nyberg.iam.apikey;

import com.nyberg.iam.domain.ApiKey;

import java.time.Instant;
import java.util.UUID;

public record ApiKeyResponse(
        UUID id,
        UUID organizationId,
        String kind,
        UUID userId,
        UUID tenantId,
        String appId,
        String name,
        boolean active,
        Instant revokedAt,
        Instant lastUsedAt,
        Instant createdAt
) {
    public static ApiKeyResponse from(ApiKey k) {
        return new ApiKeyResponse(
                k.getId(),
                k.getOrganizationId(),
                k.getKind(),
                k.getUserId(),
                k.getTenantId(),
                k.getAppId(),
                k.getName(),
                k.isActive(),
                k.getRevokedAt(),
                k.getLastUsedAt(),
                k.getCreatedAt()
        );
    }
}
