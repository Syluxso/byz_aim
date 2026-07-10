package com.nyberg.iam.admin;

import com.nyberg.iam.domain.Tenant;

import java.time.Instant;
import java.util.UUID;

public record TenantResponse(UUID id, UUID organizationId, String name, String slug, boolean active, Instant createdAt) {
    public static TenantResponse from(Tenant t) {
        return new TenantResponse(t.getId(), t.getOrganizationId(), t.getName(), t.getSlug(), t.isActive(), t.getCreatedAt());
    }
}
