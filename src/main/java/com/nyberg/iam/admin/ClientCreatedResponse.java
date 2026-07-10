package com.nyberg.iam.admin;

import com.nyberg.iam.domain.Client;

import java.time.Instant;
import java.util.UUID;

// clientSecret is included once on creation or rotation — never stored in plaintext
public record ClientCreatedResponse(
        UUID id, String clientId, UUID organizationId, UUID tenantId,
        String name, String clientType, String grantTypes, boolean active, Instant createdAt,
        String clientSecret
) {
    public static ClientCreatedResponse from(Client c, String secret) {
        return new ClientCreatedResponse(
                c.getId(), c.getClientId(), c.getOrganizationId(), c.getTenantId(),
                c.getName(), c.getClientType().name(), c.getGrantTypes(), c.isActive(), c.getCreatedAt(),
                secret);
    }
}
