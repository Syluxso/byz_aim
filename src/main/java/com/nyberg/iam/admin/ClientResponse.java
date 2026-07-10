package com.nyberg.iam.admin;

import com.nyberg.iam.domain.Client;

import java.time.Instant;
import java.util.UUID;

public record ClientResponse(
        UUID id, String clientId, UUID organizationId, UUID tenantId,
        String name, String clientType, String grantTypes, boolean active, Instant createdAt
) {
    public static ClientResponse from(Client c) {
        return new ClientResponse(
                c.getId(), c.getClientId(), c.getOrganizationId(), c.getTenantId(),
                c.getName(), c.getClientType().name(), c.getGrantTypes(), c.isActive(), c.getCreatedAt());
    }
}
