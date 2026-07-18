package com.nyberg.iam.admin;

import com.nyberg.iam.domain.User;

import java.time.Instant;
import java.util.UUID;

public record OperatorUserResponse(
        UUID id,
        UUID organizationId,
        UUID tenantId,
        String email,
        String name,
        boolean active,
        Instant createdAt
) {
    public static OperatorUserResponse from(User u) {
        return new OperatorUserResponse(
                u.getId(),
                u.getOrganizationId(),
                u.getTenantId(),
                u.getEmail(),
                u.getName(),
                u.isActive(),
                u.getCreatedAt()
        );
    }
}
