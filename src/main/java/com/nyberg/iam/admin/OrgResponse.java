package com.nyberg.iam.admin;

import com.nyberg.iam.domain.Organization;

import java.time.Instant;
import java.util.UUID;

public record OrgResponse(UUID id, String name, String slug, boolean active, Instant createdAt) {
    public static OrgResponse from(Organization o) {
        return new OrgResponse(o.getId(), o.getName(), o.getSlug(), o.isActive(), o.getCreatedAt());
    }
}
