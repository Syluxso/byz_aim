package com.nyberg.iam.apikey;

import java.util.UUID;

/** Returned once on create/rotate — secret is never stored plaintext. */
public record ApiKeyCreatedResponse(
        UUID id,
        UUID organizationId,
        String kind,
        UUID userId,
        UUID tenantId,
        String appId,
        String name,
        String secret
) {}
