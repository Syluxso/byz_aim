package com.nyberg.iam.dto;

import java.util.UUID;

public record MeResponse(
        UUID id,
        UUID organizationId,
        UUID tenantId,
        String email,
        String name
) {}
