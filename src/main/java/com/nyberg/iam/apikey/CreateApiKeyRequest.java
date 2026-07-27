package com.nyberg.iam.apikey;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record CreateApiKeyRequest(
        @NotBlank String kind,       // "user" | "tenant"
        @NotBlank String name,
        UUID userId,                 // required when kind=user
        UUID tenantId                // required when kind=tenant
) {}
