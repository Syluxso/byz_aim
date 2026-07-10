package com.nyberg.iam.admin;

import jakarta.validation.constraints.NotBlank;

import java.util.UUID;

public record CreateClientRequest(
        @NotBlank String clientId,
        @NotBlank String name,
        String type,      // "public" or "confidential" — defaults to confidential
        UUID tenantId     // optional
) {}
