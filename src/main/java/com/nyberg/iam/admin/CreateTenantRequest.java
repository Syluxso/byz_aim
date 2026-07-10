package com.nyberg.iam.admin;

import jakarta.validation.constraints.NotBlank;

public record CreateTenantRequest(
        @NotBlank String name,
        String slug
) {}
