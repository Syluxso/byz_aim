package com.nyberg.iam.admin;

import jakarta.validation.constraints.NotBlank;

public record CreateOrgRequest(
        @NotBlank String name,
        String slug
) {}
