package com.nyberg.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenRequest(
        @NotBlank String grantType,
        @NotBlank String clientId,
        String clientSecret
) {}