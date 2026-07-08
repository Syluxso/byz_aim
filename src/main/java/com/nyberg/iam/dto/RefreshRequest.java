package com.nyberg.iam.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshRequest(
        @NotBlank String refreshToken,
        @NotBlank String clientId
) {}