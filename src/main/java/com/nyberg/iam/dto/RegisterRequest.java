package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

public record RegisterRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        String name, // optional — defaults to email local-part when blank
        @NotBlank String clientId,
        @NotNull UUID tenantId
) {}
