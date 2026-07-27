package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Bootstrap signup for platform apps (e.g. Hamlet).
 * When {@code tenantName} is present, creates a new tenant under the client's organization
 * and registers the user into it. When omitted, the user is created without a tenant
 * so the app can prompt for a workspace later.
 */
public record SignupRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        String firstName,
        String lastName,
        String phone, // accepted for forward-compat; stored by Directory after signup
        String tenantName,
        @NotBlank String clientId,
        String deviceId,
        String deviceName
) {}
