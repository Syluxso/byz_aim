package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Bootstrap signup for platform apps (e.g. Hamlet): creates a new tenant under the
 * client's organization, then registers the user into that tenant.
 */
public record SignupRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        String firstName,
        String lastName,
        String phone, // accepted for forward-compat; stored by Directory after signup
        @NotBlank String tenantName,
        @NotBlank String clientId,
        String deviceId,
        String deviceName
) {}
