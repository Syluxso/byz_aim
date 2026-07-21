package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password,
        @NotBlank String clientId,
        /** Optional stable device id from the app. */
        String deviceId,
        /** Optional friendly name, e.g. "Darryn's Pixel". */
        String deviceName
) {}
