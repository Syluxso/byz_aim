package com.nyberg.iam.dto;

import jakarta.validation.constraints.NotBlank;

import java.util.UUID;

/**
 * OAuth token request.
 * <ul>
 *   <li>{@code grantType=client_credentials} — service token (sub = clientId)</li>
 *   <li>{@code grantType=subject} or {@code urn:byz:params:oauth:grant-type:subject}
 *       — short-lived recipient token (sub = subject UUID); confidential client only</li>
 * </ul>
 */
public record TokenRequest(
        @NotBlank String grantType,
        @NotBlank String clientId,
        String clientSecret,
        UUID subject
) {}
