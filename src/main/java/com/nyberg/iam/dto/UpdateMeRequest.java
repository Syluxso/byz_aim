package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateMeRequest(
        @NotBlank @Email String email,
        /** Display name; when blank, existing IAM name is left unchanged. */
        @Size(max = 255) String name
) {}
