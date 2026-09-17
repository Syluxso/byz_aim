package com.nyberg.iam.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UpdateMeRequest(
        @NotBlank @Email String email,
        @Size(max = 255) String firstName,
        @Size(max = 255) String lastName,
        /** Display name; used when first/last are omitted. Blank leaves existing name unchanged. */
        @Size(max = 255) String name
) {}
