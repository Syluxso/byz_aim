package com.nyberg.iam.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SetOperatorPasswordRequest(
        @NotBlank @Size(min = 8, max = 200) String password
) {}
