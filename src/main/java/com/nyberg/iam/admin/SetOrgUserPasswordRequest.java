package com.nyberg.iam.admin;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SetOrgUserPasswordRequest(
        @NotBlank @Size(min = 4, max = 200) String password
) {}
