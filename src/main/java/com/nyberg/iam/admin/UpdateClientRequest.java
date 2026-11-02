package com.nyberg.iam.admin;

/**
 * PATCH /orgs/{orgId}/clients/{id}. appBaseUrl is the public base URL of the
 * app that owns the client (e.g. https://inquiry.example.org); password reset
 * links point there. Blank or null clears it, falling back to the platform
 * default.
 */
public record UpdateClientRequest(
        String appBaseUrl
) {}
