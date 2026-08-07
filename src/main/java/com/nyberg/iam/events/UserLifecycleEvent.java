package com.nyberg.iam.events;

import java.time.Instant;
import java.util.UUID;

/**
 * JSON payload for {@code byz.iam.user}.
 * Types: {@link #TYPE_USER_REGISTERED}, {@link #TYPE_PASSWORD_RESET_REQUESTED},
 * {@link #TYPE_USER_AUTHENTICATED}.
 */
public record UserLifecycleEvent(
        UUID eventId,
        String type,
        Instant occurredAt,
        UUID organizationId,
        UUID tenantId,
        UUID userId,
        String email,
        String displayName,
        /** Present for {@link #TYPE_PASSWORD_RESET_REQUESTED}; null otherwise. */
        String resetUrl,
        /**
         * Auth provider hint for profile sync: {@code password}, {@code microsoft},
         * {@code google}, etc. Null on older events.
         */
        String provider
) {
    public static final String TYPE_USER_REGISTERED = "user.registered";
    public static final String TYPE_PASSWORD_RESET_REQUESTED = "user.password_reset_requested";
    /** Federated or password session established — directory may ensure/fill profile. */
    public static final String TYPE_USER_AUTHENTICATED = "user.authenticated";

    public static final String PROVIDER_PASSWORD = "password";
    public static final String PROVIDER_MICROSOFT = "microsoft";
    public static final String PROVIDER_GOOGLE = "google";

    public static UserLifecycleEvent userRegistered(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName
    ) {
        return new UserLifecycleEvent(
                UUID.randomUUID(),
                TYPE_USER_REGISTERED,
                Instant.now(),
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                null,
                PROVIDER_PASSWORD
        );
    }

    public static UserLifecycleEvent passwordResetRequested(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            String resetUrl
    ) {
        return new UserLifecycleEvent(
                UUID.randomUUID(),
                TYPE_PASSWORD_RESET_REQUESTED,
                Instant.now(),
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                resetUrl,
                null
        );
    }

    /**
     * Provider-agnostic identity hint after a successful login (Microsoft, Google, …).
     * Directory consumers should ensure a profile and fill empty name/email only.
     */
    public static UserLifecycleEvent userAuthenticated(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            String provider
    ) {
        return new UserLifecycleEvent(
                UUID.randomUUID(),
                TYPE_USER_AUTHENTICATED,
                Instant.now(),
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                null,
                provider
        );
    }
}
