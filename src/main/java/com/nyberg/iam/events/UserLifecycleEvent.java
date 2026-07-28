package com.nyberg.iam.events;

import java.time.Instant;
import java.util.UUID;

/**
 * JSON payload for {@code byz.iam.user}. See events-service {@code docs/EVENTS.md}.
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
        String resetUrl
) {
    public static final String TYPE_USER_REGISTERED = "user.registered";
    public static final String TYPE_PASSWORD_RESET_REQUESTED = "user.password_reset_requested";

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
                null
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
                resetUrl
        );
    }
}
