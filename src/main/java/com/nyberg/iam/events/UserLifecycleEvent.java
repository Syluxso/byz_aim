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
        String displayName
) {
    public static final String TYPE_USER_REGISTERED = "user.registered";

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
                displayName
        );
    }
}
