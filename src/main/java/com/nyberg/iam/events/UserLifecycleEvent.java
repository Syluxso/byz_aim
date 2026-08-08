package com.nyberg.iam.events;

import java.time.Instant;
import java.util.UUID;

/**
 * JSON payload for {@code byz.iam.user}.
 * Types: {@link #TYPE_USER_REGISTERED}, {@link #TYPE_PASSWORD_RESET_REQUESTED},
 * {@link #TYPE_USER_AUTHENTICATED}, {@link #TYPE_DEVICE_REGISTERED},
 * {@link #TYPE_DEVICE_REVOKED}.
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
        String provider,
        /** Present for device events; null otherwise. */
        UUID deviceId,
        String deviceLabel,
        String deviceIp
) {
    public static final String TYPE_USER_REGISTERED = "user.registered";
    public static final String TYPE_PASSWORD_RESET_REQUESTED = "user.password_reset_requested";
    /** Federated or password session established — directory may ensure/fill profile. */
    public static final String TYPE_USER_AUTHENTICATED = "user.authenticated";
    /** New device fingerprint first seen for this user (login/register/refresh). */
    public static final String TYPE_DEVICE_REGISTERED = "device.registered";
    /** Device revoked by the user (sessions for that device invalidated). */
    public static final String TYPE_DEVICE_REVOKED = "device.revoked";

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
        return userRegistered(organizationId, tenantId, userId, email, displayName, PROVIDER_PASSWORD);
    }

    public static UserLifecycleEvent userRegistered(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            String provider
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
                provider != null ? provider : PROVIDER_PASSWORD,
                null,
                null,
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
                resetUrl,
                null,
                null,
                null,
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
                provider,
                null,
                null,
                null
        );
    }

    /** New device first seen for this user — notifications may alert in-app + email. */
    public static UserLifecycleEvent deviceRegistered(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            UUID deviceId,
            String deviceLabel,
            String deviceIp
    ) {
        return deviceEvent(
                TYPE_DEVICE_REGISTERED,
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                deviceId,
                deviceLabel,
                deviceIp
        );
    }

    /** Device revoked — notifications may confirm in-app + email. */
    public static UserLifecycleEvent deviceRevoked(
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            UUID deviceId,
            String deviceLabel,
            String deviceIp
    ) {
        return deviceEvent(
                TYPE_DEVICE_REVOKED,
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                deviceId,
                deviceLabel,
                deviceIp
        );
    }

    private static UserLifecycleEvent deviceEvent(
            String type,
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String email,
            String displayName,
            UUID deviceId,
            String deviceLabel,
            String deviceIp
    ) {
        return new UserLifecycleEvent(
                UUID.randomUUID(),
                type,
                Instant.now(),
                organizationId,
                tenantId,
                userId,
                email,
                displayName,
                null,
                null,
                deviceId,
                deviceLabel,
                deviceIp
        );
    }
}
