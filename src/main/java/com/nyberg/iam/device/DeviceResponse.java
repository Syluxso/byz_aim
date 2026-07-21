package com.nyberg.iam.device;

import com.nyberg.iam.domain.Device;

import java.time.Instant;
import java.util.UUID;

public record DeviceResponse(
        UUID id,
        String label,
        String userAgent,
        String ipAddress,
        Instant firstSeenAt,
        Instant lastSeenAt,
        boolean newDevice
) {
    public static DeviceResponse from(Device d) {
        boolean isNew = d.getFirstSeenAt() != null
                && d.getLastSeenAt() != null
                && !d.getLastSeenAt().isAfter(d.getFirstSeenAt().plusSeconds(2));
        return new DeviceResponse(
                d.getId(),
                d.getLabel(),
                d.getUserAgent(),
                d.getIpAddress(),
                d.getFirstSeenAt(),
                d.getLastSeenAt(),
                isNew
        );
    }
}
