package com.nyberg.iam.device;

/**
 * Optional client hints plus request-derived UA/IP for device cataloging.
 *
 * @param clientDeviceId stable id from the app (optional)
 * @param deviceName     friendly label from the app (optional)
 * @param userAgent      User-Agent header (may be null)
 * @param ipAddress      client IP (may be null)
 */
public record DeviceHints(
        String clientDeviceId,
        String deviceName,
        String userAgent,
        String ipAddress
) {
    public static DeviceHints empty() {
        return new DeviceHints(null, null, null, null);
    }
}
