package com.nyberg.iam.device;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Builds {@link DeviceHints} from optional body fields + HTTP request metadata.
 */
public final class DeviceHintsFactory {

    private DeviceHintsFactory() {}

    public static DeviceHints from(HttpServletRequest request, String clientDeviceId, String deviceName) {
        return new DeviceHints(
                blankToNull(clientDeviceId),
                blankToNull(deviceName),
                blankToNull(request.getHeader("User-Agent")),
                clientIp(request)
        );
    }

    public static DeviceHints from(HttpServletRequest request) {
        return from(request, null, null);
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }
}
