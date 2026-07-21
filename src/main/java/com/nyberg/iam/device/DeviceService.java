package com.nyberg.iam.device;

import com.nyberg.iam.domain.Client;
import com.nyberg.iam.domain.Device;
import com.nyberg.iam.domain.User;
import com.nyberg.iam.repository.DeviceRepository;
import com.nyberg.iam.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DeviceService {

    private final DeviceRepository deviceRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    /**
     * Upsert device for this user+client from request hints. Returns the row to attach to the refresh token.
     */
    @Transactional
    public Device touch(User user, Client client, DeviceHints hints) {
        DeviceHints h = hints != null ? hints : DeviceHints.empty();
        String fingerprint = fingerprint(user.getId(), client.getId(), h);
        Instant now = Instant.now();

        Device device = deviceRepository
                .findByUserIdAndClientIdAndFingerprint(user.getId(), client.getId(), fingerprint)
                .orElse(null);

        if (device == null) {
            device = Device.builder()
                    .userId(user.getId())
                    .clientId(client.getId())
                    .fingerprint(fingerprint)
                    .label(label(h))
                    .userAgent(truncate(h.userAgent(), 2000))
                    .ipAddress(truncate(h.ipAddress(), 64))
                    .clientDeviceId(truncate(h.clientDeviceId(), 128))
                    .firstSeenAt(now)
                    .lastSeenAt(now)
                    .revoked(false)
                    .build();
        } else {
            device.setLastSeenAt(now);
            device.setRevoked(false);
            if (h.userAgent() != null) {
                device.setUserAgent(truncate(h.userAgent(), 2000));
            }
            if (h.ipAddress() != null) {
                device.setIpAddress(truncate(h.ipAddress(), 64));
            }
            if (h.deviceName() != null) {
                device.setLabel(truncate(h.deviceName(), 255));
            }
            if (h.clientDeviceId() != null) {
                device.setClientDeviceId(truncate(h.clientDeviceId(), 128));
            }
        }
        return deviceRepository.save(device);
    }

    @Transactional(readOnly = true)
    public List<DeviceResponse> listForUser(UUID userId) {
        return deviceRepository.findByUserIdAndRevokedFalseOrderByLastSeenAtDesc(userId).stream()
                .map(DeviceResponse::from)
                .toList();
    }

    /** Revoke device and all its refresh tokens. */
    @Transactional
    public void revoke(UUID userId, UUID deviceId) {
        Device device = deviceRepository.findByIdAndUserId(deviceId, userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));
        device.setRevoked(true);
        device.setLastSeenAt(Instant.now());
        deviceRepository.save(device);
        refreshTokenRepository.revokeAllByDeviceId(deviceId);
    }

    static String fingerprint(UUID userId, UUID clientId, DeviceHints h) {
        String material;
        if (h.clientDeviceId() != null) {
            material = userId + "|" + clientId + "|id|" + h.clientDeviceId();
        } else {
            String ua = h.userAgent() != null ? h.userAgent() : "";
            material = userId + "|" + clientId + "|ua|" + ua;
        }
        return sha256(material);
    }

    private static String label(DeviceHints h) {
        if (h.deviceName() != null) {
            return truncate(h.deviceName(), 255);
        }
        String ua = h.userAgent();
        if (ua == null || ua.isBlank()) {
            return "Unknown device";
        }
        return truncate(summarizeUa(ua), 255);
    }

    /** Lightweight UA → short label (not a full parser). */
    static String summarizeUa(String ua) {
        String lower = ua.toLowerCase();
        String browser = "Browser";
        if (lower.contains("edg/")) browser = "Edge";
        else if (lower.contains("chrome/") && !lower.contains("edg/")) browser = "Chrome";
        else if (lower.contains("firefox/")) browser = "Firefox";
        else if (lower.contains("safari/") && !lower.contains("chrome/")) browser = "Safari";

        String os = "Unknown OS";
        if (lower.contains("android")) os = "Android";
        else if (lower.contains("iphone") || lower.contains("ipad")) os = "iOS";
        else if (lower.contains("mac os")) os = "macOS";
        else if (lower.contains("windows")) os = "Windows";
        else if (lower.contains("linux")) os = "Linux";

        return browser + " on " + os;
    }

    private static String sha256(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String truncate(String v, int max) {
        if (v == null) return null;
        return v.length() <= max ? v : v.substring(0, max);
    }
}
