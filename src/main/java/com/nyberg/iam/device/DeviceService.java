package com.nyberg.iam.device;

import com.nyberg.iam.domain.Client;
import com.nyberg.iam.domain.Device;
import com.nyberg.iam.domain.User;
import com.nyberg.iam.events.DeviceRegisteredApplicationEvent;
import com.nyberg.iam.events.DeviceRevokedApplicationEvent;
import com.nyberg.iam.events.UserLifecycleEvent;
import com.nyberg.iam.repository.DeviceRepository;
import com.nyberg.iam.repository.RefreshTokenRepository;
import com.nyberg.iam.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
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
    private final UserRepository userRepository;
    private final ApplicationEventPublisher applicationEventPublisher;

    /**
     * Upsert <em>active</em> device for this user+client from request hints.
     * <p>
     * Revoked devices are never revived. After revoke, the next login with the same
     * browser fingerprint inserts a <strong>new</strong> row (soft-delete + partial unique
     * index on active fingerprints only) and emits {@code device.registered}.
     */
    @Transactional
    public Device touch(User user, Client client, DeviceHints hints) {
        DeviceHints h = hints != null ? hints : DeviceHints.empty();
        String fingerprint = fingerprint(user.getId(), client.getId(), h);
        Instant now = Instant.now();

        Device device = deviceRepository
                .findByUserIdAndClientIdAndFingerprintAndRevokedFalse(
                        user.getId(), client.getId(), fingerprint)
                .orElse(null);

        boolean isNew = device == null;
        if (isNew) {
            // Drop legacy "Unknown device" rows from Microsoft logins that used empty UA hints
            // (same client, empty fingerprint) so users don't see two devices for one browser.
            retireLegacyEmptyFingerprint(user, client, fingerprint);

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
        device = deviceRepository.save(device);
        if (isNew) {
            publishDeviceRegistered(user, device);
        }
        return device;
    }

    /**
     * Soft-delete active empty-UA devices for this user+client when a real-UA device is created.
     * No Kafka event (cleanup of a known historical bug, not a user-initiated revoke).
     */
    private void retireLegacyEmptyFingerprint(User user, Client client, String newFingerprint) {
        String emptyFp = fingerprint(user.getId(), client.getId(), DeviceHints.empty());
        if (emptyFp.equals(newFingerprint)) {
            return;
        }
        deviceRepository
                .findByUserIdAndClientIdAndFingerprintAndRevokedFalse(
                        user.getId(), client.getId(), emptyFp)
                .ifPresent(ghost -> {
                    ghost.setRevoked(true);
                    ghost.setLastSeenAt(Instant.now());
                    deviceRepository.save(ghost);
                    refreshTokenRepository.revokeAllByDeviceId(ghost.getId());
                });
    }

    private void publishDeviceRegistered(User user, Device device) {
        applicationEventPublisher.publishEvent(new DeviceRegisteredApplicationEvent(
                this,
                UserLifecycleEvent.deviceRegistered(
                        user.getOrganizationId(),
                        user.getTenantId(),
                        user.getId(),
                        user.getEmail(),
                        user.getName(),
                        device.getId(),
                        device.getLabel(),
                        device.getIpAddress()
                )
        ));
    }

    @Transactional(readOnly = true)
    public List<DeviceResponse> listForUser(UUID userId) {
        return deviceRepository.findByUserIdAndRevokedFalseOrderByLastSeenAtDesc(userId).stream()
                .map(DeviceResponse::from)
                .toList();
    }

    /**
     * Soft-delete: mark revoked, kill refresh tokens, publish {@code device.revoked}.
     * The row stays for audit; it will never be returned by list or re-activated by {@link #touch}.
     */
    @Transactional
    public void revoke(UUID userId, UUID deviceId) {
        Device device = deviceRepository.findByIdAndUserId(deviceId, userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Device not found"));
        if (device.isRevoked()) {
            return;
        }
        device.setRevoked(true);
        device.setLastSeenAt(Instant.now());
        deviceRepository.save(device);
        refreshTokenRepository.revokeAllByDeviceId(deviceId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        publishDeviceRevoked(user, device);
    }

    private void publishDeviceRevoked(User user, Device device) {
        applicationEventPublisher.publishEvent(new DeviceRevokedApplicationEvent(
                this,
                UserLifecycleEvent.deviceRevoked(
                        user.getOrganizationId(),
                        user.getTenantId(),
                        user.getId(),
                        user.getEmail(),
                        user.getName(),
                        device.getId(),
                        device.getLabel(),
                        device.getIpAddress()
                )
        ));
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
