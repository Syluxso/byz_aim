package com.nyberg.iam.device;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DeviceServiceHelpersTest {

    @Test
    void summarizeUaDetectsChromeWindows() {
        String label = DeviceService.summarizeUa(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        assertEquals("Chrome on Windows", label);
    }

    @Test
    void fingerprintPrefersClientDeviceId() {
        UUID user = UUID.randomUUID();
        UUID client = UUID.randomUUID();
        String withId = DeviceService.fingerprint(user, client,
                new DeviceHints("phone-1", "Pixel", "UA-A", "1.1.1.1"));
        String withSameIdDifferentUa = DeviceService.fingerprint(user, client,
                new DeviceHints("phone-1", "Pixel", "UA-B", "2.2.2.2"));
        String withoutId = DeviceService.fingerprint(user, client,
                new DeviceHints(null, null, "UA-A", "1.1.1.1"));
        assertEquals(withId, withSameIdDifferentUa);
        assertNotEquals(withId, withoutId);
        assertTrue(withId.matches("[0-9a-f]{64}"));
    }
}
