package com.nyberg.iam.device;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicIpsTest {

    @Test
    void publicV4() {
        assertEquals("8.8.8.8", PublicIps.normalizeOrNull("8.8.8.8"));
        assertEquals("73.1.2.3", PublicIps.normalizeOrNull(" 73.1.2.3 "));
    }

    @Test
    void privateAndSpecialRejected() {
        assertNull(PublicIps.normalizeOrNull(null));
        assertNull(PublicIps.normalizeOrNull(""));
        assertNull(PublicIps.normalizeOrNull("127.0.0.1"));
        assertNull(PublicIps.normalizeOrNull("10.0.0.1"));
        assertNull(PublicIps.normalizeOrNull("192.168.1.10"));
        assertNull(PublicIps.normalizeOrNull("172.16.0.1"));
        assertNull(PublicIps.normalizeOrNull("169.254.1.1"));
        assertNull(PublicIps.normalizeOrNull("100.64.0.1"));
        assertNull(PublicIps.normalizeOrNull("100.127.255.254"));
        assertNull(PublicIps.normalizeOrNull("0.0.0.0"));
        assertNull(PublicIps.normalizeOrNull("not-an-ip"));
        assertNull(PublicIps.normalizeOrNull("example.com"));
    }

    @Test
    void ipv6UlaAndLoopbackRejected() {
        assertNull(PublicIps.normalizeOrNull("::1"));
        assertNull(PublicIps.normalizeOrNull("fc00::1"));
        assertNull(PublicIps.normalizeOrNull("fd12:3456:789a::1"));
        assertNull(PublicIps.normalizeOrNull("fe80::1"));
    }

    @Test
    void ipv4MappedUnwraps() {
        assertEquals("8.8.8.8", PublicIps.normalizeOrNull("::ffff:8.8.8.8"));
        assertNull(PublicIps.normalizeOrNull("::ffff:192.168.0.1"));
    }

    @Test
    void samePublicIp() {
        assertTrue(PublicIps.samePublicIp("8.8.8.8", "8.8.8.8"));
        assertTrue(PublicIps.samePublicIp("::ffff:8.8.8.8", "8.8.8.8"));
        assertFalse(PublicIps.samePublicIp("8.8.8.8", "1.1.1.1"));
        assertTrue(PublicIps.samePublicIp("192.168.0.1", "10.0.0.1"));
        assertFalse(PublicIps.samePublicIp("192.168.0.1", "8.8.8.8"));
    }
}
