package com.nyberg.iam.admin;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppBaseUrlTest {

    @Test
    void blankClears() {
        assertNull(IamAdminService.normalizeAppBaseUrl(null));
        assertNull(IamAdminService.normalizeAppBaseUrl(""));
        assertNull(IamAdminService.normalizeAppBaseUrl("   "));
    }

    @Test
    void trimsAndDropsTrailingSlashes() {
        assertEquals("https://inquiry.example.org", IamAdminService.normalizeAppBaseUrl(" https://inquiry.example.org/ "));
        assertEquals("https://app.example.org/portal", IamAdminService.normalizeAppBaseUrl("https://app.example.org/portal//"));
        assertEquals("http://localhost:3030", IamAdminService.normalizeAppBaseUrl("http://localhost:3030"));
    }

    @Test
    void rejectsNonHttpOrRelative() {
        assertThrows(ResponseStatusException.class, () -> IamAdminService.normalizeAppBaseUrl("inquiry.example.org"));
        assertThrows(ResponseStatusException.class, () -> IamAdminService.normalizeAppBaseUrl("ftp://example.org"));
        assertThrows(ResponseStatusException.class, () -> IamAdminService.normalizeAppBaseUrl("javascript:alert(1)"));
        assertThrows(ResponseStatusException.class, () -> IamAdminService.normalizeAppBaseUrl("https://example.org/?x=1"));
    }
}
