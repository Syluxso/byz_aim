package com.nyberg.iam.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/** Unverified JWT payload peek for access logging (org / client). */
final class AccessJwtClaims {

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {};
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AccessJwtClaims() {}

    static Claims parse(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return null;
        }
        String token = authorizationHeader;
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = token.substring(7).trim();
        }
        if (token.isEmpty() || token.startsWith("byz_sk_") || token.chars().filter(c -> c == '.').count() < 2) {
            return null;
        }
        int first = token.indexOf('.');
        int second = token.indexOf('.', first + 1);
        if (first < 0 || second < 0) {
            return null;
        }
        try {
            byte[] json = Base64.getUrlDecoder().decode(token.substring(first + 1, second));
            Map<String, Object> claims = MAPPER.readValue(new String(json, StandardCharsets.UTF_8), MAP);
            String organizationId = asString(claims.get("organization_id"));
            String clientId = asString(claims.get("client_id"));
            if (clientId == null) {
                clientId = asString(claims.get("app_id"));
            }
            if (organizationId == null && clientId == null) {
                return null;
            }
            return new Claims(organizationId, clientId);
        } catch (Exception e) {
            return null;
        }
    }

    private static String asString(Object value) {
        if (value == null) {
            return null;
        }
        String s = String.valueOf(value).trim();
        return s.isEmpty() || "null".equals(s) ? null : s;
    }

    record Claims(String organizationId, String clientId) {}
}
