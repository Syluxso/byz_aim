package com.nyberg.iam.config;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtKeyProvider keyProvider;

    @Value("${iam.issuer}")
    private String issuer;

    @Value("${iam.access-token-ttl-seconds}")
    private long accessTokenTtlSeconds;

    @Value("${iam.subject-token-ttl-seconds:900}")
    private long subjectTokenTtlSeconds;

    public JwtService(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public String createUserToken(
            UUID userId,
            UUID organizationId,
            UUID tenantId,
            String clientId,
            String audience,
            List<String> roles
    ) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(issuer)
                .subject(userId.toString())
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
                .claim("organization_id", organizationId.toString())
                .claim("client_id", clientId)
                .claim("grant_type", "password");
        if (tenantId != null) {
            builder.claim("tenant_id", tenantId.toString());
        }
        if (roles != null && !roles.isEmpty()) {
            builder.claim("roles", roles);
        }
        return builder.signWith(keyProvider.keyPair().getPrivate()).compact();
    }

    public String createServiceToken(String clientId, UUID organizationId, UUID tenantId, String audience) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(issuer)
                .subject(clientId)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
                .claim("organization_id", organizationId.toString())
                .claim("grant_type", "client_credentials");
        if (tenantId != null) {
            builder.claim("tenant_id", tenantId.toString());
        }
        return builder.signWith(keyProvider.keyPair().getPrivate()).compact();
    }

    /** Short-lived token for an external recipient — no IAM user row required. */
    public String createSubjectToken(UUID subject, UUID organizationId, UUID tenantId, String clientId, String audience) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(issuer)
                .subject(subject.toString())
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(subjectTokenTtlSeconds)))
                .claim("organization_id", organizationId.toString())
                .claim("client_id", clientId)
                .claim("grant_type", "subject");
        if (tenantId != null) {
            builder.claim("tenant_id", tenantId.toString());
        }
        return builder.signWith(keyProvider.keyPair().getPrivate()).compact();
    }

    public String createApiKeyToken(
            UUID tokenId,
            UUID organizationId,
            UUID tenantId,
            UUID userId,
            String appId,
            String grantType,
            String audience,
            List<String> roles
    ) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
                .claim("organization_id", organizationId.toString())
                .claim("token_id", tokenId.toString())
                .claim("app_id", appId)
                .claim("grant_type", grantType);
        if (userId != null) {
            builder.subject(userId.toString());
        } else {
            builder.subject(tokenId.toString());
        }
        if (tenantId != null) {
            builder.claim("tenant_id", tenantId.toString());
        }
        if (userId != null) {
            builder.claim("user_id", userId.toString());
        }
        if (roles != null && !roles.isEmpty()) {
            builder.claim("roles", roles);
        }
        return builder.signWith(keyProvider.keyPair().getPrivate()).compact();
    }

    public long accessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public long subjectTokenTtlSeconds() {
        return subjectTokenTtlSeconds;
    }

    public Map<String, Object> jwk() {
        var publicKey = keyProvider.keyPair().getPublic();
        if (!(publicKey instanceof java.security.interfaces.RSAPublicKey rsa)) {
            throw new IllegalStateException("Expected RSA public key");
        }
        return Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", "RS256",
                "kid", keyProvider.keyId(),
                "n", base64Url(rsa.getModulus()),
                "e", base64Url(rsa.getPublicExponent())
        );
    }

    private static String base64Url(java.math.BigInteger value) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(toUnsignedBytes(value));
    }

    private static byte[] toUnsignedBytes(java.math.BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }
}