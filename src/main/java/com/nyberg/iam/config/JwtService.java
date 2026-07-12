package com.nyberg.iam.config;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
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

    public String createUserToken(UUID userId, UUID organizationId, UUID tenantId, String clientId, String audience) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(issuer)
                .subject(userId.toString())
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(accessTokenTtlSeconds)))
                .claim("organization_id", organizationId.toString())
                .claim("tenant_id", tenantId.toString())
                .claim("client_id", clientId)
                .claim("grant_type", "password")
                .signWith(keyProvider.keyPair().getPrivate())
                .compact();
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