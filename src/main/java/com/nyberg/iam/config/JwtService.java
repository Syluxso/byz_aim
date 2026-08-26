package com.nyberg.iam.config;

import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class JwtService {

    private final JwtKeyProvider keyProvider;

    @Value("${iam.issuer}")
    private String issuer;

    /**
     * Comma-separated host=issuerURL pairs.
     * When a request arrives whose X-Forwarded-Host matches a key, tokens are minted
     * with that entry's URL as the iss claim instead of the default.
     * Example: IAM_DOMAIN_ISSUERS=auth.cardwallah.com=https://auth.cardwallah.com
     */
    @Value("${IAM_DOMAIN_ISSUERS:}")
    private String domainIssuersRaw;

    private Map<String, String> domainIssuers = new HashMap<>();

    @PostConstruct
    private void initDomainIssuers() {
        if (domainIssuersRaw == null || domainIssuersRaw.isBlank()) return;
        for (String entry : domainIssuersRaw.split(",")) {
            int eq = entry.indexOf('=');
            if (eq > 0) {
                domainIssuers.put(entry.substring(0, eq).trim(), entry.substring(eq + 1).trim());
            }
        }
    }

    /**
     * Returns the issuer to embed in a token, selecting a domain-specific override
     * when the current request was forwarded through a custom hostname.
     */
    private String resolveIssuer() {
        if (domainIssuers.isEmpty()) return issuer;
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes sra) {
            String forwarded = sra.getRequest().getHeader("X-Forwarded-Host");
            if (forwarded != null && !forwarded.isBlank()) {
                String host = forwarded.split(",")[0].trim();
                String override = domainIssuers.get(host);
                if (override != null) return override;
            }
        }
        return issuer;
    }

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
            String email,
            String audience,
            List<String> roles
    ) {
        Instant now = Instant.now();
        var builder = Jwts.builder()
                .header().keyId(keyProvider.keyId()).and()
                .issuer(resolveIssuer())
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
        if (email != null && !email.isBlank()) {
            builder.claim("email", email.trim().toLowerCase(java.util.Locale.ROOT));
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
                .issuer(resolveIssuer())
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
                .issuer(resolveIssuer())
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
                .issuer(resolveIssuer())
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