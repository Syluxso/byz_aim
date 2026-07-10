package com.nyberg.iam.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class JwtDecoderConfig {

    /**
     * Verify access tokens with the same jjwt + RSA key material used to sign them.
     * Notifications already succeeds via JWKS; IAM previously used Nimbus {@code withPublicKey},
     * which could fail in ways Spring Security surfaces as Tomcat HTML 500s.
     */
    @Bean
    public JwtDecoder jwtDecoder(JwtKeyProvider keyProvider) {
        RSAPublicKey publicKey = (RSAPublicKey) keyProvider.keyPair().getPublic();
        return token -> {
            try {
                var jws = Jwts.parser()
                        .verifyWith(publicKey)
                        .build()
                        .parseSignedClaims(token);

                Claims claims = jws.getPayload();
                Map<String, Object> headers = new HashMap<>(jws.getHeader());
                Map<String, Object> claimMap = toClaimMap(claims);

                Instant issuedAt = claims.getIssuedAt() != null
                        ? claims.getIssuedAt().toInstant()
                        : Instant.now();
                Instant expiresAt = claims.getExpiration() != null
                        ? claims.getExpiration().toInstant()
                        : issuedAt.plusSeconds(3600);

                return new Jwt(token, issuedAt, expiresAt, headers, claimMap);
            } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
                throw new BadJwtException("Invalid IAM access token: " + ex.getMessage(), ex);
            } catch (RuntimeException ex) {
                throw new BadJwtException("Failed to decode IAM access token: " + ex.getMessage(), ex);
            }
        };
    }

    private static Map<String, Object> toClaimMap(Claims claims) {
        Map<String, Object> map = new HashMap<>();
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            Object value = entry.getValue();
            if ("aud".equals(entry.getKey()) && value instanceof Collection<?> aud) {
                List<String> audiences = new ArrayList<>();
                for (Object item : aud) {
                    if (item != null) audiences.add(item.toString());
                }
                map.put("aud", audiences);
            } else if (value instanceof java.util.Date date) {
                map.put(entry.getKey(), date.toInstant());
            } else {
                map.put(entry.getKey(), value);
            }
        }
        return map;
    }
}
