package com.nyberg.iam.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Validates Bearer tokens with the same jjwt + RSA keys used to sign them.
 * Avoids Spring's oauth2 Resource Server / Nimbus path, which was returning
 * Tomcat HTML 500 responses for some token failures.
 */
public class JjwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtKeyProvider keyProvider;

    public JjwtAuthenticationFilter(JwtKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = header.substring(7).trim();
        if (token.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            RSAPublicKey publicKey = (RSAPublicKey) keyProvider.keyPair().getPublic();
            var jws = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token);

            Claims claims = jws.getPayload();
            Map<String, Object> headers = new HashMap<>();
            jws.getHeader().forEach((k, v) -> headers.put(k, v));
            Map<String, Object> claimMap = toClaimMap(claims);

            Instant issuedAt = claims.getIssuedAt() != null
                    ? claims.getIssuedAt().toInstant()
                    : Instant.now();
            Instant expiresAt = claims.getExpiration() != null
                    ? claims.getExpiration().toInstant()
                    : issuedAt.plusSeconds(3600);

            Jwt jwt = new Jwt(token, issuedAt, expiresAt, headers, claimMap);
            var auth = new JwtAuthenticationToken(jwt, AuthorityUtils.NO_AUTHORITIES, jwt.getSubject());
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
            SecurityContextHolder.clearContext();
            writeUnauthorized(response, "Invalid or expired access token");
        } catch (RuntimeException ex) {
            SecurityContextHolder.clearContext();
            writeUnauthorized(response, "Token validation failed");
        }
    }

    private static void writeUnauthorized(HttpServletResponse response, String detail) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setHeader("WWW-Authenticate", "Bearer");
        String body = "{\"title\":\"Unauthorized\",\"status\":401,\"detail\":\"%s\",\"decoder\":\"jjwt\"}"
                .formatted(detail.replace("\\", "\\\\").replace("\"", "\\\""));
        response.getWriter().write(body);
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
                map.put(entry.getKey(), date.toInstant().getEpochSecond());
            } else {
                map.put(entry.getKey(), value);
            }
        }
        return map;
    }
}
