package com.nyberg.iam.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${CORS_ORIGINS:http://localhost:4200,http://localhost:4201}")
    private String corsOrigins;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        AuthenticationEntryPoint entryPoint = jsonAuthEntryPoint();
        AccessDeniedHandler accessDenied = jsonAccessDeniedHandler();

        http
                .csrf(c -> c.disable())
                .cors(c -> c.configurationSource(corsConfigurationSource()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/**").permitAll()
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .requestMatchers("/api/v1/register", "/api/v1/login",
                                "/api/v1/oauth/token", "/api/v1/oauth/refresh").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDenied))
                .addFilterBefore(
                        new AuthenticationServiceExceptionFilter(entryPoint),
                        BearerTokenAuthenticationFilter.class);
        return http.build();
    }

    /**
     * Prefer JSON over Tomcat's HTML ErrorReportValve for API clients.
     * AuthenticationServiceException / invalid bearer tokens otherwise surface as HTTP 500 HTML.
     */
    private static AuthenticationEntryPoint jsonAuthEntryPoint() {
        BearerTokenAuthenticationEntryPoint bearer = new BearerTokenAuthenticationEntryPoint();
        return (request, response, authException) -> {
            if (response.isCommitted()) {
                return;
            }
            String accept = request.getHeader("Accept");
            boolean wantsHtml = accept != null && accept.contains("text/html") && !accept.contains("application/json");
            if (wantsHtml) {
                bearer.commence(request, response, authException);
                return;
            }
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            String detail = authException instanceof OAuth2AuthenticationException oauth
                    ? String.valueOf(oauth.getError().getDescription())
                    : (authException.getMessage() != null ? authException.getMessage() : "Unauthorized");
            if (authException instanceof InvalidBearerTokenException || detail.toLowerCase().contains("jwt")) {
                detail = "Invalid or expired access token";
            }
            response.getWriter().write("""
                    {"title":"Unauthorized","status":401,"detail":"%s"}
                    """.formatted(escapeJson(detail)).trim());
        };
    }

    private static AccessDeniedHandler jsonAccessDeniedHandler() {
        BearerTokenAccessDeniedHandler bearer = new BearerTokenAccessDeniedHandler();
        return (request, response, accessDeniedException) -> {
            if (response.isCommitted()) {
                return;
            }
            String accept = request.getHeader("Accept");
            boolean wantsHtml = accept != null && accept.contains("text/html") && !accept.contains("application/json");
            if (wantsHtml) {
                bearer.handle(request, response, accessDeniedException);
                return;
            }
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.getWriter().write("""
                    {"title":"Forbidden","status":403,"detail":"Access denied"}
                    """.trim());
        };
    }

    private static String escapeJson(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", " ")
                .replace("\r", " ");
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(corsOrigins.split(",")));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
