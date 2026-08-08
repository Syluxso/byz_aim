package com.nyberg.iam.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * Always allowed for local Ionic/Angular work. Merged into whatever {@code CORS_ORIGINS}
     * is set on the host (host env often omits :8100 and breaks ionic serve).
     */
    private static final List<String> LOCAL_DEV_ORIGINS = List.of(
            "http://localhost:4200",
            "http://localhost:4201",
            "http://localhost:4202",
            "http://localhost:4203",
            "http://localhost:8100",
            "http://localhost:8101",
            "http://localhost:8102",
            "http://127.0.0.1:4200",
            "http://127.0.0.1:4201",
            "http://127.0.0.1:4202",
            "http://127.0.0.1:4203",
            "http://127.0.0.1:8100",
            "http://127.0.0.1:8101",
            "http://127.0.0.1:8102"
    );

    /**
     * Managed product SPA hosts. Always merged so a host {@code CORS_ORIGINS} that only
     * lists Admin cannot break Microsoft ticket exchange from byzantineapp.com.
     */
    private static final List<String> MANAGED_SPA_ORIGINS = List.of(
            "https://byzantineapp.com",
            "https://www.byzantineapp.com",
            "https://app.byzantineapp.com"
    );

    @Value("${CORS_ORIGINS:https://sys.byzantineapp.dev,https://admin.byzantineapp.dev,https://byzantineapp.com,https://www.byzantineapp.com,https://app.byzantineapp.com}")
    private String corsOrigins;

    /**
     * Entra browser redirects hit start/callback with no Bearer token. Ignore only GETs
     * so path-matching quirks cannot force 401. Keep POST /exchange on the security chain
     * (permitAll + CORS) for SPA ticket exchange.
     */
    @Bean
    public WebSecurityCustomizer microsoftLoginSecurityCustomizer() {
        return web -> web.ignoring().requestMatchers(
                AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/api/v1/login/microsoft"),
                AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/api/v1/login/microsoft/callback"));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtKeyProvider keyProvider) throws Exception {
        http
                .csrf(c -> c.disable())
                .cors(c -> c.configurationSource(corsConfigurationSource()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(a -> a
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .requestMatchers("/api/v1/build-info").permitAll()
                        .requestMatchers(
                                AntPathRequestMatcher.antMatcher("/api/v1/register"),
                                AntPathRequestMatcher.antMatcher("/api/v1/signup"),
                                AntPathRequestMatcher.antMatcher("/api/v1/login"),
                                AntPathRequestMatcher.antMatcher("/api/v1/forgot-password"),
                                AntPathRequestMatcher.antMatcher("/api/v1/reset-password"),
                                AntPathRequestMatcher.antMatcher("/api/v1/login/microsoft"),
                                AntPathRequestMatcher.antMatcher("/api/v1/login/microsoft/**"),
                                AntPathRequestMatcher.antMatcher("/api/v1/oauth/token"),
                                AntPathRequestMatcher.antMatcher("/api/v1/oauth/refresh"),
                                AntPathRequestMatcher.antMatcher("/api/v1/api-keys/resolve")
                        ).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, authException) -> {
                            if (response.isCommitted()) return;
                            response.setStatus(HttpStatus.UNAUTHORIZED.value());
                            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                            response.setHeader("WWW-Authenticate", "Bearer");
                            response.getWriter().write(
                                    "{\"title\":\"Unauthorized\",\"status\":401,\"detail\":\"Authentication required\",\"decoder\":\"jjwt\"}");
                        })
                        .accessDeniedHandler((request, response, accessDeniedException) -> {
                            if (response.isCommitted()) return;
                            response.setStatus(HttpStatus.FORBIDDEN.value());
                            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                            response.getWriter().write(
                                    "{\"title\":\"Forbidden\",\"status\":403,\"detail\":\"Access denied\"}");
                        }))
                // jjwt filter only — do not enable oauth2ResourceServer (Nimbus), which caused HTML 500s
                .addFilterBefore(new JjwtAuthenticationFilter(keyProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        Set<String> origins = new LinkedHashSet<>();
        if (corsOrigins != null && !corsOrigins.isBlank()) {
            origins.addAll(Arrays.stream(corsOrigins.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList()));
        }
        origins.addAll(LOCAL_DEV_ORIGINS);
        origins.addAll(MANAGED_SPA_ORIGINS);
        config.setAllowedOrigins(new ArrayList<>(origins));
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
