package com.nyberg.iam.config;

import com.nyberg.iam.events.IamAccessEvent;
import com.nyberg.iam.events.IamAccessKafkaPublisher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.UUID;

/**
 * Emits access facts to Kafka after each request (best-effort).
 * Skips actuator and CORS preflight. Paths are prefixed with {@code /iam}
 * so they match gateway-style routes in Admin live requests.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class AccessLogFilter extends OncePerRequestFilter {

    public static final String REQUEST_ID_HEADER = "X-Request-Id";

    private final ObjectProvider<IamAccessKafkaPublisher> publisher;

    public AccessLogFilter(ObjectProvider<IamAccessKafkaPublisher> publisher) {
        this.publisher = publisher;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path != null && path.startsWith("/actuator")) {
            return true;
        }
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        long startedNanos = System.nanoTime();
        String requestId = request.getHeader(REQUEST_ID_HEADER);
        if (requestId == null || requestId.isBlank()) {
            requestId = UUID.randomUUID().toString();
            response.setHeader(REQUEST_ID_HEADER, requestId);
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            emit(request, response, requestId, startedNanos);
        }
    }

    private void emit(
            HttpServletRequest request,
            HttpServletResponse response,
            String requestId,
            long startedNanos) {
        IamAccessKafkaPublisher kafka = publisher.getIfAvailable();
        if (kafka == null) {
            return;
        }

        String uri = request.getRequestURI();
        if (uri == null) {
            uri = "/";
        }
        // Align with gateway StripPrefix paths: /iam/api/v1/login
        String path = uri.startsWith("/iam/") || uri.equals("/iam") ? uri : "/iam" + uri;

        long durationMs = (System.nanoTime() - startedNanos) / 1_000_000L;
        String clientIp = request.getRemoteAddr();

        kafka.publishAsync(new IamAccessEvent(
                UUID.randomUUID().toString(),
                IamAccessEvent.TYPE,
                Instant.now().toString(),
                requestId,
                request.getMethod(),
                path,
                response.getStatus(),
                durationMs,
                clientIp,
                "iam-direct"
        ));
    }
}
