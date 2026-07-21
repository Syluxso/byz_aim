package com.nyberg.iam.events;

/**
 * HTTP access fact for direct IAM traffic (login/refresh/admin APIs).
 * Same shape as gateway {@code gateway.request.completed} so admin-gateway-sse
 * can show them on {@code byz.gateway.access}.
 */
public record IamAccessEvent(
        String eventId,
        String type,
        String occurredAt,
        String requestId,
        String method,
        String path,
        int status,
        long durationMs,
        String clientIp,
        String routeId
) {
    public static final String TYPE = "iam.request.completed";
}
