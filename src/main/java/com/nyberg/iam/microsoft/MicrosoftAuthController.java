package com.nyberg.iam.microsoft;

import com.nyberg.iam.device.DeviceHintsFactory;
import com.nyberg.iam.dto.TokenResponse;
import com.nyberg.iam.microsoft.MicrosoftAuthService.MicrosoftCallbackException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/login/microsoft")
@RequiredArgsConstructor
public class MicrosoftAuthController {

    private static final Logger log = LoggerFactory.getLogger(MicrosoftAuthController.class);

    private final MicrosoftAuthService microsoftAuth;

    /**
     * Browser redirect start. Query: clientId, redirectUri (SPA URL that will receive microsoft_login ticket).
     */
    @GetMapping
    public void start(
            @RequestParam String clientId,
            @RequestParam String redirectUri,
            HttpServletResponse response
    ) throws IOException {
        String authorizeUrl = microsoftAuth.startLogin(clientId, redirectUri);
        response.sendRedirect(authorizeUrl);
    }

    @GetMapping("/callback")
    public void callback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(required = false, name = "error_description") String errorDescription,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        try {
            String redirect = microsoftAuth.handleCallback(
                    code, state, error, errorDescription, DeviceHintsFactory.from(request));
            response.sendRedirect(redirect);
        } catch (MicrosoftCallbackException e) {
            log.warn("Microsoft callback failed: {}", e.causeStatus().getReason());
            String spa = e.spaRedirectUri();
            if (spa != null && !spa.isBlank()) {
                String target = UriComponentsBuilder
                        .fromUriString(spa)
                        .queryParam("microsoft_error", e.causeStatus().getReason() != null
                                ? e.causeStatus().getReason()
                                : "Microsoft sign-in failed")
                        .build()
                        .encode()
                        .toUriString();
                response.sendRedirect(target);
                return;
            }
            writeProblem(response, e.causeStatus());
        } catch (ResponseStatusException e) {
            log.warn("Microsoft callback rejected: {}", e.getReason());
            writeProblem(response, e);
        } catch (Exception e) {
            log.error("Microsoft callback unexpected error", e);
            writeProblem(response, new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Microsoft callback failed: " + e.getMessage()));
        }
    }

    /** SPA exchanges one-time ticket for Byz access/refresh tokens. */
    @PostMapping("/exchange")
    public TokenResponse exchange(@RequestBody Map<String, String> body) {
        String raw = body.get("ticket");
        if (raw == null || raw.isBlank()) {
            raw = body.get("microsoft_login");
        }
        if (raw == null || raw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "ticket is required");
        }
        return microsoftAuth.exchangeTicket(UUID.fromString(raw.trim()));
    }

    private static void writeProblem(HttpServletResponse response, ResponseStatusException e) throws IOException {
        if (response.isCommitted()) {
            return;
        }
        int status = e.getStatusCode().value();
        String detail = e.getReason() != null ? e.getReason() : "Microsoft sign-in failed";
        response.setStatus(status);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType("application/problem+json");
        String safe = detail.replace("\\", "\\\\").replace("\"", "\\\"");
        response.getWriter().write(
                "{\"title\":\"Microsoft sign-in failed\",\"status\":" + status
                        + ",\"detail\":\"" + safe + "\"}");
    }
}
