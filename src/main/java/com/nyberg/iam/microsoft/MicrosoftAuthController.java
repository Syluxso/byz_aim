package com.nyberg.iam.microsoft;

import com.nyberg.iam.dto.TokenResponse;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/login/microsoft")
@RequiredArgsConstructor
public class MicrosoftAuthController {

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
            HttpServletResponse response
    ) throws IOException {
        try {
            String redirect = microsoftAuth.handleCallback(code, state, error, errorDescription);
            response.sendRedirect(redirect);
        } catch (ResponseStatusException e) {
            response.sendError(e.getStatusCode().value(), e.getReason());
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
}
