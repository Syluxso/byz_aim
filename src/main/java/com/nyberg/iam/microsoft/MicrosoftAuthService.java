package com.nyberg.iam.microsoft;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nyberg.iam.crypto.CredentialEncryptionService;
import com.nyberg.iam.device.DeviceHints;
import com.nyberg.iam.domain.*;
import com.nyberg.iam.dto.TokenResponse;
import com.nyberg.iam.repository.*;
import com.nyberg.iam.events.UserAuthenticatedApplicationEvent;
import com.nyberg.iam.events.UserLifecycleEvent;
import com.nyberg.iam.events.UserRegisteredApplicationEvent;
import com.nyberg.iam.service.AuthService;
import com.nyberg.iam.service.RoleService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MicrosoftAuthService {

    private static final String PROVIDER = "microsoft";

    private final MicrosoftProviderConfigService providerConfigs;
    private final MicrosoftAuthStateRepository authStates;
    private final MicrosoftLoginTicketRepository loginTickets;
    private final ExternalIdentityRepository externalIdentities;
    private final MicrosoftTenantLinkRepository tenantLinks;
    private final TenantRepository tenants;
    private final UserRepository users;
    private final AuthService authService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final CredentialEncryptionService encryption;
    private final ObjectMapper objectMapper;
    private final ApplicationEventPublisher applicationEventPublisher;

    @Value("${iam.public-base-url:https://iam.byzantineapp.dev}")
    private String iamPublicBaseUrl;

    private final SecureRandom secureRandom = new SecureRandom();
    private final RestClient http = RestClient.create();

    /** Start OIDC authorization-code + PKCE; returns Entra authorize URL. */
    @Transactional
    public String startLogin(String clientId, String redirectUri) {
        Client client = authService.requireActiveClient(clientId);
        var creds = providerConfigs.requireActiveCredentials(client.getOrganizationId());
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "redirectUri is required");
        }

        String state = randomUrlSafe(32);
        String nonce = randomUrlSafe(24);
        String verifier = randomUrlSafe(64);
        String challenge = pkceChallenge(verifier);

        authStates.save(MicrosoftAuthState.builder()
                .state(state)
                .organizationId(client.getOrganizationId())
                .clientId(clientId)
                .redirectUri(redirectUri.trim())
                .codeVerifier(verifier)
                .nonce(nonce)
                .expiresAt(Instant.now().plusSeconds(600))
                .build());

        String callback = iamPublicBaseUrl.replaceAll("/$", "") + "/api/v1/login/microsoft/callback";
        // build(true) assumes already-encoded values and rejects spaces in scope.
        // build().encode() percent-encodes "openid profile email offline_access" correctly.
        return UriComponentsBuilder
                .fromUriString(creds.authorityBase() + "/oauth2/v2.0/authorize")
                .queryParam("client_id", creds.clientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", callback)
                .queryParam("response_mode", "query")
                .queryParam("scope", "openid profile email offline_access")
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("prompt", "select_account")
                .build()
                .encode()
                .toUriString();
    }

    /**
     * Entra callback: exchange code, JIT/link user, mint Byz tokens into a one-time ticket,
     * redirect SPA to redirectUri?microsoft_login={ticketId}.
     */
    @Transactional
    public String handleCallback(String code, String state, String error, String errorDescription) {
        if (error != null && !error.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Microsoft login failed: " + error + (errorDescription != null ? " — " + errorDescription : ""));
        }
        if (code == null || code.isBlank() || state == null || state.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "code and state are required");
        }

        MicrosoftAuthState authState = authStates.findById(state)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired state"));
        if (authState.getExpiresAt().isBefore(Instant.now())) {
            authStates.delete(authState);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Login state expired — try again");
        }

        // Capture SPA return, then consume state (one-time) before calling Microsoft.
        String spaReturn = authState.getRedirectUri();
        String codeVerifier = authState.getCodeVerifier();
        String nonce = authState.getNonce();
        String clientId = authState.getClientId();
        UUID organizationId = authState.getOrganizationId();
        authStates.delete(authState);

        try {
            Client client = authService.requireActiveClient(clientId);
            var creds = providerConfigs.requireActiveCredentials(organizationId);
            String callback = iamPublicBaseUrl.replaceAll("/$", "") + "/api/v1/login/microsoft/callback";

            JsonNode tokenJson = exchangeCode(creds, code, callback, codeVerifier);
            if (tokenJson != null && tokenJson.hasNonNull("error")) {
                String desc = text(tokenJson, "error_description");
                if (desc == null) desc = text(tokenJson, "error");
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                        "Microsoft token error: " + (desc != null ? desc : tokenJson.toString()));
            }
            String idToken = text(tokenJson, "id_token");
            if (idToken == null) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Microsoft did not return an id_token");
            }

            Claims claims = validateIdToken(idToken, creds, nonce);
            String oid = claim(claims, "oid");
            if (oid == null) oid = claims.getSubject();
            String email = firstNonBlank(claim(claims, "preferred_username"), claim(claims, "email"), claim(claims, "upn"));
            String name = firstNonBlank(claim(claims, "name"), email != null ? email.split("@")[0] : "Microsoft User");
            String entraTid = claim(claims, "tid");

            if (email == null || email.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Microsoft account did not provide an email claim");
            }
            email = email.trim().toLowerCase(Locale.ROOT);

            ResolvedUser resolved = resolveOrCreateUser(organizationId, email, name, oid, entraTid, claims, tokenJson);
            User user = resolved.user();

            TokenResponse tokens = authService.issueSession(user, client, DeviceHints.empty());
            UUID ticketId = storeTicket(tokens);

            // New account (password or federated) → notifications welcome in-app + email.
            if (resolved.created()) {
                applicationEventPublisher.publishEvent(new UserRegisteredApplicationEvent(
                        this,
                        UserLifecycleEvent.userRegistered(
                                user.getOrganizationId(),
                                user.getTenantId(),
                                user.getId(),
                                email,
                                name,
                                UserLifecycleEvent.PROVIDER_MICROSOFT
                        )
                ));
            }

            // Every successful login → profile sync + product rules (managed-api, etc.).
            applicationEventPublisher.publishEvent(new UserAuthenticatedApplicationEvent(
                    this,
                    UserLifecycleEvent.userAuthenticated(
                            user.getOrganizationId(),
                            user.getTenantId(),
                            user.getId(),
                            email,
                            name,
                            UserLifecycleEvent.PROVIDER_MICROSOFT
                    )
            ));

            return UriComponentsBuilder
                    .fromUriString(spaReturn)
                    .queryParam("microsoft_login", ticketId.toString())
                    .build()
                    .encode()
                    .toUriString();
        } catch (ResponseStatusException e) {
            throw new MicrosoftCallbackException(spaReturn, e);
        } catch (RuntimeException e) {
            throw new MicrosoftCallbackException(spaReturn,
                    new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                            "Microsoft callback failed: " + e.getMessage(), e));
        }
    }

    private record ResolvedUser(User user, boolean created) {}

    /** Wraps a callback failure with the original SPA redirect URI (for browser bounce-back). */
    public static final class MicrosoftCallbackException extends RuntimeException {
        private final String spaRedirectUri;
        private final ResponseStatusException causeStatus;

        public MicrosoftCallbackException(String spaRedirectUri, ResponseStatusException causeStatus) {
            super(causeStatus.getReason(), causeStatus);
            this.spaRedirectUri = spaRedirectUri;
            this.causeStatus = causeStatus;
        }

        public String spaRedirectUri() {
            return spaRedirectUri;
        }

        public ResponseStatusException causeStatus() {
            return causeStatus;
        }
    }

    @Transactional
    public TokenResponse exchangeTicket(UUID ticketId) {
        MicrosoftLoginTicket ticket = loginTickets.findById(ticketId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Microsoft login ticket"));
        if (ticket.getConsumedAt() != null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Microsoft login ticket already used");
        }
        if (ticket.getExpiresAt().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Microsoft login ticket expired");
        }
        ticket.setConsumedAt(Instant.now());
        loginTickets.save(ticket);
        try {
            String json = encryption.decrypt(ticket.getPayloadEncrypted());
            JsonNode node = objectMapper.readTree(json);
            return TokenResponse.of(
                    node.path("accessToken").asText(),
                    node.path("expiresIn").asLong(3600),
                    node.path("refreshToken").asText(null)
            );
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to read login ticket");
        }
    }

    private ResolvedUser resolveOrCreateUser(
            UUID organizationId,
            String email,
            String name,
            String oid,
            String entraTid,
            Claims claims,
            JsonNode tokenJson
    ) {
        UUID byzTenantId = ensureByzTenantForEntra(organizationId, entraTid, claims);

        var linked = externalIdentities.findByProviderAndSubjectAndOrganizationId(PROVIDER, oid, organizationId);
        if (linked.isPresent()) {
            User user = users.findById(linked.get().getUserId())
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "Linked user missing"));
            updateExternal(linked.get(), email, entraTid, claims, tokenJson);
            if (byzTenantId != null && user.getTenantId() == null) {
                user.setTenantId(byzTenantId);
                users.save(user);
            }
            return new ResolvedUser(user, false);
        }

        User user = users.findByOrganizationIdAndEmailIgnoreCase(organizationId, email).orElse(null);
        boolean created = false;
        if (user == null) {
            user = User.builder()
                    .organizationId(organizationId)
                    .tenantId(byzTenantId)
                    .email(email)
                    .name(name)
                    .passwordHash(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .active(true)
                    .build();
            users.save(user);
            roleService.assignDefaultsForNewUser(user);
            created = true;
        } else if (byzTenantId != null && user.getTenantId() == null) {
            user.setTenantId(byzTenantId);
            users.save(user);
        }

        ExternalIdentity identity = ExternalIdentity.builder()
                .provider(PROVIDER)
                .subject(oid)
                .userId(user.getId())
                .organizationId(organizationId)
                .email(email)
                .entraTenantId(entraTid)
                .build();
        updateExternal(identity, email, entraTid, claims, tokenJson);
        externalIdentities.save(identity);
        return new ResolvedUser(user, created);
    }

    private UUID ensureByzTenantForEntra(UUID organizationId, String entraTid, Claims claims) {
        if (entraTid == null || entraTid.isBlank()) {
            return null;
        }
        return tenantLinks.findByOrganizationIdAndEntraTenantId(organizationId, entraTid)
                .map(MicrosoftTenantLink::getTenantId)
                .orElseGet(() -> {
                    String display = firstNonBlank(
                            claim(claims, "xms_tdbr"),
                            "Microsoft " + entraTid.substring(0, Math.min(8, entraTid.length())));
                    String slug = "ms-" + entraTid.toLowerCase(Locale.ROOT).replace("-", "");
                    if (slug.length() > 60) slug = slug.substring(0, 60);
                    Tenant tenant = Tenant.builder()
                            .organizationId(organizationId)
                            .name(display)
                            .slug(uniqueSlug(organizationId, slug))
                            .active(true)
                            .build();
                    tenants.save(tenant);
                    tenantLinks.save(MicrosoftTenantLink.builder()
                            .organizationId(organizationId)
                            .entraTenantId(entraTid)
                            .tenantId(tenant.getId())
                            .displayName(display)
                            .build());
                    return tenant.getId();
                });
    }

    private String uniqueSlug(UUID organizationId, String base) {
        String candidate = base;
        int i = 2;
        while (tenants.findByOrganizationIdAndSlugIgnoreCase(organizationId, candidate).isPresent()) {
            candidate = base + "-" + i++;
            if (i > 100) {
                candidate = base + "-" + UUID.randomUUID().toString().substring(0, 8);
                break;
            }
        }
        return candidate;
    }

    private void updateExternal(
            ExternalIdentity identity,
            String email,
            String entraTid,
            Claims claims,
            JsonNode tokenJson
    ) {
        identity.setEmail(email);
        identity.setEntraTenantId(entraTid);
        try {
            identity.setClaimsJson(objectMapper.writeValueAsString(claims));
        } catch (Exception ignored) {
            identity.setClaimsJson(null);
        }
        try {
            Map<String, String> tokens = Map.of(
                    "accessToken", text(tokenJson, "access_token") == null ? "" : text(tokenJson, "access_token"),
                    "refreshToken", text(tokenJson, "refresh_token") == null ? "" : text(tokenJson, "refresh_token")
            );
            identity.setTokensEncrypted(encryption.encrypt(objectMapper.writeValueAsString(tokens)));
        } catch (Exception ignored) {
            // optional
        }
        identity.setUpdatedAt(Instant.now());
    }

    private UUID storeTicket(TokenResponse tokens) {
        try {
            String json = objectMapper.writeValueAsString(Map.of(
                    "accessToken", tokens.accessToken(),
                    "refreshToken", tokens.refreshToken() == null ? "" : tokens.refreshToken(),
                    "expiresIn", tokens.expiresIn()
            ));
            MicrosoftLoginTicket ticket = MicrosoftLoginTicket.builder()
                    .payloadEncrypted(encryption.encrypt(json))
                    .expiresAt(Instant.now().plusSeconds(120))
                    .build();
            return loginTickets.save(ticket).getId();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to create login ticket");
        }
    }

    private JsonNode exchangeCode(
            MicrosoftProviderConfigService.MicrosoftCredentials creds,
            String code,
            String redirectUri,
            String codeVerifier
    ) {
        String body = "client_id=" + url(creds.clientId())
                + "&client_secret=" + url(creds.clientSecret())
                + "&grant_type=authorization_code"
                + "&code=" + url(code)
                + "&redirect_uri=" + url(redirectUri)
                + "&code_verifier=" + url(codeVerifier);
        try {
            return http.post()
                    .uri(creds.authorityBase() + "/oauth2/v2.0/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(body)
                    .exchange((req, res) -> {
                        String respBody = new String(res.getBody().readAllBytes(), StandardCharsets.UTF_8);
                        if (res.getStatusCode().isError()) {
                            String snippet = respBody.length() > 400 ? respBody.substring(0, 400) : respBody;
                            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                                    "Microsoft token exchange failed: HTTP "
                                            + res.getStatusCode().value() + " " + snippet);
                        }
                        return objectMapper.readTree(respBody);
                    });
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Microsoft token exchange failed: " + e.getMessage());
        }
    }

    private Claims validateIdToken(
            String idToken,
            MicrosoftProviderConfigService.MicrosoftCredentials creds,
            String expectedNonce
    ) {
        try {
            String[] parts = idToken.split("\\.");
            if (parts.length < 2) {
                throw new IllegalArgumentException("Malformed id_token");
            }
            JsonNode header = objectMapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
            String kid = header.path("kid").asText(null);
            RSAPublicKey key = microsoftPublicKey(creds.authorityBase(), kid);

            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .requireAudience(creds.clientId())
                    .build()
                    .parseSignedClaims(idToken)
                    .getPayload();

            String nonce = claim(claims, "nonce");
            if (expectedNonce != null && !expectedNonce.equals(nonce)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid nonce");
            }
            String iss = claims.getIssuer();
            if (iss == null || !(iss.startsWith("https://login.microsoftonline.com/") && iss.endsWith("/v2.0"))) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid issuer");
            }
            return claims;
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Microsoft id_token: " + e.getMessage());
        }
    }

    private RSAPublicKey microsoftPublicKey(String authorityBase, String kid) throws Exception {
        String jwks = http.get()
                .uri(authorityBase + "/discovery/v2.0/keys")
                .retrieve()
                .body(String.class);
        JsonNode keys = objectMapper.readTree(jwks).path("keys");
        for (JsonNode key : keys) {
            if (kid != null && !kid.equals(key.path("kid").asText())) continue;
            byte[] n = Base64.getUrlDecoder().decode(key.path("n").asText());
            byte[] e = Base64.getUrlDecoder().decode(key.path("e").asText());
            RSAPublicKeySpec spec = new RSAPublicKeySpec(new BigInteger(1, n), new BigInteger(1, e));
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
        }
        throw new IllegalStateException("Microsoft JWKS key not found for kid=" + kid);
    }

    private static String pkceChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String randomUrlSafe(int bytes) {
        byte[] buf = new byte[bytes];
        secureRandom.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static String url(String v) {
        return URLEncoder.encode(v, StandardCharsets.UTF_8);
    }

    private static String claim(Claims claims, String key) {
        Object v = claims.get(key);
        return v == null ? null : v.toString();
    }

    private static String text(JsonNode node, String field) {
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) return null;
        String s = v.asText();
        return s == null || s.isBlank() ? null : s;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank()) return v.trim();
        }
        return null;
    }
}
