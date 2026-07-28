package com.nyberg.iam.microsoft;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nyberg.iam.crypto.CredentialEncryptionService;
import com.nyberg.iam.domain.MicrosoftProviderConfig;
import com.nyberg.iam.repository.MicrosoftProviderConfigRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class MicrosoftProviderConfigService {

    private final MicrosoftProviderConfigRepository repo;
    private final CredentialEncryptionService encryption;
    private final ObjectMapper objectMapper;

    @Transactional(readOnly = true)
    public List<MicrosoftProviderConfigResponse> listAll() {
        return repo.findAllByOrderByUpdatedAtDesc().stream().map(this::toResponse).toList();
    }

    @Transactional(readOnly = true)
    public MicrosoftCredentials requireActiveCredentials(UUID organizationId) {
        MicrosoftProviderConfig cfg = repo.findByOrganizationId(organizationId)
                .filter(MicrosoftProviderConfig::isActive)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Microsoft sign-in is not configured for this organization"));
        return decrypt(cfg);
    }

    @Transactional
    public MicrosoftProviderConfigResponse upsert(UUID organizationId, MicrosoftProviderConfigRequest req) {
        Map<String, String> incoming = req.credentials() == null ? Map.of() : new HashMap<>(req.credentials());
        MicrosoftProviderConfig existing = repo.findByOrganizationId(organizationId).orElse(null);

        if (existing != null) {
            Map<String, String> stored = decryptMap(existing.getCredentialsEncrypted());
            if (blank(incoming.get("clientSecret"))) {
                incoming.put("clientSecret", stored.getOrDefault("clientSecret", ""));
            }
            if (blank(incoming.get("clientId"))) {
                incoming.put("clientId", stored.getOrDefault("clientId", ""));
            }
            if (blank(incoming.get("authorityTenant"))) {
                incoming.put("authorityTenant", stored.getOrDefault("authorityTenant", "organizations"));
            }
        }

        if (blank(incoming.get("clientId"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId is required");
        }
        if (existing == null && blank(incoming.get("clientSecret"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientSecret is required");
        }
        if (blank(incoming.get("authorityTenant"))) {
            incoming.put("authorityTenant", "organizations");
        }

        String encrypted = encryptMap(incoming);
        if (existing != null) {
            existing.setCredentialsEncrypted(encrypted);
            existing.setActive(true);
            existing.setProvider("microsoft");
            return toResponse(repo.save(existing));
        }
        MicrosoftProviderConfig created = MicrosoftProviderConfig.builder()
                .organizationId(organizationId)
                .provider("microsoft")
                .credentialsEncrypted(encrypted)
                .active(true)
                .build();
        return toResponse(repo.save(created));
    }

    @Transactional
    public void delete(UUID id) {
        if (!repo.existsById(id)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Microsoft provider config not found");
        }
        repo.deleteById(id);
    }

    private MicrosoftProviderConfigResponse toResponse(MicrosoftProviderConfig cfg) {
        MicrosoftCredentials creds = decrypt(cfg);
        String hint = creds.clientId();
        if (hint != null && hint.length() > 8) {
            hint = "..." + hint.substring(hint.length() - 8);
        }
        return new MicrosoftProviderConfigResponse(
                cfg.getId(),
                cfg.getOrganizationId(),
                cfg.getProvider(),
                hint,
                creds.authorityTenant(),
                cfg.isActive(),
                cfg.getCreatedAt(),
                cfg.getUpdatedAt()
        );
    }

    private MicrosoftCredentials decrypt(MicrosoftProviderConfig cfg) {
        Map<String, String> m = decryptMap(cfg.getCredentialsEncrypted());
        return new MicrosoftCredentials(
                m.getOrDefault("clientId", ""),
                m.getOrDefault("clientSecret", ""),
                m.getOrDefault("authorityTenant", "organizations")
        );
    }

    private Map<String, String> decryptMap(String encrypted) {
        try {
            String json = encryption.decrypt(encrypted);
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            return Map.of();
        }
    }

    private String encryptMap(Map<String, String> credentials) {
        try {
            return encryption.encrypt(objectMapper.writeValueAsString(credentials));
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to encrypt credentials");
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    public record MicrosoftCredentials(String clientId, String clientSecret, String authorityTenant) {
        public String authorityBase() {
            String t = authorityTenant == null || authorityTenant.isBlank() ? "organizations" : authorityTenant.trim();
            return "https://login.microsoftonline.com/" + t;
        }
    }

    public record MicrosoftProviderConfigRequest(Map<String, String> credentials) {}

    public record MicrosoftProviderConfigResponse(
            UUID id,
            UUID organizationId,
            String provider,
            String clientIdHint,
            String authorityTenant,
            boolean active,
            java.time.Instant createdAt,
            java.time.Instant updatedAt
    ) {}
}
