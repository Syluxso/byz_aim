package com.nyberg.iam.microsoft;

import com.nyberg.iam.admin.AdminAuth;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/iam/microsoft-config")
@RequiredArgsConstructor
public class MicrosoftProviderConfigController {

    private final MicrosoftProviderConfigService service;

    @GetMapping
    public List<MicrosoftProviderConfigService.MicrosoftProviderConfigResponse> list() {
        AdminAuth.requireJwt();
        return service.listAll();
    }

    @PostMapping
    public MicrosoftProviderConfigService.MicrosoftProviderConfigResponse upsert(
            @Valid @RequestBody UpsertBody body
    ) {
        Jwt jwt = AdminAuth.requireJwt();
        UUID orgId = body.organizationId() != null ? body.organizationId() : AdminAuth.organizationId(jwt);
        return service.upsert(orgId, new MicrosoftProviderConfigService.MicrosoftProviderConfigRequest(body.credentials()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        AdminAuth.requireJwt();
        service.delete(id);
    }

    public record UpsertBody(UUID organizationId, java.util.Map<String, String> credentials) {}
}
