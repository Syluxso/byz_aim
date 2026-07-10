package com.nyberg.iam.admin;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/iam")
@RequiredArgsConstructor
public class IamAdminController {

    private final IamAdminService service;

    // ── Orgs ──────────────────────────────────────────────────────────────────

    @GetMapping("/orgs")
    public List<OrgResponse> listOrgs() {
        return service.listOrgs();
    }

    @PostMapping("/orgs")
    @ResponseStatus(HttpStatus.CREATED)
    public OrgResponse createOrg(@Valid @RequestBody CreateOrgRequest req) {
        return service.createOrg(req);
    }

    @DeleteMapping("/orgs/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteOrg(@PathVariable UUID id) {
        service.deleteOrg(id);
    }

    // ── Tenants ───────────────────────────────────────────────────────────────

    @GetMapping("/orgs/{orgId}/tenants")
    public List<TenantResponse> listTenants(@PathVariable UUID orgId) {
        return service.listTenants(orgId);
    }

    @PostMapping("/orgs/{orgId}/tenants")
    @ResponseStatus(HttpStatus.CREATED)
    public TenantResponse createTenant(@PathVariable UUID orgId, @Valid @RequestBody CreateTenantRequest req) {
        return service.createTenant(orgId, req);
    }

    @DeleteMapping("/orgs/{orgId}/tenants/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteTenant(@PathVariable UUID orgId, @PathVariable UUID id) {
        service.deleteTenant(orgId, id);
    }

    // ── Clients ───────────────────────────────────────────────────────────────

    @GetMapping("/orgs/{orgId}/clients")
    public List<ClientResponse> listClients(@PathVariable UUID orgId) {
        return service.listClients(orgId);
    }

    @PostMapping("/orgs/{orgId}/clients")
    @ResponseStatus(HttpStatus.CREATED)
    public ClientCreatedResponse createClient(@PathVariable UUID orgId, @Valid @RequestBody CreateClientRequest req) {
        return service.createClient(orgId, req);
    }

    @PostMapping("/orgs/{orgId}/clients/{id}/rotate-secret")
    public ClientCreatedResponse rotateSecret(@PathVariable UUID orgId, @PathVariable UUID id) {
        return service.rotateSecret(orgId, id);
    }

    @DeleteMapping("/orgs/{orgId}/clients/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deleteClient(@PathVariable UUID orgId, @PathVariable UUID id) {
        service.deleteClient(orgId, id);
    }
}
