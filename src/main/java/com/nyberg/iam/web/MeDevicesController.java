package com.nyberg.iam.web;

import com.nyberg.iam.admin.AdminAuth;
import com.nyberg.iam.device.DeviceResponse;
import com.nyberg.iam.device.DeviceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/me/devices")
@RequiredArgsConstructor
public class MeDevicesController {

    private final DeviceService deviceService;

    @GetMapping
    public List<DeviceResponse> list() {
        Jwt jwt = AdminAuth.requireJwt();
        return deviceService.listForUser(AdminAuth.subjectUserId(jwt));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID id) {
        Jwt jwt = AdminAuth.requireJwt();
        deviceService.revoke(AdminAuth.subjectUserId(jwt), id);
    }
}
