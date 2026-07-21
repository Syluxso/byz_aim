package com.nyberg.iam.web;

import com.nyberg.iam.device.DeviceHintsFactory;
import com.nyberg.iam.dto.RefreshRequest;
import com.nyberg.iam.dto.TokenRequest;
import com.nyberg.iam.dto.TokenResponse;
import com.nyberg.iam.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/oauth")
@RequiredArgsConstructor
public class OAuthController {

    private final AuthService authService;

    @PostMapping("/token")
    public TokenResponse token(@Valid @RequestBody TokenRequest request) {
        return authService.token(request);
    }

    @PostMapping("/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest http) {
        return authService.refresh(request, DeviceHintsFactory.from(http, request.deviceId(), request.deviceName()));
    }
}
