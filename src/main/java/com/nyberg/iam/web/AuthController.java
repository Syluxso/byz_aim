package com.nyberg.iam.web;

import com.nyberg.iam.device.DeviceHintsFactory;
import com.nyberg.iam.dto.ForgotPasswordRequest;
import com.nyberg.iam.dto.LoginRequest;
import com.nyberg.iam.dto.RegisterRequest;
import com.nyberg.iam.dto.ResetPasswordRequest;
import com.nyberg.iam.dto.SignupRequest;
import com.nyberg.iam.dto.TokenResponse;
import com.nyberg.iam.service.AuthService;
import com.nyberg.iam.service.PasswordResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenResponse register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        return authService.register(request, DeviceHintsFactory.from(http, request.deviceId(), request.deviceName()));
    }

    /** Creates a new tenant under the client's org, then registers the user into it. */
    @PostMapping("/signup")
    @ResponseStatus(HttpStatus.CREATED)
    public TokenResponse signup(@Valid @RequestBody SignupRequest request, HttpServletRequest http) {
        return authService.signup(request, DeviceHintsFactory.from(http, request.deviceId(), request.deviceName()));
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        return authService.login(request, DeviceHintsFactory.from(http, request.deviceId(), request.deviceName()));
    }

    /** Always 204 — does not reveal whether the email exists. */
    @PostMapping("/forgot-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.forgotPassword(request);
    }

    @PostMapping("/reset-password")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request);
    }
}
