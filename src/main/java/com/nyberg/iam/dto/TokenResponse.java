package com.nyberg.iam.dto;

public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        String refreshToken
) {
    public static TokenResponse of(String accessToken, long expiresIn, String refreshToken) {
        return new TokenResponse(accessToken, "Bearer", expiresIn, refreshToken);
    }

    public static TokenResponse accessOnly(String accessToken, long expiresIn) {
        return new TokenResponse(accessToken, "Bearer", expiresIn, null);
    }
}