package com.nyberg.iam.config;

import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.interfaces.RSAPublicKey;

@Configuration
public class JwtAuthenticationFilter {

    @Bean
    public JwtDecoder jwtDecoder(JwtKeyProvider keyProvider) {
        RSAPublicKey publicKey = (RSAPublicKey) keyProvider.keyPair().getPublic();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }
}
