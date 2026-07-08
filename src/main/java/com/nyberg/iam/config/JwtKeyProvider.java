package com.nyberg.iam.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class JwtKeyProvider {

    @Value("${iam.key-dir}")
    private String keyDir;

    private KeyPair keyPair;

    @PostConstruct
    void init() throws Exception {
        Path dir = Path.of(keyDir);
        Path privateKeyPath = dir.resolve("private.pem");
        Path publicKeyPath = dir.resolve("public.pem");

        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            keyPair = loadKeyPair(privateKeyPath, publicKeyPath);
        } else {
            Files.createDirectories(dir);
            keyPair = generateKeyPair();
            saveKeyPair(keyPair, privateKeyPath, publicKeyPath);
        }
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public String keyId() {
        return "byz-iam-1";
    }

    private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyPair loadKeyPair(Path privatePath, Path publicPath) throws Exception {
        byte[] privateBytes = Base64.getDecoder().decode(Files.readString(privatePath));
        byte[] publicBytes = Base64.getDecoder().decode(Files.readString(publicPath));
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        PublicKey publicKey = factory.generatePublic(new X509EncodedKeySpec(publicBytes));
        return new KeyPair(publicKey, privateKey);
    }

    private static void saveKeyPair(KeyPair pair, Path privatePath, Path publicPath) throws IOException {
        Files.writeString(privatePath, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        Files.writeString(publicPath, Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
    }
}