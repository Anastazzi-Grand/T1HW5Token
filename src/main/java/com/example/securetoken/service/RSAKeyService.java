package com.example.securetoken.service;

import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Сервис для генерации и хранения RSA-ключей
 */
@Service
public class RSAKeyService {

    private KeyPair keyPair;

    public RSAKeyService() {
        generateKeyPair();
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            this.keyPair = generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Ошибка при генерации RSA-ключей", e);
        }
    }

    public RSAPublicKey getPublicKey() {
        return (RSAPublicKey) keyPair.getPublic();
    }

    public RSAPrivateKey getPrivateKey() {
        return (RSAPrivateKey) keyPair.getPrivate();
    }
}