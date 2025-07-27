package com.example.securetoken.dto;

import lombok.Builder;
import lombok.Data;

/**
 * DTO для ответа с access и refresh токенами
 */
@Data
@Builder
public class AuthResponse {
    private String accessToken;   // JWE(JWS(JWT)) — зашифрованный и подписанный
    private String refreshToken;  // UUID или строка refresh-токена
    private Long expiresAt;       // Время истечения access-токена (в ms)
}