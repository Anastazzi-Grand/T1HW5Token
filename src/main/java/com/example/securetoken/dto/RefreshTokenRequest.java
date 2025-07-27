package com.example.securetoken.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO для запроса обновления access-токена
 */
@Data
public class RefreshTokenRequest {
    @NotBlank(message = "Refresh токен обязателен")
    private String refreshToken;
}