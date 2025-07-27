package com.example.securetoken.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * DTO для запроса аутентификации (логин и пароль)
 */
@Data
public class AuthRequest {
    @NotBlank(message = "Имя пользователя обязательно")
    private String username;

    @NotBlank(message = "Пароль обязателен")
    private String password;
}