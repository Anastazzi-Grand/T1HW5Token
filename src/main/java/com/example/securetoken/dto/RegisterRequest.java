package com.example.securetoken.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank(message = "Имя пользователя обязательно")
    private String username;

    @NotBlank(message = "Пароль обязателен")
    @Size(min = 6, message = "Пароль должен быть не менее 6 символов")
    private String password;
}