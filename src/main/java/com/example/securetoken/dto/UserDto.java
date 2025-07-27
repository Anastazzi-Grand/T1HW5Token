package com.example.securetoken.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * DTO для возврата информации о пользователе
 */
@Data
@Builder
public class UserDto {
    private String username;
    private List<String> roles;      // Только имена ролей: ["USER", "ADMIN"]
    private Boolean enabled;
    private Long createdAt;          // В UNIX-миллисекундах
}