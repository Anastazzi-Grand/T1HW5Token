package com.example.securetoken.dto;

import lombok.Builder;
import lombok.Data;

/**
 * DTO для ответа при успешном выходе
 */
@Data
@Builder
public class LogoutResponse {
    private String message;
}