package com.example.securetoken.controller;

import com.example.securetoken.dto.AuthRequest;
import com.example.securetoken.dto.AuthResponse;
import com.example.securetoken.dto.RegisterRequest;
import com.example.securetoken.dto.RefreshTokenRequest;
import com.example.securetoken.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
@Tag(name = "Аутентификация", description = "API для входа, выхода, регистрации и обновления токенов")
public class AuthController {

    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    @Operation(
            summary = "Вход в систему",
            description = "Возвращает access и refresh токены",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный вход",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Неверный логин или пароль")
            }
    )
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) throws ParseException, JOSEException {
        AuthResponse response = authenticationService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @Operation(
            summary = "Регистрация нового пользователя",
            description = "Создаёт нового пользователя и возвращает пару токенов (access + refresh)",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Регистрация успешна",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "400", description = "Имя пользователя уже занято или пароль слишком короткий")
            }
    )
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) throws ParseException, JOSEException {
        AuthResponse response = authenticationService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Обновить access-токен",
            description = "Использует refresh-токен для получения нового access-токена",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Токен обновлён",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Refresh токен недействителен")
            }
    )
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) throws ParseException, JOSEException {
        AuthResponse response = authenticationService.refreshToken(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(
            summary = "Выход из системы",
            description = "Отзывает текущие access и refresh токены",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Выход успешен"),
                    @ApiResponse(responseCode = "401", description = "Токен недействителен")
            }
    )
    public ResponseEntity<?> logout(HttpServletRequest request) {
        authenticationService.logout(request);
        return ResponseEntity.ok().build();
    }
}