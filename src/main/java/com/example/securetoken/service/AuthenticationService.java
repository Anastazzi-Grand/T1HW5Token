package com.example.securetoken.service;

import com.example.securetoken.dto.AuthRequest;
import com.example.securetoken.dto.AuthResponse;
import com.example.securetoken.entity.RefreshToken;
import com.example.securetoken.entity.User;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;


/**
 * Основной сервис аутентификации.
 * Обрабатывает вход, обновление токенов и выход.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final CustomUserDetailsService customUserDetailsService;

    private final com.example.securetoken.repository.UserRepository userRepository;

    /**
     * Аутентифицирует пользователя и возвращает пару токенов
     */
    @Transactional
    public AuthResponse authenticate(AuthRequest request) throws JOSEException, ParseException {
        // 1. Проверяем логин/пароль
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // 2. Получаем UserDetails (с ролями)
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 3. Генерируем access-токен (JWE+JWS)
        String accessToken = jwtService.generateSecureToken(
                userDetails.getUsername(),
                userDetails.getAuthorities().stream()
                        .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                        .toList()
        );

        // 4. Создаём и сохраняем refresh-токен
        User user = userRepository.findByUsername(userDetails.getUsername())
                .orElseThrow();
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        // 5. Возвращаем ответ
        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getTokenValue())
                .expiresAt(jwtService.getExpirationTimeFromClaims(
                        jwtService.validateTokenAndGetClaims(accessToken)
                ).getTime())
                .build();
    }

    /**
     * Обновляет access-токен с помощью refresh-токена
     */
    @Transactional
    public AuthResponse refreshToken(String refreshTokenValue) throws JOSEException, ParseException {
        // 1. Проверяем валидность refresh-токена
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenValue);

        // 2. Генерируем новый access-токен
        String newAccessToken = refreshTokenService.generateNewAccessToken(refreshToken);

        // 3. Возвращаем новый токен
        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshTokenValue) // Можно обновить refresh-токен, но пока оставим тот же
                .expiresAt(jwtService.getExpirationTimeFromClaims(
                        jwtService.validateTokenAndGetClaims(newAccessToken)
                ).getTime())
                .build();
    }

    /**
     * Выходит из системы: отзывает access и refresh токены
     */
    @Transactional
    public void logout(HttpServletRequest request) {
        // 1. Извлекаем токен из заголовка
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        String token = authHeader.substring(7);

        try {
            // 2. Валидируем и получаем claims
            var claims = jwtService.validateTokenAndGetClaims(token);
            String jti = jwtService.getJtiFromClaims(claims);
            String username = jwtService.getSubjectFromClaims(claims);

            // 3. Добавляем access-токен в чёрный список (Redis)
            long timeLeft = claims.getExpirationTime().getTime() - System.currentTimeMillis();
            tokenBlacklistService.blacklistToken(jti, timeLeft);

            // 4. Находим пользователя и отзываем все его refresh-токены
            User user = userRepository.findByUsername(username)
                    .orElseThrow();
            refreshTokenService.revokeAllRefreshTokensForUser(user);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка при выходе", e);
        }
    }
}