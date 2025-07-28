package com.example.securetoken.service;

import com.example.securetoken.entity.RefreshToken;
import com.example.securetoken.entity.User;
import com.example.securetoken.entity.Role;
import com.example.securetoken.repository.RefreshTokenRepository;
import com.nimbusds.jose.JOSEException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Сервис для управления refresh-токенами.
 * Отвечает за создание, проверку, обновление и отзыв refresh-токенов.
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    // Срок жизни refresh-токена: 7 дней
    @Value("${app.refresh-token-expiration-ms:604800000}")
    private long refreshTokenExpirationMs;

    /**
     * Создаёт и сохраняет новый refresh-токен для пользователя
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        // Генерируем случайный UUID как значение токена
        String tokenValue = UUID.randomUUID().toString();

        // Устанавливаем срок действия
        Instant expiresAt = Instant.now().plusMillis(refreshTokenExpirationMs);

        // Создаём сущность
        RefreshToken refreshToken = RefreshToken.builder()
                .tokenValue(tokenValue)
                .user(user)
                .expiresAt(expiresAt)
                .revoked(false)
                .build();

        // Сохраняем в БД
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Находит refresh-токен по его строковому значению и проверяет его валидность
     */
    @Transactional(readOnly = true)
    public RefreshToken verifyRefreshToken(String tokenValue) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenValue(tokenValue)
                .orElseThrow(() -> new RuntimeException("Refresh токен не найден"));

        if (refreshToken.getRevoked()) {
            throw new RuntimeException("Refresh токен отозван");
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh токен просрочен");
        }

        return refreshToken;
    }

    /**
     * Отзывает конкретный refresh-токен (например, при выходе)
     */
    @Transactional
    public void revokeRefreshToken(String tokenValue) {
        refreshTokenRepository.findByTokenValue(tokenValue)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }

    /**
     * Отзывает все refresh-токены пользователя (например, при выходе со всех устройств)
     */
    @Transactional
    public void revokeAllRefreshTokensForUser(User user) {
        refreshTokenRepository.deleteByUser(user);
    }

    /**
     * Обновляет access-токен, используя валидный refresh-токен
     */
    public String generateNewAccessToken(RefreshToken refreshToken) throws JOSEException {
        User user = refreshToken.getUser();

        // Извлекаем имена ролей из Set<Role>
        List<String> roleNames = user.getRoles().stream()
                .map(Role::getName)  // Получаем имя каждой роли
                .toList();

        // Генерируем новый защищённый токен
        return jwtService.generateSecureToken(user.getUsername(), roleNames);
    }
}