package com.example.securetoken.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Сервис для управления чёрным списком access-токенов в Redis.
 * Используется для немедленного отзыва токенов при выходе из системы.
 */
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;

    // Префикс для ключей в Redis
    private static final String BLACKLIST_PREFIX = "blacklist:";

    // Время, на которое токен добавляется в чёрный список (в миллисекундах)
    // Должно быть равно оставшемуся времени жизни токена
    public void blacklistToken(String jti, long expirationTimeMs) {
        String key = BLACKLIST_PREFIX + jti;

        redisTemplate.opsForValue()
                .set(key, "revoked", expirationTimeMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Проверяет, находится ли токен в чёрном списке
     */
    public boolean isTokenBlacklisted(String jti) {
        String key = BLACKLIST_PREFIX + jti;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}