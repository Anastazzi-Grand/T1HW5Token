package com.example.securetoken.repository;

import com.example.securetoken.entity.RefreshToken;
import com.example.securetoken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Репозиторий для управления refresh-токенами
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Находит refresh-токен по его строковому значению
     */
    Optional<RefreshToken> findByTokenValue(String tokenValue);

    /**
     * Удаляет все refresh-токены, связанные с пользователем
     */
    void deleteByUser(User user);
}