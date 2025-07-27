package com.example.securetoken.repository;

import com.example.securetoken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Репозиторий для управления пользователями
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Находит пользователя по имени
     */
    Optional<User> findByUsername(String username);
}