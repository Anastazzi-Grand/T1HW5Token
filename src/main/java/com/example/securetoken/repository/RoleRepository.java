package com.example.securetoken.repository;

import com.example.securetoken.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Репозиторий для управления ролями
 */
@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    /**
     * Находит роль по имени (например, "USER", "ADMIN")
     */
    Optional<Role> findByName(String name);
}