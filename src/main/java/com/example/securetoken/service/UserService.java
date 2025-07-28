package com.example.securetoken.service;

import com.example.securetoken.dto.RegisterRequest;
import com.example.securetoken.dto.UserDto;
import com.example.securetoken.entity.Role;
import com.example.securetoken.entity.User;
import com.example.securetoken.repository.UserRepository;
import com.example.securetoken.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * Сервис для работы с данными пользователя.
 * Возвращает безопасные DTO (без пароля, ID и т.д.).
 * Также отвечает за регистрацию.
 */
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Находит пользователя по имени и возвращает UserDto
     */
    public UserDto findByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден: " + username));

        return UserDto.builder()
                .username(user.getUsername())
                .roles(user.getRoles().stream()
                        .map(Role::getName)
                        .collect(Collectors.toList()))
                .enabled(user.getEnabled())
                .createdAt(user.getCreatedAt().toEpochMilli())
                .build();
    }

    /**
     * Регистрирует нового пользователя
     * Назначает роль USER по умолчанию
     */
    public User register(RegisterRequest request) {
        // Проверяем, что пользователь с таким именем не существует
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Пользователь с именем '" + request.getUsername() + "' уже существует");
        }

        // Находим роль USER
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Роль USER не найдена в БД"));

        // Хэшируем пароль
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // Создаём пользователя
        User user = User.builder()
                .username(request.getUsername())
                .passwordHash(encodedPassword)
                .enabled(true)
                .roles(Set.of(userRole)) // Назначаем роль USER
                .build();

        // Сохраняем в БД
        return userRepository.save(user);
    }

    /**
     * Находит и возвращает сущность User (для внутреннего использования сервисами)
     */
    public User findByUsernameEntity(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Пользователь не найден: " + username));
    }
}