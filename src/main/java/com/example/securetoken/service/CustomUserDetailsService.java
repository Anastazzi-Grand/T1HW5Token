package com.example.securetoken.service;

import com.example.securetoken.entity.User;
import com.example.securetoken.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Кастомная реализация UserDetailsService для загрузки пользователя из БД
 * с его ролями (через JOIN).
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Метод, который вызывает Spring Security при аутентификации.
     * Находит пользователя по имени и преобразует его в UserDetails.
     *
     * @param username имя пользователя (из запроса)
     * @return UserDetails — стандартный объект Spring Security
     * @throws UsernameNotFoundException если пользователь не найден
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "Пользователь с именем " + username + " не найден"));

        if (!user.getEnabled()) {
            throw new UsernameNotFoundException("Пользователь отключён");
        }

        // Преобразуем роли в объекты Spring Security: "USER" → "ROLE_USER"
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                .collect(Collectors.toList());

        // Возвращаем UserDetails — обёртку над пользователем
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPasswordHash())
                .disabled(!user.getEnabled())
                .authorities(authorities)
                .build();
    }
}