package com.example.securetoken.config;

import com.example.securetoken.security.JwtAuthenticationFilter;
import com.example.securetoken.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;


/**
 * Основная конфигурация Spring Security.
 * Настраивает:
 * - аутентификацию через пароль
 * - фильтр JWT
 * - правила доступа
 * - stateless сессии
 */
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    /**
     * Конфигурирует цепочку фильтров безопасности
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.cors() // Включаем CORS (если нужно)
                .and()
                .csrf(AbstractHttpConfigurer::disable)

                // Управление сессиями: stateless
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Настройка прав доступа к эндпоинтам
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login").permitAll()        // Разрешить вход
                        .requestMatchers("/refresh").permitAll()      // Разрешить обновление токена
                        .requestMatchers("/logout").authenticated()   // Выход — только для авторизованных
                        .anyRequest().authenticated()                 // Все остальные — только с токеном
                )

                // Добавляем наш JWT-фильтр ДО стандартной аутентификации по логину/паролю
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * AuthenticationManager — нужен для аутентификации при /login
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(customUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    /**
     * PasswordEncoder — для хэширования паролей
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}