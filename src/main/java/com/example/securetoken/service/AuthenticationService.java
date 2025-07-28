package com.example.securetoken.service;

import com.example.securetoken.dto.AuthRequest;
import com.example.securetoken.dto.AuthResponse;
import com.example.securetoken.dto.RegisterRequest;
import com.example.securetoken.entity.RefreshToken;
import com.example.securetoken.entity.User;
import com.nimbusds.jose.JOSEException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final UserService userService;

    @Transactional
    public AuthResponse authenticate(AuthRequest request) throws ParseException, JOSEException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        // Получаем User из БД (не из UserDetails)
        User user = userService.findByUsernameEntity(request.getUsername());

        // Генерируем access-токен
        String accessToken = jwtService.generateSecureToken(
                user.getUsername(),
                user.getRoles().stream()
                        .map(role -> role.getName())
                        .toList()
        );

        // Создаём refresh-токен
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getTokenValue())
                .expiresAt(jwtService.getExpirationTimeFromClaims(
                        jwtService.validateTokenAndGetClaims(accessToken)
                ).getTime())
                .build();
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) throws ParseException, JOSEException {
        // 1. Регистрируем пользователя
        User user = userService.register(request);

        // 2. Автоматически входим
        return authenticate(new AuthRequest(user.getUsername(), request.getPassword()));
    }

    @Transactional
    public AuthResponse refreshToken(String refreshTokenValue) throws ParseException, JOSEException {
        RefreshToken refreshToken = refreshTokenService.verifyRefreshToken(refreshTokenValue);
        String newAccessToken = refreshTokenService.generateNewAccessToken(refreshToken);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshTokenValue)
                .expiresAt(jwtService.getExpirationTimeFromClaims(
                        jwtService.validateTokenAndGetClaims(newAccessToken)
                ).getTime())
                .build();
    }

    @Transactional
    public void logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return;

        String token = authHeader.substring(7);
        try {
            var claims = jwtService.validateTokenAndGetClaims(token);
            String jti = jwtService.getJtiFromClaims(claims);
            String username = jwtService.getSubjectFromClaims(claims);

            long timeLeft = claims.getExpirationTime().getTime() - System.currentTimeMillis();
            tokenBlacklistService.blacklistToken(jti, timeLeft);

            User user = userService.findByUsernameEntity(username);
            refreshTokenService.revokeAllRefreshTokensForUser(user);

        } catch (Exception e) {
            throw new RuntimeException("Ошибка при выходе", e);
        }
    }
}