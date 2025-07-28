package com.example.securetoken.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Сервис для безопасной генерации и валидации токенов в формате JWE(JWS(JWT)).
 * Обеспечивает:
 * - Конфиденциальность: шифрование (JWE)
 * - Целостность и подлинность: подпись (JWS)
 * - Защиту от подмены даже участниками обмена
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final RSAKeyService rsaKeyService; // Сервис с ключами

    // Время жизни access-токена: 15 минут
    private static final long EXPIRATION_TIME_MS = 15 * 60 * 1000;

    static {
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Генерирует защищённый токен: JWE(JWS(JWT))
     * Порядок: сначала подписываем (JWS), потом шифруем (JWE)
     *
     * @param subject идентификатор пользователя (например, username)
     * @param roles   список ролей (например, ["USER", "ADMIN"])
     * @return зашифрованная строка токена (JWE)
     * @throws JOSEException если ошибка шифрования/подписи
     */
    public String generateSecureToken(String subject, List<String> roles) throws JOSEException {
        // Создаём claims — полезные данные токена
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusMillis(EXPIRATION_TIME_MS)))
                .jwtID(UUID.randomUUID().toString())
                .claim("roles", roles)
                .build();

        //    Подписываем JWT → получаем JWS (защита от подмены)
        //    Алгоритм: RS256 (RSA + SHA-256)
        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

        // Только сервер может подписать → никто не сможет подделать токен
        RSASSASigner signer = new RSASSASigner(rsaKeyService.getPrivateKey());
        signedJWT.sign(signer);

        //    Шифруем JWS → получаем JWE (защита от компрометации)
        //    Алгоритм шифрования: RSA-OAEP-256 + A128GCM
        JWEHeader jweHeader = new JWEHeader.Builder(
                JWEAlgorithm.RSA_OAEP_256,           // Асимметричное шифрование: публичный ключ шифрует
                EncryptionMethod.A128GCM             // Симметричное шифрование содержимого
        )
                .contentType("JWT")
                .build();

        // Полезная нагрузка — подписанный JWS
        Payload payload = new Payload(signedJWT);

        // Создаём JWE объект
        JWEObject jweObject = new JWEObject(jweHeader, payload);

        RSAEncrypter encrypter = new RSAEncrypter(rsaKeyService.getPublicKey());
        jweObject.encrypt(encrypter);

        return jweObject.serialize();
    }

    /**
     * Валидирует токен: расшифровывает (JWE), проверяет подпись (JWS), возвращает claims.
     * Выбрасывает исключение, если токен:
     * - скомпрометирован
     * - подделан
     * - просрочен
     * - отозван (проверяется отдельно через Redis)
     *
     * @param tokenString строка токена (JWE)
     * @return JWTClaimsSet — расшифрованные данные
     * @throws JOSEException, ParseException, IllegalArgumentException
     */
    public JWTClaimsSet validateTokenAndGetClaims(String tokenString)
            throws JOSEException, ParseException {

        JWEObject jweObject = JWEObject.parse(tokenString);

        RSADecrypter decrypter = new RSADecrypter(rsaKeyService.getPrivateKey());
        jweObject.decrypt(decrypter);

        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

        if (signedJWT == null) {
            throw new IllegalArgumentException("Токен не содержит подписанный JWT");
        }

        // 4. Проверяем подпись JWS с помощью публичного ключа сервера
        JWSVerifier verifier = new RSASSAVerifier(rsaKeyService.getPublicKey());
        if (!signedJWT.verify(verifier)) {
            throw new IllegalArgumentException("Подпись токена недействительна — возможно, он был подделан");
        }

        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        Date now = new Date();
        if (claims.getExpirationTime().before(now)) {
            throw new IllegalArgumentException("Токен просрочен");
        }

        return claims;
    }

    /**
     * Извлекает время истечения токена (exp) из claims
     * (используется при создании refresh-токена)
     */
    public Date getExpirationTimeFromClaims(JWTClaimsSet claims) {
        return claims.getExpirationTime();
    }

    /**
     * Извлекает jti (JWT ID) — уникальный идентификатор токена
     * (нужен для отзыва через Redis)
     */
    public String getJtiFromClaims(JWTClaimsSet claims) {
        return claims.getJWTID();
    }

    /**
     * Извлекает subject (обычно username)
     */
    public String getSubjectFromClaims(JWTClaimsSet claims) {
        return claims.getSubject();
    }

    /**
     * Извлекает список ролей
     */
    public List<String> getRolesFromClaims(JWTClaimsSet claims) {
        Object roles = claims.getClaim("roles");
        if (roles instanceof List) {
            return (List<String>) roles;
        }
        return Collections.emptyList();
    }
}