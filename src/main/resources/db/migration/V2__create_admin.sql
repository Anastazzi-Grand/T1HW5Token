-- Создаём пользователя admin, если его ещё нет
INSERT INTO users (username, password_hash, enabled, created_at, updated_at)
VALUES (
    'admin',
    -- Хэш от пароля 'admin' (BCrypt, cost=12)
    -- Сгенерирован на https://bcrypt-generator.com/
    '$2a$12$KqJFz6Xv.6L7WJkKZ3f9gO.EE55u3V8x2J3V8x2J3V8x2J3V8x2J3V8x2',
    true,
    NOW(),
    NOW()
)
ON CONFLICT (username) DO NOTHING;

-- Назначаем роль ADMIN
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id
FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ADMIN'
ON CONFLICT (user_id, role_id) DO NOTHING;