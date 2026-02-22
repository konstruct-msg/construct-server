-- Таблица пользователей
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
   );

-- Индекс для быстрого поиска по username
CREATE INDEX idx_users_username ON users(username);

-- Таблица для PreKeys (Signal Protocol)
CREATE TABLE prekeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id INTEGER NOT NULL,
    key_data BYTEA NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, key_id)
);

CREATE INDEX idx_prekeys_user ON prekeys(user_id) WHERE NOT used;
