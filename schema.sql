-- 1. Create the primary users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

-- 2. Create the user statistics table
CREATE TABLE IF NOT EXISTS stats (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    api_calls INTEGER DEFAULT 0,
    tokens_used INTEGER DEFAULT 0,
    account_status VARCHAR DEFAULT 'active'
);

-- 3. Create the API keys management table
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    api_key VARCHAR UNIQUE NOT NULL,
    nickname VARCHAR,
    date_created TIMESTAMPTZ DEFAULT NOW()
);
