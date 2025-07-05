-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    profile_picture TEXT,
    google_id TEXT UNIQUE,
    created_at TEXT NOT NULL
);

-- Blocked users table
CREATE TABLE IF NOT EXISTS blocked_users (
    user_id TEXT NOT NULL,
    blocked_id TEXT NOT NULL,
    PRIMARY KEY (user_id, blocked_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (blocked_id) REFERENCES users(id)
);

-- Confessions table
CREATE TABLE IF NOT EXISTS confessions (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    is_anonymous INTEGER NOT NULL,
    author_id TEXT,
    author_username TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (author_id) REFERENCES users(id)
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_username TEXT NOT NULL,
    receiver_id TEXT,
    image_base64 TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
); 