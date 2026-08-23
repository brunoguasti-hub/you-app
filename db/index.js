const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'you.sqlite3');
const db = new Database(DB_PATH);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
name TEXT NOT NULL,
email TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
birth_date TEXT NOT NULL,
avatar_json TEXT,
tasks_onboarded INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE TABLE IF NOT EXISTS task_logs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
day TEXT NOT NULL,
task_key TEXT NOT NULL,
done INTEGER NOT NULL DEFAULT 0,
done_at TEXT,
on_time INTEGER,
UNIQUE(user_id, day, task_key)
);
CREATE INDEX IF NOT EXISTS idx_task_logs_user_day ON task_logs(user_id, day);
CREATE TABLE IF NOT EXISTS task_categories (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
name TEXT NOT NULL,
icon TEXT NOT NULL DEFAULT '',
sort_order INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_task_categories_user ON task_categories(user_id);
CREATE TABLE IF NOT EXISTS task_defs (
id INTEGER PRIMARY KEY AUTOINCREMENT,
user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
category_id INTEGER NOT NULL REFERENCES task_categories(id) ON DELETE CASCADE,
title TEXT NOT NULL,
subtitle TEXT NOT NULL DEFAULT '',
time TEXT,
recurrence TEXT NOT NULL DEFAULT 'daily',
action TEXT,
auto INTEGER NOT NULL DEFAULT 0,
sort_order INTEGER NOT NULL DEFAULT 0,
created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_task_defs_user ON task_defs(user_id);
CREATE INDEX IF NOT EXISTS idx_task_defs_category ON task_defs(category_id);
CREATE TABLE IF NOT EXISTS wallet (
user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
balance INTEGER NOT NULL DEFAULT 0,
claimed_through_day TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_items (
user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
item_key TEXT NOT NULL,
acquired_at TEXT NOT NULL DEFAULT (datetime('now')),
PRIMARY KEY (user_id, item_key)
);
CREATE TABLE IF NOT EXISTS user_equipped (
user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
slot TEXT NOT NULL,
item_key TEXT,
PRIMARY KEY (user_id, slot)
);
`);

try { db.exec("ALTER TABLE users ADD COLUMN tasks_onboarded INTEGER NOT NULL DEFAULT 0"); } catch (e) { }
try { db.exec("ALTER TABLE task_logs ADD COLUMN on_time INTEGER"); } catch (e) { }

module.exports = db;
