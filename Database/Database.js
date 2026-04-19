const db = require('better-sqlite3')('users.db');

// Создаем таблицу
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )
`);

module.exports = db; // Экспортируем базу