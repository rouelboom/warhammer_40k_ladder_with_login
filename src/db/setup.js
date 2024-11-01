import Database from 'better-sqlite3';

const db = new Database('warhammer.db');

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    preferred_faction TEXT,
    date_joined TEXT NOT NULL
  )
`);

console.log('Database setup completed successfully!');