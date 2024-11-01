import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import { User } from '../types';

const db = new Database('warhammer.db');

export interface CreateUserData {
  email: string;
  username: string;
  password: string;
  preferredFaction?: string;
}

export class DatabaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DatabaseError';
  }
}

export const userDb = {
  createUser: (userData: CreateUserData): User => {
    const { email, username, password, preferredFaction } = userData;

    try {
      // Check if email already exists
      const existingEmail = db.prepare('SELECT email FROM users WHERE email = ?').get(email);
      if (existingEmail) {
        throw new DatabaseError('Email already registered');
      }

      // Check if username already exists
      const existingUsername = db.prepare('SELECT username FROM users WHERE username = ?').get(username);
      if (existingUsername) {
        throw new DatabaseError('Username already taken');
      }

      // Hash password
      const hashedPassword = bcrypt.hashSync(password, 10);

      // Generate unique ID
      const id = Math.random().toString(36).substr(2, 9);
      const dateJoined = new Date().toISOString();

      const stmt = db.prepare(`
        INSERT INTO users (id, email, username, password, preferred_faction, date_joined)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      stmt.run(id, email, username, hashedPassword, preferredFaction || null, dateJoined);

      return {
        id,
        email,
        username,
        preferredFaction,
        dateJoined
      };
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      throw new DatabaseError('Failed to create user');
    }
  },

  verifyUser: (email: string, password: string): User => {
    try {
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
      
      if (!user) {
        throw new DatabaseError('Invalid email or password');
      }

      const validPassword = bcrypt.compareSync(password, user.password);
      if (!validPassword) {
        throw new DatabaseError('Invalid email or password');
      }

      return {
        id: user.id,
        email: user.email,
        username: user.username,
        preferredFaction: user.preferred_faction,
        dateJoined: user.date_joined
      };
    } catch (error) {
      if (error instanceof DatabaseError) {
        throw error;
      }
      throw new DatabaseError('Authentication failed');
    }
  }
};