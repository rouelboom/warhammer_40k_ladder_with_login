export interface Player {
  id: string;
  name: string;
  faction: string;
  points: number;
  wins: number;
  losses: number;
}

export interface Game {
  id: string;
  date: string;
  player1: string;
  player2?: string;
  status: 'open' | 'matched' | 'completed';
  points: number;
  winner?: string;
  faction1?: string;
  faction2?: string;
}

export interface User {
  id: string;
  email: string;
  username: string;
  preferredFaction?: string;
  dateJoined: string;
}