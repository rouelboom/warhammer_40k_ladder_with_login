import React, { useState } from 'react';
import { Header } from './components/Header';
import { LeaderBoard } from './components/LeaderBoard';
import { GameRegistration } from './components/GameRegistration';
import { GameLobbies } from './components/GameLobbies';
import { RegisteredGames } from './components/RegisteredGames';
import type { Game } from './types';

function App() {
  const [games, setGames] = useState<Game[]>([]);

  const handleCreateGame = (game: Omit<Game, 'id'>) => {
    const newGame: Game = {
      ...game,
      id: Math.random().toString(36).substr(2, 9),
      status: 'open',
    };
    setGames([...games, newGame]);
  };

  const handleJoinGame = (gameId: string, player2: string, faction2: string) => {
    setGames(games.map(game => 
      game.id === gameId 
        ? { ...game, player2, faction2, status: 'matched' }
        : game
    ));
  };

  return (
    <div className="min-h-screen bg-gray-900">
      <Header />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <LeaderBoard />
          <GameRegistration onCreateGame={handleCreateGame} />
        </div>
        <GameLobbies games={games.filter(g => g.status === 'open')} onJoinGame={handleJoinGame} />
        <RegisteredGames games={games.filter(g => g.status !== 'open')} />
      </main>
    </div>
  );
}

export default App;