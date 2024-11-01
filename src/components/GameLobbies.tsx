import React, { useState } from 'react';
import { Users, Swords } from 'lucide-react';
import type { Game } from '../types';

interface Props {
  games: Game[];
  onJoinGame: (gameId: string, player2: string, faction2: string) => void;
}

export function GameLobbies({ games, onJoinGame }: Props) {
  const [joinForm, setJoinForm] = useState<{
    gameId: string;
    player2: string;
    faction2: string;
  } | null>(null);

  const handleJoin = (e: React.FormEvent) => {
    e.preventDefault();
    if (joinForm) {
      onJoinGame(joinForm.gameId, joinForm.player2, joinForm.faction2);
      setJoinForm(null);
    }
  };

  if (games.length === 0) {
    return null;
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-xl p-6">
      <div className="flex items-center space-x-3 mb-6">
        <Users className="w-6 h-6 text-blue-500" />
        <h2 className="text-xl font-bold text-gray-100">Open Game Lobbies</h2>
      </div>
      <div className="space-y-4">
        {games.map((game) => (
          <div key={game.id} className="border border-gray-700 rounded-lg p-4">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-lg font-medium text-gray-100">{game.player1}'s Game</h3>
                <p className="text-gray-400">Faction: {game.faction1}</p>
                <p className="text-gray-400">{game.points}pts - {new Date(game.date).toLocaleDateString()}</p>
              </div>
              {!joinForm && (
                <button
                  onClick={() => setJoinForm({ gameId: game.id, player2: '', faction2: '' })}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition"
                >
                  Join Game
                </button>
              )}
            </div>
            {joinForm?.gameId === game.id && (
              <form onSubmit={handleJoin} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Your Name
                  </label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={joinForm.player2}
                    onChange={(e) => setJoinForm({ ...joinForm, player2: e.target.value })}
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Your Faction
                  </label>
                  <input
                    type="text"
                    className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={joinForm.faction2}
                    onChange={(e) => setJoinForm({ ...joinForm, faction2: e.target.value })}
                    required
                    placeholder="e.g., Space Marines, Orks, Tyranids"
                  />
                </div>
                <div className="flex space-x-3">
                  <button
                    type="submit"
                    className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition"
                  >
                    Confirm Join
                  </button>
                  <button
                    type="button"
                    onClick={() => setJoinForm(null)}
                    className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded-md transition"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}