import React from 'react';
import { CalendarDays } from 'lucide-react';
import type { Game } from '../types';

interface Props {
  games: Game[];
}

export function RegisteredGames({ games }: Props) {
  if (games.length === 0) {
    return null;
  }

  return (
    <div className="bg-gray-800 rounded-lg shadow-xl p-6">
      <div className="flex items-center space-x-3 mb-6">
        <CalendarDays className="w-6 h-6 text-purple-500" />
        <h2 className="text-xl font-bold text-gray-100">Registered Games</h2>
      </div>
      <div className="space-y-4">
        {games.map((game) => (
          <div key={game.id} className="border border-gray-700 rounded-lg p-4">
            <div className="flex justify-between items-center">
              <div className="space-y-2">
                <div className="flex items-center space-x-3">
                  <span className="text-lg font-medium text-gray-100">{game.player1}</span>
                  <span className="text-gray-500">vs</span>
                  <span className="text-lg font-medium text-gray-100">{game.player2}</span>
                </div>
                <div className="text-sm text-gray-400">
                  <span>{game.faction1}</span>
                  <span className="mx-2">vs</span>
                  <span>{game.faction2}</span>
                </div>
                <div className="text-sm text-gray-400">
                  {game.points}pts - {new Date(game.date).toLocaleDateString()}
                </div>
              </div>
              <div className="flex items-center">
                <span className={`px-3 py-1 rounded-full text-sm ${
                  game.status === 'matched' ? 'bg-yellow-500/20 text-yellow-400' : 'bg-green-500/20 text-green-400'
                }`}>
                  {game.status === 'matched' ? 'Scheduled' : 'Completed'}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}