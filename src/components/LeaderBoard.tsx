import React from 'react';
import { Trophy, Skull, Sword } from 'lucide-react';
import type { Player } from '../types';

const mockPlayers: Player[] = [
  { id: '1', name: 'Inquisitor Magnus', faction: 'Space Marines', points: 1200, wins: 5, losses: 1 },
  { id: '2', name: 'Warmaster Horus', faction: 'Chaos Space Marines', points: 1100, wins: 4, losses: 2 },
  { id: '3', name: 'Farseer Taldeer', faction: 'Craftworlds', points: 1000, wins: 3, losses: 2 },
];

export function LeaderBoard() {
  return (
    <div className="bg-gray-800 rounded-lg shadow-xl p-6">
      <div className="flex items-center space-x-3 mb-6">
        <Trophy className="w-6 h-6 text-yellow-500" />
        <h2 className="text-xl font-bold text-gray-100">Current Rankings</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="text-left border-b border-gray-700">
              <th className="pb-3 text-gray-400 font-medium">Rank</th>
              <th className="pb-3 text-gray-400 font-medium">Player</th>
              <th className="pb-3 text-gray-400 font-medium">Faction</th>
              <th className="pb-3 text-gray-400 font-medium">Points</th>
              <th className="pb-3 text-gray-400 font-medium">W/L</th>
            </tr>
          </thead>
          <tbody>
            {mockPlayers.map((player, index) => (
              <tr key={player.id} className="border-b border-gray-700 last:border-0">
                <td className="py-4 text-gray-100">{index + 1}</td>
                <td className="py-4">
                  <div className="flex items-center space-x-3">
                    <div className="text-gray-100 font-medium">{player.name}</div>
                  </div>
                </td>
                <td className="py-4 text-gray-300">{player.faction}</td>
                <td className="py-4 text-gray-100">{player.points}</td>
                <td className="py-4">
                  <div className="flex items-center space-x-2">
                    <span className="text-green-500">{player.wins}</span>
                    <span className="text-gray-500">/</span>
                    <span className="text-red-500">{player.losses}</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}