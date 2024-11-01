import React, { useState } from 'react';
import { CalendarDays, Users, Sword } from 'lucide-react';
import type { Game } from '../types';

interface Props {
  onCreateGame: (game: Omit<Game, 'id'>) => void;
}

export function GameRegistration({ onCreateGame }: Props) {
  const [formData, setFormData] = useState({
    player1: '',
    faction1: '',
    date: '',
    points: 2000,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onCreateGame({
      date: formData.date,
      player1: formData.player1,
      faction1: formData.faction1,
      points: formData.points,
      status: 'open',
    });
    setFormData({
      player1: '',
      faction1: '',
      date: '',
      points: 2000,
    });
  };

  return (
    <div className="bg-gray-800 rounded-lg shadow-xl p-6">
      <div className="flex items-center space-x-3 mb-6">
        <Sword className="w-6 h-6 text-red-500" />
        <h2 className="text-xl font-bold text-gray-100">Create Game Lobby</h2>
      </div>
      <form onSubmit={handleSubmit} className="space-y-6">
        <div className="grid grid-cols-1 gap-6">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Your Name
            </label>
            <input
              type="text"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.player1}
              onChange={(e) => setFormData({ ...formData, player1: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Your Faction
            </label>
            <input
              type="text"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.faction1}
              onChange={(e) => setFormData({ ...formData, faction1: e.target.value })}
              required
              placeholder="e.g., Space Marines, Orks, Tyranids"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Date
            </label>
            <input
              type="date"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.date}
              onChange={(e) => setFormData({ ...formData, date: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Points Level
            </label>
            <select
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.points}
              onChange={(e) => setFormData({ ...formData, points: Number(e.target.value) })}
            >
              <option value="500">500 pts - Combat Patrol</option>
              <option value="1000">1000 pts - Incursion</option>
              <option value="2000">2000 pts - Strike Force</option>
              <option value="3000">3000 pts - Onslaught</option>
            </select>
          </div>
        </div>
        <button
          type="submit"
          className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded-md transition duration-200"
        >
          Create Game Lobby
        </button>
      </form>
    </div>
  );
}