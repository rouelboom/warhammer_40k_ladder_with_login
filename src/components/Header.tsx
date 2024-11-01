import React from 'react';
import { Swords, Trophy, Users } from 'lucide-react';
import { AuthButtons } from './auth/AuthButtons';

export function Header() {
  return (
    <header className="bg-gray-900 border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Swords className="w-8 h-8 text-red-500" />
            <h1 className="text-2xl font-bold text-gray-100">Warhammer 40K Ladder</h1>
          </div>
          <div className="flex items-center space-x-6">
            <nav className="flex space-x-6">
              <a href="#" className="flex items-center space-x-2 text-gray-300 hover:text-white transition">
                <Trophy className="w-5 h-5" />
                <span>Leaderboard</span>
              </a>
              <a href="#" className="flex items-center space-x-2 text-gray-300 hover:text-white transition">
                <Users className="w-5 h-5" />
                <span>Players</span>
              </a>
            </nav>
            <AuthButtons />
          </div>
        </div>
      </div>
    </header>
  );
}