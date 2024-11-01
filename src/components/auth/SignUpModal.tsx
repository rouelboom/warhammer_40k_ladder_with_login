import React, { useState } from 'react';
import { X } from 'lucide-react';
import { userDb, DatabaseError } from '../../db';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function SignUpModal({ isOpen, onClose }: Props) {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    preferredFaction: '',
  });

  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    try {
      const user = userDb.createUser({
        email: formData.email,
        username: formData.username,
        password: formData.password,
        preferredFaction: formData.preferredFaction || undefined,
      });

      console.log('User created successfully:', user);
      onClose();
    } catch (err) {
      if (err instanceof DatabaseError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred');
      }
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>
        
        <h2 className="text-2xl font-bold text-gray-100 mb-6">Create Account</h2>
        
        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500 rounded-md text-red-400">
            {error}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Username
            </label>
            <input
              type="text"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Email
            </label>
            <input
              type="email"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Preferred Faction
            </label>
            <input
              type="text"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.preferredFaction}
              onChange={(e) => setFormData({ ...formData, preferredFaction: e.target.value })}
              placeholder="e.g., Space Marines, Orks, Tyranids"
            />
          </div>
          
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Password
            </label>
            <input
              type="password"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.password}
              onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Confirm Password
            </label>
            <input
              type="password"
              className="w-full bg-gray-700 border border-gray-600 rounded-md px-4 py-2 text-gray-100 focus:outline-none focus:ring-2 focus:ring-red-500"
              value={formData.confirmPassword}
              onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
              required
            />
          </div>

          <div className="flex items-center">
            <input
              type="checkbox"
              id="terms"
              className="rounded bg-gray-700 border-gray-600 text-red-600 focus:ring-red-500"
              required
            />
            <label htmlFor="terms" className="ml-2 text-sm text-gray-300">
              I agree to the <button type="button" className="text-red-500 hover:text-red-400">Terms of Service</button> and{' '}
              <button type="button" className="text-red-500 hover:text-red-400">Privacy Policy</button>
            </label>
          </div>

          <button
            type="submit"
            className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-md transition duration-200"
          >
            Create Account
          </button>
        </form>
      </div>
    </div>
  );
}