import React, { useState } from 'react';
import { X } from 'lucide-react';
import { userDb, DatabaseError } from '../../db';

interface Props {
  isOpen: boolean;
  onClose: () => void;
}

export function SignInModal({ isOpen, onClose }: Props) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });

  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    try {
      const user = userDb.verifyUser(formData.email, formData.password);
      console.log('User signed in:', user);
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
        
        <h2 className="text-2xl font-bold text-gray-100 mb-6">Sign In</h2>
        
        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500 rounded-md text-red-400">
            {error}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className="space-y-4">
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

          <div className="flex items-center justify-between">
            <label className="flex items-center">
              <input type="checkbox" className="rounded bg-gray-700 border-gray-600 text-red-600 focus:ring-red-500" />
              <span className="ml-2 text-sm text-gray-300">Remember me</span>
            </label>
            <button type="button" className="text-sm text-red-500 hover:text-red-400">
              Forgot password?
            </button>
          </div>

          <button
            type="submit"
            className="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-md transition duration-200"
          >
            Sign In
          </button>
        </form>
      </div>
    </div>
  );
}