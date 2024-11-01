import React, { useState } from 'react';
import { SignInModal } from './SignInModal';
import { SignUpModal } from './SignUpModal';

export function AuthButtons() {
  const [showSignIn, setShowSignIn] = useState(false);
  const [showSignUp, setShowSignUp] = useState(false);

  return (
    <>
      <div className="flex items-center space-x-3">
        <button
          onClick={() => setShowSignIn(true)}
          className="px-4 py-2 text-gray-300 hover:text-white transition"
        >
          Sign In
        </button>
        <button
          onClick={() => setShowSignUp(true)}
          className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md transition"
        >
          Sign Up
        </button>
      </div>

      <SignInModal isOpen={showSignIn} onClose={() => setShowSignIn(false)} />
      <SignUpModal isOpen={showSignUp} onClose={() => setShowSignUp(false)} />
    </>
  );
}