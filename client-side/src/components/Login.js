import React, { useState } from 'react';

function Login({ onLoginSuccess, setShowLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://localhost:5000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();
      if (response.ok && data.token) {
        localStorage.setItem('token', data.token); // Store token
        onLoginSuccess(data.token);
        setMessage('Login successful');
      } else {
        setMessage(data.error || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      setMessage('Error logging in: ' + error.message);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-100 via-white to-blue-100">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-full max-w-md">
        <h2 className="text-3xl font-bold text-gray-800 text-center mb-6">
          Sign In to Shoes App
        </h2>
        <p className="text-gray-500 text-center mb-8">
          Enter your credentials to access your account
        </p>

        <form onSubmit={handleLogin}>
          <div className="mb-5">
            <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
              Username
            </label>
            <input
              type="text"
              id="username"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
              placeholder="Enter your username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
          </div>

          <div className="mb-6">
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              type="password"
              id="password"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 transition"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>

          <button
            type="submit"
            className="w-full bg-green-600 text-white font-semibold py-2 rounded-lg hover:bg-green-700 transition duration-300"
          >
            Sign In
          </button>

          {message && (
            <p
              className={`mt-4 text-center text-sm ${
                message.includes('successful') ? 'text-green-600' : 'text-red-600'
              }`}
            >
              {message}
            </p>
          )}
        </form>

        <p className="text-gray-500 text-center text-sm mt-6">
          Don't have an account?{' '}
          <button
            onClick={() => setShowLogin(false)}
            className="text-blue-600 hover:underline"
          >
            Sign Up
          </button>
        </p>
      </div>
    </div>
  );
}

export default Login;