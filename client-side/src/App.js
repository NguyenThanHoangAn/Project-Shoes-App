import React, { useState } from 'react';
import Login from './components/Login';
import Register from './components/Register';
import Home from './components/Home';
import 'bootstrap/dist/css/bootstrap.min.css';

function App() {
  const [token, setToken] = useState(null);
  const [showLogin, setShowLogin] = useState(true);

  const handleLoginSuccess = (newToken) => {
    setToken(newToken);
  };

  const handleLogout = async () => {
    try {
      const response = await fetch('http://localhost:5000/logout', {
        method: 'POST',
        credentials: 'include',
      });
      const data = await response.json();
      setToken(null);
      alert(data.message || 'Logged out successfully');
    } catch (error) {
      alert('Error logging out');
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        {!token ? (
          showLogin ? (
            <Login onLoginSuccess={handleLoginSuccess} setShowLogin={setShowLogin} />
          ) : (
            <Register setShowLogin={setShowLogin} />
          )
        ) : (
          <>
            <h1 className="text-4xl font-bold text-center my-6">Shoes App</h1>
            <Home token={token} onLogout={handleLogout} />
          </>
        )}
      </header>
    </div>
  );
}

export default App;