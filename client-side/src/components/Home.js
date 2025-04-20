import React, { useState } from 'react';
import ShoesList from './ShoesList';
import AddShoes from './AddShoes';

function Home({ token, onLogout }) {
  const [view, setView] = useState('list'); // 'list' or 'add'
  const [searchQuery, setSearchQuery] = useState('');

  const handleSearch = (e) => {
    setSearchQuery(e.target.value);
  };

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Hero Section */}
      <div className="relative bg-gradient-to-r from-blue-600 to-indigo-600 text-white py-20">
        <div className="container mx-auto px-4 text-center">
          <h1 className="text-4xl md:text-5xl font-bold mb-4">
            Discover Your Perfect Pair
          </h1>
          <p className="text-lg md:text-xl mb-6">
            Explore our exclusive collection of stylish and comfortable shoes.
          </p>
          <button
            onClick={() => setView('list')}
            className="bg-white text-blue-600 font-semibold py-2 px-6 rounded-full hover:bg-blue-100 transition"
          >
            Shop Now
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-4 py-12">
        {/* Header with Logout */}
        <div className="flex justify-between items-center mb-8">
          <h2 className="text-3xl font-bold text-gray-800">Shoes Collection</h2>
          <button
            onClick={onLogout}
            className="bg-red-500 text-white font-semibold py-2 px-4 rounded-lg hover:bg-red-600 transition"
          >
            Logout
          </button>
        </div>

        {/* View Toggle Buttons */}
        <div className="flex gap-4 mb-8">
          <button
            onClick={() => setView('list')}
            className={`py-2 px-6 rounded-lg font-semibold transition ${
              view === 'list'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            Browse Shoes
          </button>
          <button
            onClick={() => setView('add')}
            className={`py-2 px-6 rounded-lg font-semibold transition ${
              view === 'add'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
            }`}
          >
            Add New Shoe
          </button>
        </div>

        {/* Search Bar (Visible in List View) */}
        {view === 'list' && (
          <div className="mb-8">
            <input
              type="text"
              className="w-full max-w-lg mx-auto block py-3 px-4 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="Search for shoes..."
              value={searchQuery}
              onChange={handleSearch}
            />
          </div>
        )}

        {/* Content Area */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          {view === 'list' && <ShoesList token={token} searchQuery={searchQuery} />}
          {view === 'add' && <AddShoes token={token} />}
        </div>
      </div>
    </div>
  );
}

export default Home;