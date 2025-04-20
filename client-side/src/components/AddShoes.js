import React, { useState, useEffect } from 'react';

function AddShoes({ token, onAddSuccess }) {
  const [newShoe, setNewShoe] = useState({
    id: '',
    name: '',
    price: '',
    type: '',
    color: '',
    attribute: '',
    image: ''
  });
  const [error, setError] = useState('');
  const [showAddForm, setShowAddForm] = useState(true);
  const [successMessage, setSuccessMessage] = useState('');

  // Generate ID automatically when type changes
  useEffect(() => {
    const generateID = async () => {
      const validTypes = ['MEN', 'WOMEN', 'KIDS', 'SPORT', 'SLIPPER', 'SANDAL'];
      if (!validTypes.includes(newShoe.type)) {
        setError('Please select a valid shoe type');
        return;
      }

      try {
        const response = await fetch(`https://project-shoes-app.onrender.com/generate-id?type=${newShoe.type}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
          const text = await response.text();
          console.error('Non-JSON response:', text);
          throw new Error('Server returned non-JSON response');
        }

        const data = await response.json();
        console.log('Response from /generate-id:', data);
        if (response.ok && data.id) {
          setNewShoe((prev) => ({ ...prev, id: data.id }));
          setError('');
        } else {
          setError(data.error || 'Failed to generate ID');
        }
      } catch (err) {
        console.error('Error generating ID:', err.message);
        setError('Error generating ID: ' + err.message);
      }
    };

    if (newShoe.type) {
      generateID();
    }
  }, [newShoe.type, token]);

  const handleAddShoe = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('https://project-shoes-app.onrender.com/shoes', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify(newShoe),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();
      if (response.ok && data.shoe) {
        // Check if onAddSuccess is a function before calling it
        if (typeof onAddSuccess === 'function') {
          onAddSuccess(data.shoe);
        }
        // Show success notification
        setSuccessMessage('Shoe added successfully!');
        // Clear success message after 3 seconds
        setTimeout(() => {
          setSuccessMessage('');
        }, 3000);
        setNewShoe({ 
          id: '', 
          name: '', 
          price: '', 
          type: 'MEN', 
          color: '', 
          attribute: '', 
          image: ''
        });
        setShowAddForm(false);
        setError('');
      } else {
        setError(data.error || 'Error adding shoe');
      }
    } catch (err) {
      console.error('Error adding shoe:', err.message);
      setError('Error adding shoe: ' + err.message);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setNewShoe((prev) => ({ ...prev, [name]: value }));
  };

  return (
    <div className="p-4 relative">
      {/* Success Notification */}
      {successMessage && (
        <div className="fixed top-4 left-1/2 transform -translate-x-1/2 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg z-50 animate-fade-in-out">
          {successMessage}
        </div>
      )}
      {error && <p className="text-red-500 mb-3">{error}</p>}

      {showAddForm && (
        <div className="card shadow-lg p-4 mb-4 bg-white rounded-lg">
          <h3 className="text-lg font-bold mb-3">Add New Shoe</h3>
          <form onSubmit={handleAddShoe}>
            <div className="mb-3">
              <label className="form-label text-gray-600">ID</label>
              <input
                type="text"
                name="id"
                className="form-control"
                value={newShoe.id}
                readOnly
              />
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Name</label>
              <input
                type="text"
                name="name"
                className="form-control"
                value={newShoe.name}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Image URL</label>
              <input
                type="url"
                name="image"
                className="form-control"
                value={newShoe.image}
                onChange={handleInputChange}
                placeholder="link hình ảnh ở đây https://example.com/shoe-image.jpg"
                required
              />
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Price</label>
              <input
                type="number"
                name="price"
                className="form-control"
                value={newShoe.price}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Type</label>
              <select
                name="type"
                className="form-control"
                value={newShoe.type}
                onChange={handleInputChange}
                required
              >
                <option value="" disabled>Select a type</option>
                <option value="MEN">MEN</option>
                <option value="WOMEN">WOMEN</option>
                <option value="KIDS">KIDS</option>
                <option value="SPORT">SPORT</option>
                <option value="SLIPPER">SLIPPER</option>
                <option value="SANDAL">SANDAL</option>
              </select>
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Color</label>
              <input
                type="text"
                name="color"
                className="form-control"
                value={newShoe.color}
                onChange={handleInputChange}
                required
              />
            </div>
            <div className="mb-3">
              <label className="form-label text-gray-600">Attribute</label>
              <select
                name="attribute"
                className="form-control"
                value={newShoe.attribute}
                onChange={handleInputChange}
                required
              >
                <option value="" disabled>Select an attribute</option>
                <option value="Best Seller">Best Seller</option>
                <option value="Trending">Trending</option>
                <option value="New Arrival">New Arrival</option>
                <option value="Classic">Classic</option>
                <option value="Sold Out">Sold Out</option>
                <option value="Limited Edition">Limited Edition</option>
              </select>
            </div>
            <button
              type="submit"
              className="btn btn-primary hover:bg-blue-600 transition duration-300"
            >
              Add Shoe
            </button>
          </form>
        </div>
      )}
    </div>
  );
}

export default AddShoes;