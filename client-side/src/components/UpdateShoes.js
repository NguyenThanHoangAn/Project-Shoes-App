import React, { useState, useEffect } from 'react';

function UpdateShoes({ token, shoe, onUpdateSuccess, onCancel }) {
  const [editShoe, setEditShoe] = useState({
    id: shoe.id,
    name: shoe.name,
    image: shoe.image || '',
    price: shoe.price,
    type: shoe.type,
    color: shoe.color || '',
    attribute: shoe.attribute || '',
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Generate new ID if type changes
  useEffect(() => {
    const generateID = async () => {
      if (editShoe.type === shoe.type) {
        setEditShoe((prev) => ({ ...prev, id: shoe.id }));
        return;
      }

      try {
        const response = await fetch(`https://project-shoes-app.onrender.com/generate-id?type=${editShoe.type}`, {
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
        if (response.ok && data.id) {
          setEditShoe((prev) => ({ ...prev, id: data.id }));
          setError('');
        } else {
          setError(data.error || 'Failed to generate ID');
        }
      } catch (err) {
        console.error('Error generating ID:', err.message);
        setError('Error generating ID: ' + err.message);
      }
    };

    if (editShoe.type) {
      generateID();
    }
  }, [editShoe.type, token, shoe.id, shoe.type]);

  const handleUpdateShoe = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`https://project-shoes-app.onrender.com/shoes/${shoe._id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        credentials: 'include',
        body: JSON.stringify(editShoe),
      });

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();
      if (response.ok && data.shoe) {
        onUpdateSuccess(data.shoe);
        setSuccess('Shoe updated successfully!');
        setError('');
        // Clear success message after 3 seconds
        setTimeout(() => setSuccess(''), 3000);
      } else {
        setError(data.error || 'Error updating shoe');
        setSuccess('');
      }
    } catch (err) {
      console.error('Error updating shoe:', err.message);
      setError('Error updating shoe: ' + err.message);
      setSuccess('');
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setEditShoe((prev) => ({ ...prev, [name]: value }));
  };

  // Clear success and error messages on cancel
  const handleCancel = () => {
    setSuccess('');
    setError('');
    onCancel();
  };

  return (
    <div className="relative p-4">
      {/* Success Notification Toast */}
      {success && (
        <div
          role="alert"
          className="fixed top-4 left-1/2 transform -translate-x-1/2 bg-green-600 text-white px-6 py-3 rounded-lg shadow-xl z-50 animate-fade-in-out flex items-center gap-2 text-lg font-semibold"
        >
          <svg
            className="w-6 h-6"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M5 13l4 4L19 7"
            />
          </svg>
          {success}
        </div>
      )}
      {error && <p className="text-red-500 mb-3">{error}</p>}
      <div className="card shadow-lg p-4 mb-4 bg-white rounded-lg">
        <h3 className="text-lg font-bold mb-3">Edit Shoe</h3>
        <form onSubmit={handleUpdateShoe}>
          <div className="mb-3">
            <label className="form-label text-gray-600">ID</label>
            <input
              type="text"
              className="form-control"
              value={editShoe.id}
              readOnly
            />
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Name</label>
            <input
              type="text"
              name="name"
              className="form-control"
              value={editShoe.name}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Image URL</label>
            <input
              type="text"
              name="image"
              className="form-control"
              value={editShoe.image}
              onChange={handleInputChange}
            />
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Price</label>
            <input
              type="number"
              name="price"
              className="form-control"
              value={editShoe.price}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Type</label>
            <select
              name="type"
              className="form-control"
              value={editShoe.type}
              onChange={handleInputChange}
              required
            >
              <option value="MEN">MEN</option>
              <option value="WMN">WMN</option>
              <option value="KID">KID</option>
              <option value="SPT">SPT</option>
              <option value="SLP">SLP</option>
              <option value="SND">SND</option>
            </select>
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Color</label>
            <input
              type="text"
              name="color"
              className="form-control"
              value={editShoe.color}
              onChange={handleInputChange}
            />
          </div>
          <div className="mb-3">
            <label className="form-label text-gray-600">Attribute</label>
            <select
              name="attribute"
              className="form-control"
              value={editShoe.attribute}
              onChange={handleInputChange}
            >
              <option value="">Select an attribute (optional)</option>
              <option value="Best Seller">Best Seller</option>
              <option value="Trending">Trending</option>
              <option value="New Arrival">New Arrival</option>
              <option value="Classic">Classic</option>
              <option value="Sold Out">Sold Out</option>
              <option value="Limited Edition">Limited Edition</option>
            </select>
          </div>
          <div className="d-flex gap-2">
            <button
              type="submit"
              className="btn btn-primary hover:bg-blue-600 transition duration-300"
            >
              Update Shoe
            </button>
            <button
              type="button"
              onClick={handleCancel}
              className="btn btn-secondary hover:bg-gray-600 transition duration-300"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export default UpdateShoes;