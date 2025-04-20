import React, { useState, useEffect } from 'react';
import UpdateShoes from './UpdateShoes';
import DeleteShoes from './DeleteShoes';
import 'bootstrap/dist/css/bootstrap.min.css';

function ShoesList({ token }) {
  const [shoes, setShoes] = useState([]);
  const [error, setError] = useState('');
  const [editShoe, setEditShoe] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const shoesPerPage = 6;

  // Fetch danh sách giày
  const fetchShoes = async () => {
    if (!token) {
      setError('No token provided. Please login.');
      return;
    }

    try {
      console.log('Fetching shoes with token:', token);
      const response = await fetch('https://project-shoes-app.onrender.com/shoes', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        credentials: 'include',
      });

      console.log('Response status:', response.status);
      console.log('Response headers:', response.headers.get('content-type'));

      const contentType = response.headers.get('content-type');
      if (!contentType || !contentType.includes('application/json')) {
        const text = await response.text();
        console.error('Non-JSON response:', text);
        throw new Error('Server returned non-JSON response');
      }

      const data = await response.json();
      console.log('Response data:', data);

      if (response.ok && data.shoes) {
        setShoes(data.shoes);
        setError('');
      } else {
        setError(data.error || 'No shoes data found');
      }
    } catch (err) {
      console.error('Fetch error:', err);
      setError(err.message || 'Error fetching shoes');
    }
  };

  useEffect(() => {
    fetchShoes();
  }, [token]);

  // Callback khi cập nhật giày thành công
  const handleUpdateSuccess = (updatedShoe) => {
    setShoes(shoes.map((s) => (s._id === updatedShoe._id ? updatedShoe : s)));
    setEditShoe(null);
  };

  // Xử lý chỉnh sửa giày
  const handleEditShoe = (shoe) => {
    setEditShoe(shoe);
  };

  // Hủy chỉnh sửa
  const handleCancelEdit = () => {
    setEditShoe(null);
  };

  // Lọc và tìm kiếm giày
  const filteredShoes = shoes.filter((shoe) =>
    shoe.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  // Phân trang
  const indexOfLastShoe = currentPage * shoesPerPage;
  const indexOfFirstShoe = indexOfLastShoe - shoesPerPage;
  const currentShoes = filteredShoes.slice(indexOfFirstShoe, indexOfLastShoe);
  const totalPages = Math.ceil(filteredShoes.length / shoesPerPage);

  const paginate = (pageNumber) => setCurrentPage(pageNumber);

  return (
    <div className="container py-5">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="text-3xl font-bold text-gray-800">Shoes Collection</h2>
        <div className="d-flex align-items-center gap-3">
          <input
            type="text"
            className="form-control w-50"
            placeholder="Search shoes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>

      {/* Hiển thị lỗi */}
      {error && <p className="text-danger mb-4">{error}</p>}

      {/* Component UpdateShoes */}
      {editShoe && (
        <UpdateShoes
          token={token}
          shoe={editShoe}
          onUpdateSuccess={handleUpdateSuccess}
          onCancel={handleCancelEdit}
        />
      )}

      {/* Danh sách giày dạng lưới */}
      <div className="row">
        {currentShoes.length > 0 ? (
          currentShoes.map((shoe) => (
            <div key={shoe._id} className="col-md-4 col-sm-6 mb-4">
              <div className="card h-100 shadow-sm hover:shadow-lg transition-shadow duration-300">
                {/* Hình ảnh */}
                <div className="position-relative">
                  {shoe.image && (
                    <img
                      src={shoe.image}
                      alt={shoe.name}
                      className="card-img-top"
                      style={{ height: '200px', objectFit: 'cover' }}
                    />
                  )}
                  {/* Nhãn Attribute */}
                  {shoe.attribute && (
                    <span
                      className={`position-absolute top-0 start-0 badge ${
                        shoe.attribute === 'Sold Out'
                          ? 'bg-danger'
                          : shoe.attribute === 'Best Seller'
                          ? 'bg-success'
                          : shoe.attribute === 'New Arrival'
                          ? 'bg-info'
                          : 'bg-warning'
                      } m-2`}
                    >
                      {shoe.attribute}
                    </span>
                  )}
                </div>
                <div className="card-body">
                  <h5 className="card-title font-weight-bold">{shoe.name}</h5>
                  <p className="card-text text-muted mb-1">{shoe.type}</p>
                  <p className="card-text text-muted mb-1">{shoe.color}</p>
                  <p className="card-text text-success font-weight-bold">
                    {shoe.price.toLocaleString()} VND
                  </p>
                </div>
                <div className="card-footer bg-transparent border-0 d-flex justify-content-between">
                  <button
                    onClick={() => handleEditShoe(shoe)}
                    className="btn btn-outline-warning btn-sm"
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => DeleteShoes(shoe._id, token, fetchShoes)}
                    className="btn btn-outline-danger btn-sm"
                  >
                    Delete
                  </button>
                </div>
              </div>
            </div>
          ))
        ) : (
          <div className="col-12 text-center">
            <p className="text-muted">No shoes found.</p>
          </div>
        )}
      </div>

      {/* Phân trang */}
      {totalPages > 1 && (
        <nav className="d-flex justify-content-center mt-4">
          <ul className="pagination">
            <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={() => paginate(currentPage - 1)}
              >
                Previous
              </button>
            </li>
            {[...Array(totalPages)].map((_, index) => (
              <li
                key={index + 1}
                className={`page-item ${currentPage === index + 1 ? 'active' : ''}`}
              >
                <button
                  className="page-link"
                  onClick={() => paginate(index + 1)}
                >
                  {index + 1}
                </button>
              </li>
            ))}
            <li className={`page-item ${currentPage === totalPages ? 'disabled' : ''}`}>
              <button
                className="page-link"
                onClick={() => paginate(currentPage + 1)}
              >
                Next
              </button>
            </li>
          </ul>
        </nav>
      )}
    </div>
  );
}

export default ShoesList;