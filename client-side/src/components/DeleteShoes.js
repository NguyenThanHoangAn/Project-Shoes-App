import React from 'react';

const DeleteShoes = async (shoeId, token, onSuccess) => {
  const confirmDelete = window.confirm('Bạn có chắc chắn muốn xóa đôi giày này không?');
  if (!confirmDelete) return;

  try {
    const response = await fetch(`http://localhost:5000/shoes/${shoeId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      credentials: 'include',
    });

    const contentType = response.headers.get('content-type');
    if (!contentType || !contentType.includes('application/json')) {
      const text = await response.text();
      console.error('Non-JSON response:', text);
      throw new Error('Server returned non-JSON response');
    }

    const result = await response.json();
    if (response.ok) {
      alert(result.message);
      onSuccess(); // Gọi callback để cập nhật danh sách
    } else {
      throw new Error(result.error || 'Xóa không thành công');
    }
  } catch (error) {
    console.error('Error deleting shoe:', error.message);
    alert(`Đã xảy ra lỗi khi xóa giày: ${error.message}`);
  }
};

export default DeleteShoes;