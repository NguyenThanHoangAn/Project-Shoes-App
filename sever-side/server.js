const express = require('express');
const app = express();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
require('dotenv').config();

const port = process.env.PORT || 5000;

// Cấu hình CORS
const allowedOrigins = [
  'https://project-shoes-app-five.vercel.app',
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(cors({
  credentials: true,
  origin: (origin, callback) => {
    console.log('Request Origin:', origin); // Log origin for debugging
    // Allow requests with no origin (e.g., Postman, curl) or from allowed origins
    if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.onrender.com')) {
      callback(null, true);
    } else {
      console.error('CORS Error: Origin not allowed:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
}));
app.use(express.json());
app.use(cookieParser());

// Kiểm tra các biến môi trường
const requiredEnvVars = ['MONGODB_USERNAME', 'MONGODB_PASSWORD', 'MONGODB_DATABASE', 'MONGODB_CLUSTER', 'JWT_SECRET'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`Error: Missing environment variable ${envVar}`);
    process.exit(1);
  }
}

// Tạo chuỗi kết nối MongoDB
const MONGODB_URI = `mongodb+srv://${process.env.MONGODB_USERNAME}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_CLUSTER}/${process.env.MONGODB_DATABASE}?retryWrites=true&w=majority&appName=Cluster0`;

// Kết nối MongoDB Atlas
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB Atlas');
    console.log('Using database:', mongoose.connection.db.databaseName);
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Schema và Model cho Shoes
const ShoeSchema = new mongoose.Schema({
  id: { type: String, unique: true },
  name: String,
  image: String,
  price: Number,
  type: String,
  color: String,
  attribute: String,
}, { collection: 'Shoes' });
const Shoe = mongoose.model('Shoe', ShoeSchema);

// Schema và Model cho Users
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
}, { collection: 'Users' });
const User = mongoose.model('User', UserSchema);

// Secret key cho JWT
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware kiểm tra token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// Hàm generate ID theo định dạng
const generateShoeId = async (type) => {
  let typeCode;
  switch (type.toUpperCase()) {
    case 'MEN':
      typeCode = 'MEN';
      break;
    case 'WOMEN':
      typeCode = 'WMN';
      break;
    case 'KIDS':
      typeCode = 'KID';
      break;
    case 'SPORT':
      typeCode = 'SPT';
      break;
    case 'SLIPPER':
      typeCode = 'SLP';
      break;
    case 'SANDAL':
      typeCode = 'SND';
      break;
    default:
      throw new Error('Invalid shoe type');
  }

  let sequence = 1;
  let generatedId;
  let existingShoe;

  // Keep trying until a unique ID is found
  do {
    const sequenceStr = sequence.toString().padStart(3, '0');
    generatedId = `SHOE${typeCode}${sequenceStr}`;
    existingShoe = await Shoe.findOne({ id: generatedId });
    sequence++;
  } while (existingShoe);

  return generatedId;
};

// Route đăng ký
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Error registering user: ' + error.message });
  }
});

// Route đăng nhập
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Error logging in: ' + error.message });
  }
});

// Route đăng xuất
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Logged out successfully' });
});

// Lấy danh sách giày
app.get('/shoes', async (req, res) => {
  try {
    const shoes = await Shoe.find();
    res.json({ shoes });
  } catch (error) {
    console.error('Error fetching shoes:', error);
    res.status(500).json({ error: 'Error fetching shoes: ' + error.message });
  }
});

// Thêm giày mới
app.post('/shoes', authenticateToken, async (req, res) => {
  try {
    const { name, image, price, type, color, attribute } = req.body;

    if (!name || !price || !type) {
      return res.status(400).json({ error: 'Name, price, and type are required' });
    }

    const validTypes = ['MEN', 'WOMEN', 'KIDS', 'SPORT', 'SLIPPER', 'SANDAL'];
    if (!validTypes.includes(type.toUpperCase())) {
      return res.status(400).json({ error: 'Invalid shoe type' });
    }

    const id = await generateShoeId(type);
    const newShoe = new Shoe({ id, name, image, price: Number(price), type: type.toUpperCase(), color, attribute });
    await newShoe.save();

    res.status(201).json({ message: 'Shoe added successfully', shoe: newShoe });
  } catch (error) {
    console.error('Error adding shoe:', error);
    if (error.code === 11000) {
      res.status(400).json({ error: 'Duplicate shoe ID detected' });
    } else {
      res.status(500).json({ error: 'Error adding shoe: ' + error.message });
    }
  }
});

// Cập nhật giày
app.put('/shoes/:id', authenticateToken, async (req, res) => {
  try {
    const shoeId = req.params.id;
    const { name, image, price, type, color, attribute } = req.body;

    if (!name || !price || !type) {
      return res.status(400).json({ error: 'Name, price, and type are required' });
    }

    const validTypes = ['MEN', 'WOMEN', 'KIDS', 'SPORT', 'SLIPPER', 'SANDAL'];
    if (!validTypes.includes(type.toUpperCase())) {
      return res.status(400).json({ error: 'Invalid shoe type' });
    }

    const existingShoe = await Shoe.findById(shoeId);
    if (!existingShoe) {
      return res.status(404).json({ error: 'Shoe not found' });
    }

    // Nếu type thay đổi, tạo ID mới
    let updatedId = existingShoe.id;
    if (type.toUpperCase() !== existingShoe.type) {
      updatedId = await generateShoeId(type);
    }

    const updatedShoe = await Shoe.findByIdAndUpdate(
      shoeId,
      {
        id: updatedId,
        name,
        image,
        price: Number(price),
        type: type.toUpperCase(),
        color,
        attribute,
      },
      { new: true }
    );

    res.json({ message: 'Shoe updated successfully', shoe: updatedShoe });
  } catch (error) {
    console.error('Error updating shoe:', error);
    if (error.code === 11000) {
      res.status(400).json({ error: 'Duplicate shoe ID detected' });
    } else {
      res.status(500).json({ error: 'Error updating shoe: ' + error.message });
    }
  }
});

// Xóa giày
app.delete('/shoes/:id', authenticateToken, async (req, res) => {
  try {
    const shoeId = req.params.id;
    const shoe = await Shoe.findByIdAndDelete(shoeId);
    if (!shoe) {
      return res.status(404).json({ error: 'Shoe not found' });
    }
    res.json({ message: 'Shoe deleted successfully' });
  } catch (error) {
    console.error('Error deleting shoe:', error);
    res.status(500).json({ error: 'Error deleting shoe: ' + error.message });
  }
});

// Route để generate ID dựa trên type
app.get('/generate-id', async (req, res) => {
  try {
    const { type } = req.query;
    if (!type) {
      return res.status(400).json({ error: 'Type is required' });
    }
    const id = await generateShoeId(type);
    res.json({ id });
  } catch (error) {
    console.error('Error generating ID:', error);
    res.status(500).json({ error: 'Error generating ID: ' + error.message });
  }
});

// Xử lý lỗi toàn cục
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error: ' + err.message });
});

// Khởi động server
app.listen(port, () => {
  console.log(`Example app listening on port ${port}!`);
});