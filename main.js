//  This is the main file
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();

// Middleware
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'pavan123';
const PORT = 5000;

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/ecommerce',)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' }
});
const User = mongoose.model('User', UserSchema);

// Product Schema
const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  description: String
});
const Product = mongoose.model('Product', ProductSchema);

// Cart Schema
const CartSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  items: [{ productId: mongoose.Schema.Types.ObjectId, quantity: Number }]
});
const Cart = mongoose.model('Cart', CartSchema);

// Order Schema
const OrderSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  items: [{ productId: mongoose.Schema.Types.ObjectId, quantity: Number }],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', OrderSchema);

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Failed to authenticate token' });
    req.user = decoded;
    next();
  });
};

// Admin middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admins only' });
  next();
};

//  User Registration
app.post('/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ name, email, password: hashedPassword, role });
    res.json({ message: 'User registered', user });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

//Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
    if (!user)
        return res.status(404).json({ message: 'User not found' });
  const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
        return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
  res.json({ message: 'Login successful', token });
});

// Products
app.get('/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.post('/products', authMiddleware, isAdmin, async (req, res) => {
  const product = await Product.create(req.body);
  res.json(product);
});

app.put('/products/:id', authMiddleware, isAdmin, async (req, res) => {
  const updated = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updated);
});

app.delete('/products/:id', authMiddleware, isAdmin, async (req, res) => {
  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: 'Product deleted' });
});

// Cart
app.post('/cart', authMiddleware, async (req, res) => {
  const { productId, quantity } = req.body;
  let cart = await Cart.findOne({ userId: req.user.id });
  if (!cart) cart = await Cart.create({ userId: req.user.id, items: [] });

  const itemIndex = cart.items.findIndex(item => item.productId.equals(productId));
  if (itemIndex > -1) {
    cart.items[itemIndex].quantity += quantity;
  } else {
    cart.items.push({ productId, quantity });
  }
  await cart.save();
  res.json(cart);
});

app.get('/cart', authMiddleware, async (req, res) => {
  const cart = await Cart.findOne({ userId: req.user.id }).populate('items.productId');
  res.json(cart);
});

//  Order
app.post('/orders', authMiddleware, async (req, res) => {
  const cart = await Cart.findOne({ userId: req.user.id });
  if (!cart || cart.items.length === 0) return res.status(400).json({ message: 'Cart is empty' });

  const order = await Order.create({ userId: req.user.id, items: cart.items });
  cart.items = [];
  await cart.save();
  res.json({ message: 'Order placed', order });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
