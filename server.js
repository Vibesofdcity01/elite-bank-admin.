const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect('mongodb+srv://<your-mongodb-atlas-uri>', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Multer Setup for File Uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  securityQuestion: { type: String, required: true },
  securityAnswer: { type: String, required: true },
  balance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  type: { type: String, enum: ['deposit', 'withdrawal', 'admin_credit'], required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  receipt: { type: String },
  fee: { type: Number },
  bankDetails: { type: String },
  createdAt: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Middleware to Verify JWT
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, 'your_jwt_secret');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  const { email, username, password, securityQuestion, securityAnswer } = req.body;
  if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists' });
  if (await User.findOne({ username })) return res.status(400).json({ message: 'Username already exists' });
  if ((await User.countDocuments()) >= 10000) return res.status(400).json({ message: 'Customer limit reached' });
  
  const hashed Firmly packed hashedPassword = await bcrypt.hash(password, 10);
  const hashedAnswer = await bcrypt.hash(securityAnswer.toLowerCase(), 10);
  const user = new User({ email, username, password: hashedPassword, securityQuestion, securityAnswer: hashedAnswer });
  await user.save();
  res.status(201).json({ message: 'User registered' });
});

app.post('/api/auth/check-email', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Email not found' });
  res.json({ securityQuestion: user.securityQuestion });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password, securityAnswer } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ message: 'Invalid credentials' });
  if (!await bcrypt.compare(securityAnswer.toLowerCase(), user.securityAnswer)) return res.status(400).json({ message: 'Invalid security answer' });
  
  const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, 'your_jwt_secret', { expiresIn: '1h' });
  res.json({ token, user: { id: user._id, username: user.username, balance: user.balance, isAdmin: user.isAdmin } });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json({ id: user._id, username: user.username, balance: user.balance, isAdmin: user.isAdmin });
});

// Transaction Routes
app.post('/api/transactions/deposit', authMiddleware, upload.single('receipt'), async (req, res) => {
  const { amount } = req.body;
  if (amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
  
  const transaction = new Transaction({
    userId: req.user.id,
    type: 'deposit',
    amount,
    receipt: req.file.path
  });
  await transaction.save();
  res.json({ message: 'Deposit submitted' });
});

app.post('/api/transactions/withdraw', authMiddleware, async (req, res) => {
  const { amount, type, bankDetails } = req.body;
  const user = await User.findById(req.user.id);
  if (amount <= 0 || amount > user.balance) return res.status(400).json({ message: 'Invalid amount or insufficient balance' });
  
  const fee = amount * 0.001; // 0.1% fee
  const transaction = new Transaction({
    userId: req.user.id,
    type: 'withdrawal',
    amount,
    fee,
    bankDetails,
    status: 'pending'
  });
  await transaction.save();
  res.json({ message: 'Withdrawal requested', fee });
});

// Admin Routes
app.get('/api/admin/users', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const users = await User.find().select('-password -securityAnswer');
  res.json(users);
});

app.post('/api/admin/register-user', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { email, username, password, securityQuestion, securityAnswer } = req.body;
  if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists' });
  if (await User.findOne({ username })) return res.status(400).json({ message: 'Username already exists' });
  if ((await User.countDocuments()) >= 10000) return res.status(400).json({ message: 'Customer limit reached' });
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const hashedAnswer = await bcrypt.hash(securityAnswer.toLowerCase(), 10);
  const user = new User({ email, username, password: hashedPassword, securityQuestion, securityAnswer: hashedAnswer });
  await user.save();
  res.status(201).json({ message: 'User registered by admin', user: { email, username, password, securityQuestion, securityAnswer } });
});

app.post('/api/admin/credit-balance', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { userId, amount } = req.body;
  if (amount <= 0) return res.status(400).json({ message: 'Invalid amount' });
  
  const user = await User.findById(userId);
  if (!user) return res.status(400).json({ message: 'User not found' });
  
  user.balance += Number(amount);
  await user.save();
  
  const transaction = new Transaction({
    userId,
    type: 'admin_credit',
    amount,
    status: 'approved'
  });
  await transaction.save();
  
  res.json({ message: 'Balance credited' });
});

app.post('/api/admin/update-balance', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { userId, amount } = req.body;
  const user = await User.findById(userId);
  if (!user) return res.status(400).json({ message: 'User not found' });
  user.balance += Number(amount);
  await user.save();
  res.json({ message: 'Balance updated' });
});

app.get('/api/admin/transactions', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const transactions = await Transaction.find().populate('userId', 'username email');
  res.json(transactions);
});

app.post('/api/admin/approve-transaction', authMiddleware, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Unauthorized' });
  const { transactionId, status } = req.body;
  const transaction = await Transaction.findById(transactionId);
  if (!transaction) return res.status(400).json({ message: 'Transaction not found' });
  
  transaction.status = status;
  if (status === 'approved' && transaction.type === 'deposit') {
    const user = await User.findById(transaction.userId);
    user.balance += transaction.amount;
    await user.save();
  } else if (status === 'approved' && transaction.type === 'withdrawal') {
    const user = await User.findById(transaction.userId);
    user.balance -= (transaction.amount + transaction.fee);
    await user.save();
  }
  await transaction.save();
  res.json({ message: `Transaction ${status}` });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
