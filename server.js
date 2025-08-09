const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('./models/User');
const Employee = require('./models/Employees.js');
const cors = require('cors')

dotenv.config();
const app = express();
app.use(express.json());
 
// DB Connect
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Middleware to protect routes
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Access token missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(403).json({ msg: 'Invalid or expired token' });
  }
};

// Signup
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ msg: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ msg: 'Signup successful' });
  } catch (err) {
    res.status(500).json({ msg: 'Signup failed', error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ msg: 'Invalid email or password' });

    const accessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    user.refreshToken = refreshToken;
    await user.save();

    res.json({ msg: 'Login successful', accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ msg: 'Login failed', error: err.message });
  }
});

// Refresh Token
app.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ msg: 'Refresh token required' });

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user || user.refreshToken !== refreshToken)
      return res.status(403).json({ msg: 'Invalid refresh token' });

    const newAccessToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(403).json({ msg: 'Refresh token invalid or expired' });
  }
});

// Logout
app.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  try {
    const user = await User.findOne({ refreshToken });
    if (!user) return res.status(400).json({ msg: 'Invalid refresh token' });

    user.refreshToken = null;
    await user.save();

    res.json({ msg: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ msg: 'Logout failed', error: err.message });
  }
});

// Protected Profile
app.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password -refreshToken');
    res.json(user);
  } catch (err) {
    res.status(500).json({ msg: 'Cannot fetch profile', error: err.message });
  }
});

// GET API to fetch all employees
app.get("/api/employees", cors(), async (req, res) => {
  try {
    const employees = await Employee.find();
    res.json({ success: true, data: employees });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
