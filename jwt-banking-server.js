
// Title: JWT Authentication for Secure Banking API Endpoints
// Objective: Implement secure authentication in Express.js using JSON Web Tokens (JWT)
// to protect sensitive banking routes such as balance, deposit, and withdraw.

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ---------------------------
// 1️⃣ Hardcoded User & Secret
// ---------------------------
const USER = { username: 'user123', password: 'bank@123' };
const SECRET_KEY = 'myjwtsecretkey';

// ---------------------------
// 2️⃣ JWT Authentication Middleware
// ---------------------------
// Checks if Authorization header exists and verifies the JWT.
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }

  const token = authHeader.split(' ')[1]; // Expected format: Bearer <token>

  if (!token) {
    return res.status(401).json({ error: 'Missing token' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user; // attach decoded token data to request
    next();
  });
};

// ---------------------------
// 3️⃣ Banking Data (In-memory)
// ---------------------------
let accountBalance = 1000; // default balance

// ---------------------------
// 4️⃣ Login Route (Public)
// ---------------------------
// Returns a signed JWT token on successful login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check hardcoded credentials
  if (username === USER.username && password === USER.password) {
    const token = jwt.sign({ username: USER.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login successful', token });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

// ---------------------------
// 5️⃣ Protected Banking Routes
// ---------------------------

// View account balance
app.get('/balance', authMiddleware, (req, res) => {
  res.json({ balance: accountBalance });
});

// Deposit money
app.post('/deposit', authMiddleware, (req, res) => {
  const { amount } = req.body;

  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid deposit amount' });
  }

  accountBalance += amount;
  res.json({ message: 'Deposit successful', newBalance: accountBalance });
});

// Withdraw money
app.post('/withdraw', authMiddleware, (req, res) => {
  const { amount } = req.body;

  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid withdrawal amount' });
  }

  if (amount > accountBalance) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  accountBalance -= amount;
  res.json({ message: 'Withdrawal successful', newBalance: accountBalance });
});

// ---------------------------
// 6️⃣ Start the Server
// ---------------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Banking API running on http://localhost:${PORT}`);
});
