// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');

// Models (assuming these files exist in project root / same folder)
const Target = require('.models/Target');
const User = require('.models/User');

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan('tiny')); // optional but useful for debugging

// Config
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/targetflow';
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_prod';
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('✅ MongoDB connected'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

/**
 * Middleware: authenticateToken
 * Expects Authorization: Bearer <token>
 * Attaches req.user = { id: <userId> } when valid
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || req.headers['Authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing auth token' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.user = { id: payload.id, email: payload.email };
    next();
  });
}

/**
 * Middleware: validateObjectIds
 * Validates params.id and params.logId if present
 */
function validateObjectIds(req, res, next) {
  const { id, logId } = req.params;
  if (id && !mongoose.Types.ObjectId.isValid(id)) {
    return res.status(400).json({ error: 'Invalid target id' });
  }
  if (logId && !mongoose.Types.ObjectId.isValid(logId)) {
    return res.status(400).json({ error: 'Invalid log id' });
  }
  next();
}

/* ========================
   AUTH ROUTES
   POST /api/auth/signup
   POST /api/auth/login
   ======================== */

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, age, place, gender, studentClass, collegeName } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'name, email and password are required' });
    }

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const saltRounds = 10;
    const hashed = await bcrypt.hash(password, saltRounds);

    const user = new User({
      name,
      email: email.toLowerCase(),
      password: hashed,
      age,
      place,
      gender,
      studentClass,
      collegeName
    });

    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    // don't send password back
    const userOut = {
      id: user._id,
      name: user.name,
      email: user.email,
      age: user.age,
      place: user.place,
      gender: user.gender,
      studentClass: user.studentClass,
      collegeName: user.collegeName
    };

    return res.status(201).json({ token, user: userOut });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ error: 'Server error during signup' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

    const userOut = {
      id: user._id,
      name: user.name,
      email: user.email,
      age: user.age,
      place: user.place,
      gender: user.gender,
      studentClass: user.studentClass,
      collegeName: user.collegeName
    };

    return res.json({ token, user: userOut });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ error: 'Server error during login' });
  }
});

/* ==============
   USER ROUTE
   ============== */
app.get('/api/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    console.error('/api/me error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ========================
   TARGETS + LOGS ROUTES
   Protected by authenticateToken
   ======================== */

// GET all targets for user
app.get('/api/targets', authenticateToken, async (req, res) => {
  try {
    const targets = await Target.find({ user: req.user.id }).sort({ isPinned: -1, dueDate: 1 });
    res.json(targets);
  } catch (err) {
    console.error('GET /api/targets error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// CREATE a target
app.post('/api/targets', authenticateToken, async (req, res) => {
  try {
    // server ensures the owner is the authenticated user
    const payload = { ...req.body, user: req.user.id };
    const target = new Target(payload);
    const saved = await target.save();
    res.status(201).json(saved);
  } catch (err) {
    console.error('POST /api/targets error:', err);
    res.status(400).json({ error: err.message || 'Invalid data' });
  }
});

// UPDATE a target
app.patch('/api/targets/:id', authenticateToken, validateObjectIds, async (req, res) => {
  try {
    const { id } = req.params;
    const updated = await Target.findOneAndUpdate(
      { _id: id, user: req.user.id },
      { $set: req.body },
      { new: true, runValidators: true }
    );
    if (!updated) return res.status(404).json({ error: 'Target not found or not owned by you' });
    res.json(updated);
  } catch (err) {
    console.error('PATCH /api/targets/:id error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE a target
app.delete('/api/targets/:id', authenticateToken, validateObjectIds, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Target.findOneAndDelete({ _id: id, user: req.user.id });
    if (!deleted) return res.status(404).json({ error: 'Target not found or not owned by you' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /api/targets/:id error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ===== Logs endpoints ====== */

// Add a log to a target
app.post('/api/targets/:id/logs', authenticateToken, validateObjectIds, async (req, res) => {
  try {
    const { id } = req.params;
    const target = await Target.findOne({ _id: id, user: req.user.id });
    if (!target) return res.status(404).json({ error: 'Target not found or not owned by you' });

    // Basic validation of log shape - adapt as per your schema
    const log = {
      date: req.body.date || new Date(),
      planned: req.body.planned || '',
      completed: req.body.completed || '',
      note: req.body.note || ''
    };

    target.logs.push(log);
    await target.save();
    res.status(201).json(target);
  } catch (err) {
    console.error('POST /api/targets/:id/logs error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update a log
app.put('/api/targets/:id/logs/:logId', authenticateToken, validateObjectIds, async (req, res) => {
  try {
    const { id, logId } = req.params;
    const target = await Target.findOne({ _id: id, user: req.user.id });
    if (!target) return res.status(404).json({ error: 'Target not found or not owned by you' });

    const log = target.logs.id(logId);
    if (!log) return res.status(404).json({ error: 'Log not found' });

    // Update allowed fields only
    if (req.body.date !== undefined) log.date = req.body.date;
    if (req.body.planned !== undefined) log.planned = req.body.planned;
    if (req.body.completed !== undefined) log.completed = req.body.completed;
    if (req.body.note !== undefined) log.note = req.body.note;

    await target.save();
    res.json(target);
  } catch (err) {
    console.error('PUT /api/targets/:id/logs/:logId error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete a log
app.delete('/api/targets/:id/logs/:logId', authenticateToken, validateObjectIds, async (req, res) => {
  try {
    const { id, logId } = req.params;
    const target = await Target.findOne({ _id: id, user: req.user.id });
    if (!target) return res.status(404).json({ error: 'Target not found or not owned by you' });

    const log = target.logs.id(logId);
    if (!log) return res.status(404).json({ error: 'Log not found' });

    target.logs.pull(logId);
    await target.save();
    res.json(target);
  } catch (err) {
    console.error('DELETE /api/targets/:id/logs/:logId error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ==============
   Generic 404 + error handler
   ============== */
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

/* ==============
   Start server (Render-friendly)
   ============== */
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
