require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const User = require('./models/User');
const Target = require('./models/Target');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'secret_key_123';

// --- MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Access Denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid Token" });
    req.user = user;
    next();
  });
};

// Connect DB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/targetflow')
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error(err));

// --- AUTH ROUTES ---

// Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, age, place, gender, studentClass, collegeName } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, age, place, gender, studentClass, collegeName });
    await user.save();

    const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET);
    const userObj = user.toObject();
    delete userObj.password;
    res.json({ token, user: userObj });
  } catch (err) {
    res.status(400).json({ error: "Error creating user" });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user._id, name: user.name }, JWT_SECRET);
    const userObj = user.toObject();
    delete userObj.password;
    
    res.json({ token, user: userObj });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// UPDATE PROFILE
app.patch('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const { name, age, place, gender, studentClass, collegeName } = req.body;
    
    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, age, place, gender, studentClass, collegeName },
      { new: true }
    ).select('-password');

    if (!updatedUser) return res.status(404).json({ error: "User not found" });

    res.json(updatedUser);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- TARGET DATA ROUTES (Protected) ---

app.get('/api/targets', authenticateToken, async (req, res) => {
  try {
    const targets = await Target.find({ user: req.user.id }).sort({ isPinned: -1, dueDate: 1 });
    res.json(targets);
  } catch (err) {
    res.status(500).json({ error: "Error fetching targets" });
  }
});

app.post('/api/targets', authenticateToken, async (req, res) => {
  try {
    const newTarget = new Target({ ...req.body, user: req.user.id });
    const saved = await newTarget.save();
    res.json(saved);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.patch('/api/targets/:id', authenticateToken, async (req, res) => {
  try {
    const updated = await Target.findOneAndUpdate({ _id: req.params.id, user: req.user.id }, req.body, { new: true });
    if (!updated) return res.status(404).json({ error: "Target not found" });
    res.json(updated);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

app.delete('/api/targets/:id', authenticateToken, async (req, res) => {
  try {
    await Target.findOneAndDelete({ _id: req.params.id, user: req.user.id });
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// --- LOG ROUTES (Fixed with Try/Catch) ---

// Add Log
app.post('/api/targets/:id/logs', authenticateToken, async (req, res) => {
  try {
    // Validate ID format prevents CastError crash
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid Target ID" });
    }

    const target = await Target.findOne({ _id: req.params.id, user: req.user.id });
    if (!target) return res.status(404).json({ error: "Target not found" });
    
    target.logs.push(req.body);
    await target.save();
    res.json(target);
  } catch (err) {
    console.error("Add Log Error:", err);
    res.status(500).json({ error: "Server error while adding log" });
  }
});

// Edit Log
app.put('/api/targets/:id/logs/:logId', authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid Target ID" });
    }

    const target = await Target.findOne({ _id: req.params.id, user: req.user.id });
    if (!target) return res.status(404).json({ error: "Target not found" });
    
    const log = target.logs.id(req.params.logId);
    if(log) {
      if(req.body.completed !== undefined) log.completed = req.body.completed;
      if(req.body.planned !== undefined) log.planned = req.body.planned;
      if(req.body.date) log.date = req.body.date;
      if(req.body.note !== undefined) log.note = req.body.note;
      await target.save();
    } else {
      return res.status(404).json({ error: "Log entry not found" });
    }
    res.json(target);
  } catch (err) {
    console.error("Edit Log Error:", err);
    res.status(500).json({ error: "Server error while editing log" });
  }
});

// Delete Log
app.delete('/api/targets/:id/logs/:logId', authenticateToken, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ error: "Invalid Target ID" });
    }

    const target = await Target.findOne({ _id: req.params.id, user: req.user.id });
    if (!target) return res.status(404).json({ error: "Target not found" });
    
    target.logs.pull(req.params.logId);
    await target.save();
    res.json(target);
  } catch (err) {
    console.error("Delete Log Error:", err);
    res.status(500).json({ error: "Server error while deleting log" });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));