const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  date: { type: String, required: true },
  planned: { type: String, default: '' },
  completed: { type: String,  default: '' },
  note: { type: String, default: '' }
});

const TargetSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Link to User
  title: { type: String, required: true },
  description: { type: String, default: '' },
  dueDate: { type: Date, required: true },
  tags: [String],
  isPinned: { type: Boolean, default: false },
  isArchived: { type: Boolean, default: false },
  logs: [LogSchema]
}, { timestamps: true });

module.exports = mongoose.model('Target', TargetSchema);