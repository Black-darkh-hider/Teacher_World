const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema(
  {
    hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: String,
    description: String,
    startTime: Date,
    duration: Number,
    meetingLink: String,
    provider: { type: String, default: 'Jitsi' },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Session', sessionSchema);
