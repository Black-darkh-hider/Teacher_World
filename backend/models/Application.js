const mongoose = require('mongoose');

const applicationSchema = new mongoose.Schema(
  {
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true, index: true },
    teacherId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    coverLetter: String,
    status: { type: String, default: 'applied' },
  },
  { timestamps: true }
);

module.exports = mongoose.model('Application', applicationSchema);
