const mongoose = require('mongoose');

const jobSchema = new mongoose.Schema(
  {
    employerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    qualifications: String,
    city: String,
    salary: String,
    tags: [{ type: String }],
  },
  { timestamps: true }
);

module.exports = mongoose.model('Job', jobSchema);
