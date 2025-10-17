const mongoose = require('mongoose');

const certificateSchema = new mongoose.Schema(
  {
    title: String,
    fileUrl: String,
    uploadedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

const teacherProfileSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    name: String,
    phone: String,
    city: String,
    qualification: String,
    resumeUrl: String,
    certificates: [certificateSchema],
  },
  { timestamps: true }
);

module.exports = mongoose.model('TeacherProfile', teacherProfileSchema);
