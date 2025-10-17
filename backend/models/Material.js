const mongoose = require('mongoose');

const materialSchema = new mongoose.Schema(
  {
    uploaderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    description: String,
    subject: String,
    classGrade: String,
    fileUrl: String,
    linkUrl: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model('Material', materialSchema);
