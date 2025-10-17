const mongoose = require('mongoose');

const institutionProfileSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', unique: true, required: true },
    orgName: String,
    contactPerson: String,
    city: String,
    contactInfo: String,
    description: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model('InstitutionProfile', institutionProfileSchema);
