import mongoose from 'mongoose';

const Registration2026Schema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  mobile: { type: String, required: true },
  rollNumber: { type: String, required: true },
  department: { type: String, required: true },
  year: { type: String, required: true },
  interests: { type: [String], default: ['Cloud Computing'] },
  experience: { type: String },
  expectations: { type: String },
  referral: { type: String },
  emailSent: { type: Boolean, default: false },
  emailSentAt: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

Registration2026Schema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

Registration2026Schema.index({ createdAt: -1 });
Registration2026Schema.index({ department: 1, year: 1 });
Registration2026Schema.index({ emailSent: 1 });

export default mongoose.model('Registration2026', Registration2026Schema, 'registrations-2026');
