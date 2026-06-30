import mongoose from 'mongoose';

const IdeathonSubmissionSchema = new mongoose.Schema({
  name: { type: String, required: true },
  college: { type: String, required: true },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  phone: { type: String, required: true },
  idea: { type: String, required: true },
  utrId: { type: String, required: true, unique: true, trim: true },
  paymentScreenshotUrl: { type: String, required: true },
  thumbnailUrl: { type: String, default: null },
  paymentVerified: { type: Boolean, default: false },
  verifiedAt: { type: Date },
  verifiedBy: { type: String },
  teamName: { type: String, required: true, unique: true, trim: true },
  domain: { type: String, required: true },
  teamSize: { type: Number, required: true },
  teamMembers: [
    {
      name: { type: String, required: true },
      email: { type: String, required: true, lowercase: true, trim: true },
    },
  ],
  referralCode: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
  },
  referredByCode: { type: String, uppercase: true, trim: true, index: true },
  referralPoints: { type: Number, default: 0, index: true },
  lastPointEarnedAt: { type: Date, default: Date.now, index: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

IdeathonSubmissionSchema.pre('save', function () {
  this.updatedAt = new Date();
});

IdeathonSubmissionSchema.index({ createdAt: -1 });
IdeathonSubmissionSchema.index({ paymentVerified: 1 });

export default mongoose.model(
  'DigitalIndiaIdeathonSubmission',
  IdeathonSubmissionSchema,
  'digital_india_ideathon_submissions',
);
