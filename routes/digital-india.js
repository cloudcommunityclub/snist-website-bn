import { Router } from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { UPLOAD_CATEGORIES } from '../config/uploads.js';
import { uploadIdeathonScreenshot } from '../middleware/uploader.js';
import { validateUploadedFile } from '../middleware/file-validator.js';
import { optimizeUploadedImage, toRelativeUrl } from '../middleware/image-processor.js';
import IdeathonSubmission from '../models/digital-india-ideathon.js';
import { requireApiKey } from '../middleware/auth.js';

const router = Router();

async function generateReferralCode(category) {
  const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const Model = category === 'hackathon'
    ? (await import('../models/digital-india-hackathon.js')).default
    : IdeathonSubmission;

  for (let attempt = 0; attempt < 20; attempt++) {
    let code = '';
    for (let i = 0; i < 6; i++) {
      code += CHARS[crypto.randomInt(CHARS.length)];
    }
    const existing = await Model.findOne({ referralCode: code });
    if (!existing) return code;
  }
  throw new Error('Could not generate a unique referral code after multiple attempts.');
}

function extractFormFields(body) {
  return {
    name: body.name?.trim(),
    college: body.college?.trim(),
    email: body.email?.trim().toLowerCase(),
    phone: body.phone?.trim(),
    idea: body.idea?.trim(),
    utrId: body.utrId?.trim(),
    teamName: body.teamName?.trim(),
    domain: body.domain?.trim(),
    teamSize: body.teamSize ? Number(body.teamSize) : undefined,
    teamMembers: (() => {
      try {
        return body.teamMembers ? JSON.parse(body.teamMembers) : [];
      } catch {
        return [];
      }
    })(),
    referredByCode: body.referredBy?.trim().toUpperCase() || null,
  };
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

router.post(
  '/ideathon/submit',
  uploadIdeathonScreenshot.single('screenshot'),
  validateUploadedFile(),
  optimizeUploadedImage({ category: UPLOAD_CATEGORIES.DIGITAL_INDIA_IDEATHON }),
  async (req, res) => {
    try {
      const fields = extractFormFields(req.body);

      const requiredFields = [
        'name', 'college', 'email', 'phone', 'idea',
        'utrId', 'teamName', 'domain', 'teamSize',
      ];

      for (const field of requiredFields) {
        if (!fields[field]) {
          if (req.file?.path) {
            await fs.unlink(req.file.path).catch(() => {});
            if (req.file?.thumbnailPath) {
              await fs.unlink(req.file.thumbnailPath).catch(() => {});
            }
          }
          return res.status(400).json({
            message: 'error',
            error: `Field "${field}" is required.`,
          });
        }
      }

      const [existingEmail, existingUtr, existingTeam] = await Promise.all([
        IdeathonSubmission.findOne({ email: fields.email }),
        IdeathonSubmission.findOne({ utrId: fields.utrId }),
        IdeathonSubmission.findOne({
          teamName: new RegExp(`^${escapeRegex(fields.teamName)}$`, 'i'),
        }),
      ]);

      if (existingEmail) {
        return res.status(400).json({
          message: 'error',
          error: 'A submission with this email already exists.',
        });
      }
      if (existingUtr) {
        return res.status(400).json({
          message: 'error',
          error: 'A submission with this UTR ID already exists.',
        });
      }
      if (existingTeam) {
        return res.status(400).json({
          message: 'error',
          error: 'A team with this name already exists.',
        });
      }

      const paymentScreenshotUrl = toRelativeUrl(req.file.path);
      const thumbnailUrl = req.file.thumbnailPath
        ? toRelativeUrl(req.file.thumbnailPath)
        : null;

      const referralCode = await generateReferralCode('ideathon');

      const submission = await IdeathonSubmission.create({
        name: fields.name,
        college: fields.college,
        email: fields.email,
        phone: fields.phone,
        idea: fields.idea,
        utrId: fields.utrId,
        paymentScreenshotUrl,
        thumbnailUrl,
        paymentVerified: false,
        teamName: fields.teamName,
        domain: fields.domain,
        teamSize: fields.teamSize,
        teamMembers: fields.teamMembers,
        referralCode,
        referredByCode: fields.referredByCode || undefined,
        referralPoints: 0,
        lastPointEarnedAt: new Date(),
      });

      console.log(`✅ Ideathon submission recorded: ${fields.email}`);

      if (fields.referredByCode) {
        try {
          const referrer = await IdeathonSubmission.findOne({
            referralCode: fields.referredByCode,
          });
          if (referrer) {
            if (referrer.email === fields.email || referrer.phone === fields.phone) {
              console.warn(`⚠️ Self-referral detected for ${fields.email}`);
            } else {
              await referrer.updateOne({
                $inc: { referralPoints: 1 },
                $set: { lastPointEarnedAt: new Date() },
              });
              console.log(`🎉 Referral point awarded to ${referrer.email}`);
            }
          }
        } catch (refErr) {
          console.error('❌ Referral processing error:', refErr);
        }
      }

      try {
        const { sendIdeathonConfirmation } = await import('../lib/email-templates.js');
        await sendIdeathonConfirmation(fields.email, {
          name: fields.name,
          teamName: fields.teamName,
          referralCode,
        });
        console.log(`✅ Confirmation email sent to ${fields.email}`);
      } catch (emailErr) {
        console.error('❌ Confirmation email failed:', emailErr.message);
      }

      return res.status(201).json({
        message: 'success',
        data: {
          id: submission._id,
          name: fields.name,
          email: fields.email,
          teamName: fields.teamName,
          paymentScreenshotUrl,
          referralCode,
        },
      });
    } catch (error) {
      console.error('❌ Ideathon submission error:', error);
      return res.status(500).json({
        message: 'error',
        error: 'An error occurred while processing your submission.',
      });
    }
  },
);

export default router;
