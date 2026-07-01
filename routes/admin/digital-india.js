import { Router } from 'express';
import path from 'node:path';
import fs from 'node:fs/promises';
import { requireApiKey } from '../../middleware/auth.js';
import IdeathonSubmission from '../../models/digital-india-ideathon.js';
import mongoose from 'mongoose';
import { UPLOAD_ROOT } from '../../config/uploads.js';
import { fetchFromR2, isConfigured as r2Configured, initR2 } from '../../lib/r2.js';

initR2();

const router = Router();
const MAX_SEARCH_LENGTH = 100;

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function escCsv(val) {
  if (val == null) return '';
  const s = Array.isArray(val) ? val.join('; ') : String(val);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

router.get('/stats', requireApiKey, async (req, res) => {
  try {
    const now = new Date();
    const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const [
      totalIdeathon, ideathon24h, ideathonVerified,
      totalHackathon, hackathon24h, hackathonVerified,
    ] = await Promise.all([
      IdeathonSubmission.countDocuments(),
      IdeathonSubmission.countDocuments({ createdAt: { $gte: last24h } }),
      IdeathonSubmission.countDocuments({ paymentVerified: true }),
      0, 0, 0,
    ]);

    return res.json({
      ideathon: {
        total: totalIdeathon, last24h: ideathon24h,
        verified: ideathonVerified, pending: totalIdeathon - ideathonVerified,
      },
      hackathon: {
        total: totalHackathon, last24h: hackathon24h,
        verified: hackathonVerified, pending: totalHackathon - hackathonVerified,
      },
    });
  } catch (error) {
    console.error('Admin digital-india stats error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to fetch stats' });
  }
});

router.get('/ideathon', requireApiKey, async (req, res) => {
  try {
    const { page = '1', limit = '20', search = '', verified = '' } = req.query;

    if (search.length > MAX_SEARCH_LENGTH) {
      return res.status(400).json({ message: 'error', error: 'Search query too long' });
    }

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (pageNum - 1) * limitNum;

    const filter = {};

    if (search.trim()) {
      const searchRegex = new RegExp(escapeRegex(search.trim()), 'i');
      filter.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { teamName: searchRegex },
      ];
    }

    if (verified === 'true') filter.paymentVerified = true;
    if (verified === 'false') filter.paymentVerified = false;

    const [data, total] = await Promise.all([
      IdeathonSubmission.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select('-__v')
        .lean(),
      IdeathonSubmission.countDocuments(filter),
    ]);

    return res.json({
      data,
      pagination: { total, page: pageNum, limit: limitNum, pages: Math.ceil(total / limitNum) || 1 },
    });
  } catch (error) {
    console.error('Admin ideathon list error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to fetch submissions' });
  }
});

router.get('/ideathon/export', requireApiKey, async (req, res) => {
  try {
    const submissions = await IdeathonSubmission.find()
      .sort({ createdAt: -1 })
      .select('-__v -_id')
      .lean();

    const headers = [
      'Name', 'College', 'Email', 'Phone', 'Idea Description',
      'UTR ID', 'Payment Screenshot URL', 'Thumbnail URL', 'Verified',
      'Verified At', 'Verified By', 'Team Name', 'Domain Track',
      'Team Size', 'Team Members', 'Referral Code', 'Referred By',
      'Referral Points', 'Registered At',
    ];

    const rows = submissions.map((s) =>
      [
        s.name, s.college, s.email, s.phone, s.idea,
        s.utrId, s.paymentScreenshotUrl, s.thumbnailUrl ?? '',
        s.paymentVerified ? 'Yes' : 'No',
        s.verifiedAt ? new Date(s.verifiedAt).toISOString() : '',
        s.verifiedBy ?? '',
        s.teamName, s.domain, s.teamSize,
        s.teamMembers
          ? s.teamMembers.map((m) => `${m.name} (${m.email})`).join('; ')
          : '',
        s.referralCode, s.referredByCode ?? '',
        s.referralPoints,
        s.createdAt ? new Date(s.createdAt).toISOString() : '',
      ]
        .map(escCsv)
        .join(','),
    );

    const csv = [headers.join(','), ...rows].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="c3-ideathon-submissions-${Date.now()}.csv"`);
    return res.send(csv);
  } catch (error) {
    console.error('Ideathon export error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to export submissions' });
  }
});

router.get('/screenshot', requireApiKey, async (req, res) => {
  try {
    const { id, thumb } = req.query;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({ message: 'error', error: 'Submission ID is required' });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'error', error: 'Invalid Submission ID format' });
    }

    let submission = await IdeathonSubmission.findById(id).lean();
    if (!submission) {
      const HackathonModel = (await import('../../models/digital-india-hackathon.js')).default;
      submission = await HackathonModel.findById(id).lean();
    }
    if (!submission) {
      submission = await mongoose.connection.db.collection('digital_india_accepted').findOne({ _id: new mongoose.Types.ObjectId(id) });
    }

    if (!submission) {
      return res.status(404).json({ message: 'error', error: 'Submission not found' });
    }

    const relativePath = thumb === 'true' && submission.thumbnailUrl
      ? submission.thumbnailUrl
      : submission.paymentScreenshotUrl;

    if (!relativePath) {
      return res.status(404).json({ message: 'error', error: 'No file found for this submission' });
    }

    let absolutePath;
    if (relativePath.startsWith('http')) {
      const urlPath = new URL(relativePath).pathname.replace(/^\//, '');
      const filename = path.basename(urlPath);
      const searchDir = path.join(UPLOAD_ROOT, 'digital-india-hackathon', 'ideathon', 'payment-screenshots');
      absolutePath = await findFileRecursive(searchDir, filename);

      if (absolutePath) {
        try {
          await fs.access(absolutePath);
        } catch {
          absolutePath = null;
        }
      }

      if (!absolutePath) {
        const r2Key = urlPath;
        const r2Result = await fetchFromR2(r2Key);
        if (r2Result) {
          res.set('Content-Type', r2Result.contentType);
          res.set('Cache-Control', 'public, max-age=86400');
          res.set('X-Source', 'r2-fallback');
          return res.send(r2Result.body);
        }

        const msg = r2Configured()
          ? 'Screenshot not found in R2 bucket.'
          : 'Old R2-hosted screenshot is not available. Configure R2_ENDPOINT and credentials to enable fallback.';
        return res.status(404).json({ message: 'error', error: msg });
      }
    } else {
      absolutePath = path.resolve(UPLOAD_ROOT, relativePath.replace(/^\/uploads\//, ''));
      if (!absolutePath.startsWith(UPLOAD_ROOT)) {
        return res.status(403).json({ message: 'error', error: 'Invalid file path' });
      }
      try {
        await fs.access(absolutePath);
      } catch {
        return res.status(404).json({ message: 'error', error: 'File not found on disk' });
      }
    }

    const ext = path.extname(absolutePath).toLowerCase();
    const mimeTypes = {
      '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
      '.webp': 'image/webp', '.avif': 'image/avif',
    };
    const contentType = mimeTypes[ext] || 'application/octet-stream';

    return res.sendFile(absolutePath, {
      headers: {
        'Content-Type': contentType,
        'Cache-Control': 'public, max-age=86400',
      },
    });
  } catch (error) {
    console.error('Screenshot serve error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to serve file' });
  }
});

router.post('/ideathon/verify', requireApiKey, async (req, res) => {
  try {
    const { id, verified } = req.body;

    if (!id || typeof id !== 'string') {
      return res.status(400).json({ message: 'error', error: 'Submission ID is required' });
    }

    const update = {
      paymentVerified: verified === true,
      verifiedAt: verified === true ? new Date() : null,
      verifiedBy: verified === true ? (req.headers['x-admin-user'] || 'admin') : null,
    };

    const submission = await IdeathonSubmission.findByIdAndUpdate(id, { $set: update }, { new: true });

    if (!submission) {
      return res.status(404).json({ message: 'error', error: 'Submission not found' });
    }

    return res.json({
      message: 'success',
      data: {
        id: submission._id,
        paymentVerified: submission.paymentVerified,
        verifiedAt: submission.verifiedAt,
      },
    });
  } catch (error) {
    console.error('Ideathon verify error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to update verification status' });
  }
});

async function findFileRecursive(baseDir, filename) {
  try {
    const entries = await fs.readdir(baseDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const found = await findFileRecursive(path.join(baseDir, entry.name), filename);
        if (found) return found;
      } else if (entry.name === filename) {
        return path.join(baseDir, entry.name);
      }
    }
  } catch {}
  return null;
}

export default router;
