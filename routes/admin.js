import { Router } from 'express';
import Registration2026 from '../models/registration2026.js';
import { requireApiKey } from '../middleware/auth.js';

const router = Router();

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

    const [total, recent24h, emailed] = await Promise.all([
      Registration2026.countDocuments(),
      Registration2026.countDocuments({ createdAt: { $gte: last24h } }),
      Registration2026.countDocuments({ emailSent: true }),
    ]);

    return res.json({
      total,
      recent24h,
      emailed,
      pendingEmail: total - emailed,
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to fetch stats' });
  }
});

router.get('/members', requireApiKey, async (req, res) => {
  try {
    const { page = '1', limit = '20', search = '' } = req.query;

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const skip = (pageNum - 1) * limitNum;

    const filter = {};
    if (search.trim()) {
      const searchRegex = new RegExp(search.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { rollNumber: searchRegex },
      ];
    }

    const [data, total] = await Promise.all([
      Registration2026.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select('-__v')
        .lean(),
      Registration2026.countDocuments(filter),
    ]);

    return res.json({
      data,
      pagination: { total, page: pageNum, limit: limitNum, pages: Math.ceil(total / limitNum) || 1 },
    });
  } catch (error) {
    console.error('Admin members list error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to fetch members' });
  }
});

router.get('/members/export', requireApiKey, async (req, res) => {
  try {
    const members = await Registration2026.find()
      .sort({ createdAt: -1 })
      .select('-__v -_id')
      .lean();

    const headers = ['Name', 'Email', 'Mobile', 'Roll Number', 'Department', 'Year', 'Interests', 'Experience', 'Expectations', 'Referral', 'Email Sent', 'Email Sent At', 'Registered At'];

    const rows = members.map((m) =>
      [
        m.name, m.email, m.mobile, m.rollNumber, m.department, m.year,
        m.interests ? m.interests.join('; ') : '',
        m.experience || '', m.expectations || '', m.referral || '',
        m.emailSent ? 'Yes' : 'No',
        m.emailSentAt ? new Date(m.emailSentAt).toISOString() : '',
        m.createdAt ? new Date(m.createdAt).toISOString() : '',
      ]
        .map(escCsv)
        .join(',')
    );

    const csv = [headers.join(','), ...rows].join('\n');

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="c3-members-${Date.now()}.csv"`);
    return res.send(csv);
  } catch (error) {
    console.error('Members export error:', error);
    return res.status(500).json({ message: 'error', error: 'Failed to export members' });
  }
});

export default router;
