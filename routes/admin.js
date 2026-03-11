import { Router } from 'express';
import { requireApiKey } from '../middleware/auth.js';
import Registration2026 from '../models/registration2026.js';
import Recruitment from '../models/recruitment.js';

const router = Router();

/**
 * Escape a value for CSV output
 */
function escCsv(val) {
    if (val == null) return '';
    const s = Array.isArray(val) ? val.join('; ') : String(val);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
}

/**
 * Escape regex special chars for safe use in RegExp constructor
 */
function escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── STATS ───────────────────────────────────────────────────────────────────

/**
 * GET /api/admin/stats
 * Returns aggregate counts for the dashboard summary cards.
 */
router.get('/stats', requireApiKey, async (req, res) => {
    try {
        const now = new Date();
        const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);

        const [
            totalMembers,
            members24h,
            emailSent,
            totalRecruitment,
            recruitment24h,
            unlocked,
            submitted
        ] = await Promise.all([
            Registration2026.countDocuments(),
            Registration2026.countDocuments({ createdAt: { $gte: last24h } }),
            Registration2026.countDocuments({ emailSent: true }),
            Recruitment.countDocuments(),
            Recruitment.countDocuments({ createdAt: { $gte: last24h } }),
            Recruitment.countDocuments({ problemUnlocked: { $exists: true, $ne: null } }),
            Recruitment.countDocuments({ submittedSolution: true }),
        ]);

        return res.json({
            members: {
                total: totalMembers,
                last24h: members24h,
                emailSent,
                emailPending: totalMembers - emailSent,
            },
            recruitment: {
                total: totalRecruitment,
                last24h: recruitment24h,
                unlocked,
                submitted,
            }
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        return res.status(500).json({ message: 'error', error: 'Failed to fetch stats' });
    }
});

// ─── MEMBERS ─────────────────────────────────────────────────────────────────

/**
 * GET /api/admin/members
 * Paginated, filtered list of registered members.
 * Query params: page, limit, search, dept, year, emailSent
 */
router.get('/members', requireApiKey, async (req, res) => {
    try {
        const {
            page = '1',
            limit = '20',
            search = '',
            dept = '',
            year = '',
            emailSent = ''
        } = req.query;

        // Type-guard query params
        if (
            typeof page !== 'string' || typeof limit !== 'string' ||
            typeof search !== 'string' || typeof dept !== 'string' ||
            typeof year !== 'string' || typeof emailSent !== 'string'
        ) {
            return res.status(400).json({ message: 'error', error: 'Invalid query parameters' });
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
                { rollNumber: searchRegex }
            ];
        }
        if (dept.trim()) filter.department = { $eq: dept.trim() };
        if (year.trim()) filter.year = { $eq: year.trim() };
        if (emailSent === 'true') filter.emailSent = true;
        if (emailSent === 'false') filter.emailSent = false;

        const [data, total] = await Promise.all([
            Registration2026.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limitNum)
                .select('-__v')
                .lean(),
            Registration2026.countDocuments(filter)
        ]);

        return res.json({
            data,
            pagination: {
                total,
                page: pageNum,
                limit: limitNum,
                pages: Math.ceil(total / limitNum) || 1
            }
        });
    } catch (error) {
        console.error('Admin members list error:', error);
        return res.status(500).json({ message: 'error', error: 'Failed to fetch members' });
    }
});

/**
 * GET /api/admin/members/export
 * Download all members as a CSV file.
 */
router.get('/members/export', requireApiKey, async (req, res) => {
    try {
        const members = await Registration2026.find()
            .sort({ createdAt: -1 })
            .select('-__v -_id')
            .lean();

        const headers = [
            'Name', 'Email', 'Mobile', 'Roll Number', 'Department', 'Year',
            'Interests', 'Experience', 'Expectations', 'Referral',
            'Email Sent', 'Email Sent At', 'Registered At'
        ];

        const rows = members.map(m => [
            m.name, m.email, m.mobile, m.rollNumber, m.department, m.year,
            m.interests, m.experience ?? '', m.expectations ?? '', m.referral ?? '',
            m.emailSent ? 'Yes' : 'No',
            m.emailSentAt ? new Date(m.emailSentAt).toISOString() : '',
            m.createdAt ? new Date(m.createdAt).toISOString() : ''
        ].map(escCsv).join(','));

        const csv = [headers.join(','), ...rows].join('\n');

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="c3-members-${Date.now()}.csv"`);
        return res.send(csv);
    } catch (error) {
        console.error('Members export error:', error);
        return res.status(500).json({ message: 'error', error: 'Failed to export members' });
    }
});

// ─── RECRUITMENT ─────────────────────────────────────────────────────────────

/**
 * GET /api/admin/recruitment
 * Paginated, filtered list of recruitment candidates.
 * Query params: page, limit, search, year, unlocked
 */
router.get('/recruitment', requireApiKey, async (req, res) => {
    try {
        const {
            page = '1',
            limit = '20',
            search = '',
            year = '',
            unlocked = ''
        } = req.query;

        if (
            typeof page !== 'string' || typeof limit !== 'string' ||
            typeof search !== 'string' || typeof year !== 'string' ||
            typeof unlocked !== 'string'
        ) {
            return res.status(400).json({ message: 'error', error: 'Invalid query parameters' });
        }

        const pageNum = Math.max(1, parseInt(page, 10) || 1);
        const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
        const skip = (pageNum - 1) * limitNum;

        const filter = {};
        if (search.trim()) {
            const searchRegex = new RegExp(escapeRegex(search.trim()), 'i');
            filter.$or = [{ name: searchRegex }, { email: searchRegex }];
        }
        if (year.trim()) filter.passingOutYear = { $eq: year.trim() };
        if (unlocked === 'true') {
            filter.problemUnlocked = { $exists: true, $ne: null };
        } else if (unlocked === 'false') {
            filter.$and = [
                ...(filter.$and || []),
                { $or: [{ problemUnlocked: { $exists: false } }, { problemUnlocked: null }] }
            ];
        }

        const [data, total] = await Promise.all([
            Recruitment.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limitNum)
                .select('-__v')
                .lean(),
            Recruitment.countDocuments(filter)
        ]);

        return res.json({
            data,
            pagination: {
                total,
                page: pageNum,
                limit: limitNum,
                pages: Math.ceil(total / limitNum) || 1
            }
        });
    } catch (error) {
        console.error('Admin recruitment list error:', error);
        return res.status(500).json({ message: 'error', error: 'Failed to fetch recruitment data' });
    }
});

/**
 * GET /api/admin/recruitment/export
 * Download all recruitment candidates as a CSV file.
 */
router.get('/recruitment/export', requireApiKey, async (req, res) => {
    try {
        const candidates = await Recruitment.find()
            .sort({ createdAt: -1 })
            .select('-__v -_id')
            .lean();

        const headers = [
            'Name', 'Email', 'Mobile', 'Passing Year',
            'Problem Unlocked', 'Solution Submitted', 'Source', 'Registered At'
        ];

        const rows = candidates.map(c => [
            c.name, c.email, c.mobile, c.passingOutYear,
            c.problemUnlocked ?? '',
            c.submittedSolution ? 'Yes' : 'No',
            c.source ?? '',
            c.createdAt ? new Date(c.createdAt).toISOString() : ''
        ].map(escCsv).join(','));

        const csv = [headers.join(','), ...rows].join('\n');

        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="c3-recruitment-${Date.now()}.csv"`);
        return res.send(csv);
    } catch (error) {
        console.error('Recruitment export error:', error);
        return res.status(500).json({ message: 'error', error: 'Failed to export recruitment data' });
    }
});

export default router;
