import { Router } from "express";
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';
import Recruitment from "../models/recruitment.js";
import { requireApiKey } from "../middleware/auth.js";

dotenv.config();
const router = Router();

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'error', error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * GET /api/recruitment
 * Returns API information
 */
router.get("/", (req, res) => {
    res.status(200).json({
        message: "Recruitment API is working",
        instructions: "Use POST endpoints to interact with the recruitment flow",
        endpoints: {
            unlock: "POST /api/recruitment/unlock - Submit details to unlock challenges",
            submit: "POST /api/recruitment/submit - Record a PR submission (sets submittedSolution: true)"
        }
    });
});

/**
 * POST /api/recruitment/unlock
 * Save candidate information from recruitment page
 * Protected with API key
 */
router.post("/unlock", apiLimiter, requireApiKey, async (req, res) => {
    try {
        const { name, email: rawEmail, mobile, passingOutYear, problemId } = req.body;

        // Validate required fields and explicitly check types to prevent NoSQL injection via objects
        if (!name || !rawEmail || !mobile || !passingOutYear ||
            typeof name !== 'string' || typeof rawEmail !== 'string' ||
            typeof mobile !== 'string' || typeof passingOutYear !== 'string') {
            return res.status(400).json({
                message: "error",
                error: "Name, email, mobile, and passing out year are required text fields"
            });
        }

        const email = rawEmail.trim();

        // Limit length to prevent ReDoS
        if (email.length > 254 || name.length > 200 || mobile.length > 50) {
            return res.status(400).json({
                message: "error",
                error: "Input fields exceed maximum allowed length"
            });
        }

        // Basic email validation
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                message: "error",
                error: "Invalid email format"
            });
        }

        // Domain validation - accept any subdomain ending in .sreenidhi.edu.in or .shu.edu.in
        const emailDomain = email.toLowerCase().split('@')[1];

        if (!emailDomain || (!emailDomain.endsWith('sreenidhi.edu.in') && !emailDomain.endsWith('shu.edu.in'))) {
            return res.status(400).json({
                message: "error",
                error: "Only emails from sreenidhi.edu.in or shu.edu.in domains are accepted"
            });
        }

        // Mobile number format validation (Indian 10-digit)
        const mobileRegex = /^[6-9]\d{9}$/;
        if (!mobileRegex.test(mobile.replace(/\s+/g, '').replace(/^\+91/, ''))) {
            return res.status(400).json({
                message: "error",
                error: "Invalid mobile number format. Please provide a valid 10-digit Indian mobile number"
            });
        }

        // Save or update candidate data
        // Using upsert pattern to allow retries
        const candidateData = {
            name,
            email,
            mobile,
            passingOutYear,
            source: "Recruitment Page",
            updatedAt: new Date()
        };

        if (problemId && typeof problemId === 'string') {
            candidateData.problemUnlocked = problemId;
        }

        const candidate = await Recruitment.findOneAndUpdate(
            { email: { $eq: email } },
            { $set: candidateData },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        );

        console.log(`✅ Recruitment candidate saved: ${name} (${email})`);

        // Return success response
        return res.status(200).json({
            message: "success",
            data: {
                name,
                email,
                unlocked: true
            }
        });

    } catch (error) {
        console.error('Recruitment unlock error:', error);
        return res.status(500).json({
            message: "error",
            error: "An error occurred while processing your request"
        });
    }
});

/**
 * POST /api/recruitment/submit
 * Mark a candidate's solution as submitted
 * Protected with API key
 */
router.post('/submit', requireApiKey, async (req, res) => {
    try {
        const { email: rawEmail, problemId, prUrl } = req.body;

        if (!rawEmail || typeof rawEmail !== 'string') {
            return res.status(400).json({ message: 'error', error: 'Email is required' });
        }

        const email = rawEmail.trim().toLowerCase();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'error', error: 'Invalid email format' });
        }

        const updateData = {
            submittedSolution: true,
            updatedAt: new Date()
        };
        if (problemId && typeof problemId === 'string') updateData.problemUnlocked = problemId;
        if (prUrl && typeof prUrl === 'string' && prUrl.length < 500) updateData.prUrl = prUrl;

        const candidate = await Recruitment.findOneAndUpdate(
            { email: { $eq: email } },
            { $set: updateData },
            { new: true }
        );

        if (!candidate) {
            return res.status(404).json({ message: 'error', error: 'Candidate not found. Please unlock a challenge first.' });
        }

        console.log(`✅ Submission recorded: ${email}`);
        return res.status(200).json({
            message: 'success',
            data: { email, submittedSolution: true }
        });

    } catch (error) {
        console.error('Submission error:', error);
        return res.status(500).json({ message: 'error', error: 'An error occurred' });
    }
});

export default router;
