/**
 * Authentication Middleware
 * Validates API key from request headers
 */

import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';

// Separate rate limiter for authentication failures to prevent brute-force attacks
const authFailureLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Only 5 failed attempts per 15 minutes per IP
    skipSuccessfulRequests: true,
    message: { message: 'error', error: 'Too many failed authentication attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

export function requireApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'];
    const serverApiKey = process.env.API_KEY;

    // Check if API key is configured
    if (!serverApiKey) {
        console.error('⚠️  SECURITY WARNING: API_KEY not configured in environment variables!');
        return res.status(500).json({
            message: 'error',
            error: 'Server configuration error'
        });
    }

    // Validate API key using timing-safe comparison to prevent timing attacks
    if (!apiKey || apiKey.length !== serverApiKey.length || !crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(serverApiKey))) {
        // Apply auth failure rate limiter before responding
        return authFailureLimiter(req, res, () => {
            console.warn(`🚫 Unauthorized access attempt from IP: ${req.ip}`);
            return res.status(401).json({
                message: 'error',
                error: 'Unauthorized: Invalid or missing API key'
            });
        });
    }

    // API key is valid, continue to next middleware
    next();
}
