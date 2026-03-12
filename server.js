import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import registerRoutes from './routes/register.js';
import adminRoutes from './routes/admin.js';
import recruitmentRoutes from './routes/recruitment.js';
import dns from 'node:dns';

// Force IPv4 resolution to avoid timeouts in some container environments (like Render)
dns.setDefaultResultOrder('ipv4first');

dotenv.config();

const app = express();

/**
 * SECURITY NOTE: This API uses header-based authentication (x-api-key) which provides
 * inherent CSRF protection. The 'credentials: true' CORS setting exists for compatibility
 * but must be reviewed before any cookie-based authentication is introduced (VA-007).
 */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
}));

const PORT = process.env.PORT || 5000;

// CORS configuration — localhost is excluded in production as a fail-safe (VA-010)
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : (process.env.NODE_ENV === 'production'
    ? ['https://snist.cloudcommunityclub.tech', 'https://cloudcommunityclub-c3.vercel.app']
    : ['http://localhost:3000', 'https://snist.cloudcommunityclub.tech', 'https://cloudcommunityclub-c3.vercel.app']);

const corsOptions = {
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Redact PII and sensitive fields before logging (VA-011)
const SENSITIVE_FIELDS = ['email', 'mobile', 'password', 'token', 'rollNumber'];
function redactBody(body) {
  const redacted = { ...body };
  for (const field of SENSITIVE_FIELDS) {
    if (redacted[field] !== undefined) redacted[field] = '[REDACTED]';
  }
  return redacted;
}

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  const headersToLog = { ...req.headers };
  if (headersToLog['x-api-key']) headersToLog['x-api-key'] = '[REDACTED]';
  console.log('Headers:', headersToLog);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', redactBody(req.body));
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Routes
app.use('/api/register', registerRoutes);
app.use('/api/recruitment', recruitmentRoutes);

// Admin routes — protected by requireApiKey middleware within the router
app.use('/api/admin', adminRoutes);

// Error handling middleware — stack traces are never exposed in production (VA-005)
app.use((err, req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  } else {
    console.error(`Error: ${err.message} | Path: ${req.path} | IP: ${req.ip}`);
  }
  res.status(500).json({
    message: 'error',
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// Validate MongoDB URI format before connecting (VA-008)
function validateMongoUri(uri) {
  if (!uri) throw new Error('MONGO_URI environment variable is required');
  try {
    const url = new URL(uri);
    if (!['mongodb:', 'mongodb+srv:'].includes(url.protocol)) {
      throw new Error('Invalid MongoDB URI protocol');
    }
    return uri;
  } catch {
    throw new Error('Invalid MONGO_URI format');
  }
}

// Connect to MongoDB
if (process.env.NODE_ENV !== 'test') {
  const validatedMongoUri = validateMongoUri(process.env.MONGO_URI);
  mongoose.connect(validatedMongoUri)
    .then(() => {
      console.log('Connected to MongoDB');
      // Only start server after successful DB connection
      app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
      });
    })
    .catch(err => {
      console.error('MongoDB connection error:', err);
      process.exit(1);
    });
  mongoose.connection.on('disconnected', () => console.error('⚠️  MongoDB disconnected'));
  mongoose.connection.on('reconnected', () => console.info('✅ MongoDB reconnected'));
}

export default app;
