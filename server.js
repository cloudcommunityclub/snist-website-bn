import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import registerRoutes from './routes/register.js';
import adminRoutes from './routes/admin.js';
import recruitmentRoutes from './routes/recruitment.js';
import digitalIndiaRoutes from './routes/digital-india.js';
import adminDigitalIndiaRoutes from './routes/admin/digital-india.js';
import { multerErrorHandler } from './middleware/uploader.js';
import dns from 'node:dns';

dns.setDefaultResultOrder('ipv4first');

dotenv.config();

const app = express();

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
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
}));

const PORT = process.env.PORT || 5000;

const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : (process.env.NODE_ENV === 'production'
    ? ['https://snist.cloudcommunityclub.tech', 'https://cloudcommunityclub-c3.vercel.app']
    : ['http://localhost:3000', 'https://snist.cloudcommunityclub.tech', 'https://cloudcommunityclub-c3.vercel.app']);

const corsOptions = {
  origin: allowedOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

const SENSITIVE_FIELDS = ['email', 'mobile', 'password', 'token', 'rollNumber'];
function redactBody(body) {
  const redacted = { ...body };
  for (const field of SENSITIVE_FIELDS) {
    if (redacted[field] !== undefined) redacted[field] = '[REDACTED]';
  }
  return redacted;
}

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

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.use('/api/register', registerRoutes);
app.use('/api/recruitment', recruitmentRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/digital-india', digitalIndiaRoutes);
app.use('/api/admin/digital-india', adminDigitalIndiaRoutes);

app.use(multerErrorHandler);

app.use((err, req, res, next) => {
  if (process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  } else {
    console.error(`Error: ${err.message} | Path: ${req.path} | IP: ${req.ip}`);
  }
  res.status(500).json({
    message: 'error',
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});

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

if (process.env.NODE_ENV !== 'test') {
  const validatedMongoUri = validateMongoUri(process.env.MONGO_URI);
  mongoose.connect(validatedMongoUri)
    .then(() => {
      console.log('Connected to MongoDB');
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
