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
app.use(helmet());
const PORT = process.env.PORT || 5000;

// CORS configuration
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:3000', 'https://snist.cloudcommunityclub.tech', 'https://cloudcommunityclub-c3.vercel.app'];

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

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  const headersToLog = { ...req.headers };
  if (headersToLog['x-api-key']) headersToLog['x-api-key'] = '[REDACTED]';
  console.log('Headers:', headersToLog);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', req.body);
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

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'error',
    error: 'Something went wrong!'
  });
});

// Connect to MongoDB
if (process.env.NODE_ENV !== 'test') {
  mongoose.connect(process.env.MONGO_URI)
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
