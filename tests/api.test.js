import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../server.js';
import { jest } from '@jest/globals';
import Registration2026 from '../models/registration2026.js';

// Set timeout to avoid issues with slow CI environments
jest.setTimeout(30000);

let mongoServer;
const TEST_API_KEY = 'test-api-key';

beforeAll(async () => {
  process.env.API_KEY = TEST_API_KEY;
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

beforeEach(async () => {
  await Registration2026.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

describe('API Tests', () => {
  test('GET /health', async () => {
    const res = await request(app).get('/health');
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('GET /api/register', async () => {
    const res = await request(app).get('/api/register');
    expect(res.statusCode).toBe(200);
    expect(res.body.message).toBe('Registration API is working');
  });

  // Test registration endpoint (validation)
  test('POST /api/register - Validation Error', async () => {
    const res = await request(app)
      .post('/api/register')
      .set('x-api-key', TEST_API_KEY)
      .send({});
    expect(res.statusCode).toBe(400);
  });

  // Test registration endpoint (success)
  test('POST /api/register - Success', async () => {
     // The code swallows email errors so it should succeed even if email fails.

     const payload = {
        name: "Test User",
        email: "test@example.com",
        mobile: "1234567890",
        rollNumber: "123",
        department: "CSE",
        year: "3",
        interests: ["Cloud"],
        experience: "None",
        expectations: "Learn",
        referral: "None"
     };

     const res = await request(app)
       .post('/api/register')
       .set('x-api-key', TEST_API_KEY)
       .send(payload);
     expect(res.statusCode).toBe(200);
     expect(res.body.message).toBe("success");

     // Verify it is in DB
     const member = await Registration2026.findOne({ email: "test@example.com" });
     expect(member).toBeTruthy();
     expect(member.name).toBe("Test User");
  });
});
