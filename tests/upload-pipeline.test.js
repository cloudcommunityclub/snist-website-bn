import request from 'supertest';
import mongoose from 'mongoose';
import fs from 'node:fs/promises';
import path from 'node:path';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../server.js';
import { jest } from '@jest/globals';
import sharp from 'sharp';
import IdeathonSubmission from '../models/digital-india-ideathon.js';

jest.setTimeout(60000);

let mongoServer;
const TEST_API_KEY = 'test-api-key';

async function createTestPng() {
  return sharp({
    create: { width: 100, height: 100, channels: 3, background: { r: 66, g: 133, b: 244 } },
  }).png().toBuffer();
}

let testPng;

const validFields = {
  name: 'Test User',
  college: 'SNIST',
  email: 'test@example.com',
  phone: '9876543210',
  idea: 'A cloud-native platform for managing college club activities end-to-end with automated workflows.',
  utrId: 'UTR123456789',
  teamName: 'CloudNinjas',
  domain: 'Web Development',
  teamSize: '3',
  teamMembers: JSON.stringify([{ name: 'Member 1', email: 'member1@test.com' }]),
};

beforeAll(async () => {
  testPng = await createTestPng();
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

beforeEach(async () => {
  await IdeathonSubmission.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
  if (process.env.UPLOAD_PATH) {
    await fs.rm(process.env.UPLOAD_PATH, { recursive: true, force: true });
  }
});

describe('Upload Pipeline', () => {
  test('rejects file larger than size limit', async () => {
    const largeBuffer = Buffer.alloc(16 * 1024 * 1024);
    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'Test')
      .field('college', 'SNIST')
      .field('email', 'large@test.com')
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', 'UTR-LARGE-001')
      .field('teamName', 'LargeFileTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', largeBuffer, 'screenshot.png');

    expect(res.status).toBe(413);
    expect(res.body.message).toBe('error');
    expect(res.body.error).toContain('File too large');
  });

  test('rejects invalid MIME type', async () => {
    const textBuffer = Buffer.from('not an image, just some text', 'utf-8');
    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'Test')
      .field('college', 'SNIST')
      .field('email', 'mime@test.com')
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', 'UTR-MIME-001')
      .field('teamName', 'MimeTestTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', textBuffer, { filename: 'fake.png', contentType: 'image/png' });

    expect(res.status).toBe(400);
  });

  test('successfully uploads, optimizes and persists a valid PNG', async () => {
    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', validFields.name)
      .field('college', validFields.college)
      .field('email', validFields.email)
      .field('phone', validFields.phone)
      .field('idea', validFields.idea)
      .field('utrId', validFields.utrId)
      .field('teamName', validFields.teamName)
      .field('domain', validFields.domain)
      .field('teamSize', validFields.teamSize)
      .field('teamMembers', validFields.teamMembers)
      .attach('screenshot', testPng, 'screenshot.png');

    expect(res.status).toBe(201);
    expect(res.body.message).toBe('success');
    expect(res.body.data).toHaveProperty('referralCode');
    expect(res.body.data).toHaveProperty('paymentScreenshotUrl');
    expect(res.body.data.paymentScreenshotUrl).toMatch(/^\/uploads\//);

    const saved = await IdeathonSubmission.findOne({ email: validFields.email }).lean();
    expect(saved).toBeTruthy();
    expect(saved.name).toBe(validFields.name);
    expect(saved.utrId).toBe(validFields.utrId);
    expect(saved.teamName).toBe(validFields.teamName);
    expect(saved.paymentScreenshotUrl).toMatch(/^\/uploads\//);
    expect(saved.thumbnailUrl).toMatch(/^\/uploads\//);

    const absolutePath = path.join(
      process.env.UPLOAD_PATH,
      saved.paymentScreenshotUrl.replace('/uploads/', '')
    );
    const stats = await fs.stat(absolutePath);
    expect(stats.size).toBeGreaterThan(0);
    expect(stats.size).toBeLessThan(testPng.length);
  });

  test('rejects duplicate email', async () => {
    const email = 'duplicate-email@test.com';
    await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'First')
      .field('college', 'SNIST')
      .field('email', email)
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', 'UTR-DUP-EMAIL-01')
      .field('teamName', 'FirstTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'Second')
      .field('college', 'SNIST')
      .field('email', email)
      .field('phone', '9876543211')
      .field('idea', 'B'.repeat(50))
      .field('utrId', 'UTR-DUP-EMAIL-02')
      .field('teamName', 'SecondTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('email already exists');
  });

  test('rejects duplicate UTR ID', async () => {
    const utrId = 'UTR-DUP-UT-001';
    await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'First')
      .field('college', 'SNIST')
      .field('email', 'utr-dup-1@test.com')
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', utrId)
      .field('teamName', 'FirstUtrTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'Second')
      .field('college', 'SNIST')
      .field('email', 'utr-dup-2@test.com')
      .field('phone', '9876543211')
      .field('idea', 'B'.repeat(50))
      .field('utrId', utrId)
      .field('teamName', 'SecondUtrTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('UTR ID already exists');
  });

  test('rejects duplicate team name', async () => {
    const teamName = 'DuplicateTeamName';
    await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'First')
      .field('college', 'SNIST')
      .field('email', 'team-dup-1@test.com')
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', 'UTR-DUP-TEAM-01')
      .field('teamName', teamName)
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', 'Second')
      .field('college', 'SNIST')
      .field('email', 'team-dup-2@test.com')
      .field('phone', '9876543211')
      .field('idea', 'B'.repeat(50))
      .field('utrId', 'UTR-DUP-TEAM-02')
      .field('teamName', teamName)
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('team with this name already exists');
  });

  test('requires all mandatory fields', async () => {
    const res = await request(app)
      .post('/api/digital-india/ideathon/submit')
      .field('name', '')
      .field('college', 'SNIST')
      .field('email', 'missing@test.com')
      .field('phone', '9876543210')
      .field('idea', 'A'.repeat(50))
      .field('utrId', 'UTR-MISSING-001')
      .field('teamName', 'MissingFieldsTeam')
      .field('domain', 'Web')
      .field('teamSize', '1')
      .attach('screenshot', testPng, 'screenshot.png');

    expect(res.status).toBe(400);
    expect(res.body.message).toBe('error');
  });

  test('generates unique referral codes', async () => {
    const codes = new Set();
    for (let i = 0; i < 5; i++) {
      const res = await request(app)
        .post('/api/digital-india/ideathon/submit')
        .field('name', `User ${i}`)
        .field('college', 'SNIST')
        .field('email', `ref-test-${i}@test.com`)
        .field('phone', `98765432${String(i).padStart(2, '0')}`)
        .field('idea', 'A'.repeat(50) + i)
        .field('utrId', `UTR-REF-${String(i).padStart(3, '0')}`)
        .field('teamName', `RefTeam${i}`)
        .field('domain', 'Web')
        .field('teamSize', '1')
        .attach('screenshot', testPng, 'screenshot.png');

      expect(res.status).toBe(201);
      codes.add(res.body.data.referralCode);
    }

    expect(codes.size).toBe(5);
  });
});
