import { mkdtempSync, existsSync, mkdirSync, rmSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const testDir = resolve(__dirname, '.test-tmp');
if (!existsSync(testDir)) mkdirSync(testDir);

process.env.UPLOAD_PATH = mkdtempSync(join(testDir, 'c3-uploads-'));
process.env.API_KEY = 'test-api-key';
process.env.NODE_ENV = 'test';
