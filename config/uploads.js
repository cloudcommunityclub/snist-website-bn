import path from 'node:path';
import fs from 'node:fs';

export const UPLOAD_ROOT = process.env.UPLOAD_PATH
  ? path.resolve(process.env.UPLOAD_PATH)
  : path.resolve(process.cwd(), 'uploads');

export const MIN_DISK_SPACE = 100 * 1024 * 1024;

export async function assertDiskSpace(dirPath, requiredBytes = MIN_DISK_SPACE) {
  try {
    const stats = await fs.promises.statfs(dirPath);
    if (stats.available * stats.bsize < requiredBytes) {
      throw Object.assign(
        new Error('Insufficient disk space. Please try again later.'),
        { status: 503, code: 'DISK_FULL' }
      );
    }
  } catch (err) {
    if (err.code === 'DISK_FULL' || err.status === 503) throw err;
  }
}

export const FILE_SIZE_LIMITS = {
  SCREENSHOT: 5 * 1024 * 1024,
  PDF: 10 * 1024 * 1024,
  AVATAR: 2 * 1024 * 1024,
};

export const ALLOWED_MIMES = {
  IMAGE: ['image/png', 'image/jpeg', 'image/webp', 'image/avif'],
  PDF: ['application/pdf'],
};

export const UPLOAD_CATEGORIES = {
  DIGITAL_INDIA_IDEATHON: {
    name: 'digital-india-ideathon',
    relativePath: 'digital-india-hackathon/ideathon/payment-screenshots',
    thumbnailPath: 'digital-india-hackathon/ideathon/thumbnails',
    allowedMimes: ALLOWED_MIMES.IMAGE,
    maxSize: FILE_SIZE_LIMITS.SCREENSHOT,
  },
  DIGITAL_INDIA_HACKATHON: {
    name: 'digital-india-hackathon',
    relativePath: 'digital-india-hackathon/hackathon/payment-screenshots',
    thumbnailPath: 'digital-india-hackathon/hackathon/thumbnails',
    allowedMimes: ALLOWED_MIMES.IMAGE,
    maxSize: FILE_SIZE_LIMITS.SCREENSHOT,
  },
  PDF_UPLOAD: {
    name: 'pdfs',
    relativePath: 'pdfs',
    thumbnailPath: null,
    allowedMimes: ALLOWED_MIMES.PDF,
    maxSize: FILE_SIZE_LIMITS.PDF,
  },
};

export function resolveUploadPaths(category, date = new Date()) {
  const year = String(date.getFullYear());
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const dir = path.join(UPLOAD_ROOT, category.relativePath, year, month);
  const thumbnailDir = category.thumbnailPath
    ? path.join(UPLOAD_ROOT, category.thumbnailPath, year, month)
    : null;
  return { dir, thumbnailDir };
}
