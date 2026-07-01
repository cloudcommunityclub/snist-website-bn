import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { UPLOAD_CATEGORIES, resolveUploadPaths, assertDiskSpace } from '../config/uploads.js';

function ensureDirectory(dirPath) {
  if (!dirPath) return dirPath;
  fs.mkdirSync(dirPath, { recursive: true });
  return dirPath;
}

function createCategoryStorage(categoryConfig) {
  return multer.diskStorage({
    destination(_req, _file, cb) {
      const { dir, thumbnailDir } = resolveUploadPaths(categoryConfig);
      ensureDirectory(dir);
      if (thumbnailDir) ensureDirectory(thumbnailDir);
      assertDiskSpace(dir).then(() => cb(null, dir)).catch((err) => cb(err));
    },
    filename(_req, file, cb) {
      const ext = path.extname(file.originalname).toLowerCase() || '.png';
      const uuid = crypto.randomUUID();
      cb(null, `${uuid}${ext}`);
    },
  });
}

function createFileFilter(allowedMimes) {
  return (_req, file, cb) => {
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        Object.assign(
          new Error(
            `Unsupported file type "${file.mimetype}". ` +
            `Allowed types: ${allowedMimes.join(', ')}`
          ),
          { status: 400, code: 'UNSUPPORTED_FILE_TYPE' }
        )
      );
    }
  };
}

export const uploadIdeathonScreenshot = multer({
  storage: createCategoryStorage(UPLOAD_CATEGORIES.DIGITAL_INDIA_IDEATHON),
  limits: { fileSize: UPLOAD_CATEGORIES.DIGITAL_INDIA_IDEATHON.maxSize },
  fileFilter: createFileFilter(UPLOAD_CATEGORIES.DIGITAL_INDIA_IDEATHON.allowedMimes),
});

export const uploadHackathonScreenshot = multer({
  storage: createCategoryStorage(UPLOAD_CATEGORIES.DIGITAL_INDIA_HACKATHON),
  limits: { fileSize: UPLOAD_CATEGORIES.DIGITAL_INDIA_HACKATHON.maxSize },
  fileFilter: createFileFilter(UPLOAD_CATEGORIES.DIGITAL_INDIA_HACKATHON.allowedMimes),
});

export const uploadPdf = multer({
  storage: createCategoryStorage(UPLOAD_CATEGORIES.PDF_UPLOAD),
  limits: { fileSize: UPLOAD_CATEGORIES.PDF_UPLOAD.maxSize },
  fileFilter: createFileFilter(UPLOAD_CATEGORIES.PDF_UPLOAD.allowedMimes),
});

export function multerErrorHandler(err, _req, res, next) {
  if (!err) return next();
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        message: 'error',
        error: 'File too large. Maximum allowed upload size exceeded.',
      });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({
        message: 'error',
        error: 'Unexpected file field. Check the field name used in the form.',
      });
    }
    return res.status(400).json({
      message: 'error',
      error: `Upload error: ${err.message}`,
    });
  }
  if (err.status) {
    return res.status(err.status).json({
      message: 'error',
      error: err.message,
    });
  }
  next(err);
}
