import sharp from 'sharp';
import path from 'node:path';
import fs from 'node:fs/promises';
import { UPLOAD_ROOT, resolveUploadPaths } from '../config/uploads.js';

const DEFAULTS = {
  MAX_DIMENSION: 1920,
  QUALITY: 80,
  THUMB_WIDTH: 320,
  THUMB_QUALITY: 60,
};

export async function optimizeImage(filePath, options = {}) {
  const {
    maxDimension = DEFAULTS.MAX_DIMENSION,
    quality = DEFAULTS.QUALITY,
    thumbWidth = DEFAULTS.THUMB_WIDTH,
    thumbQuality = DEFAULTS.THUMB_QUALITY,
  } = options;

  const ext = path.extname(filePath).toLowerCase();
  const basePath = filePath.replace(ext, '');
  const tempPath = `${basePath}_optimized${ext}`;

  const originalStat = await fs.stat(filePath).catch(() => ({ size: 0 }));
  const originalSize = originalStat.size;

  const metadata = await sharp(filePath).metadata();

  const pipeline = sharp(filePath)
    .rotate()
    .resize(maxDimension, maxDimension, {
      fit: 'inside',
      withoutEnlargement: true,
    });

  switch (ext) {
    case '.png':
      pipeline.png({ compressionLevel: 9, palette: true });
      break;
    case '.webp':
      pipeline.webp({ quality });
      break;
    case '.avif':
      pipeline.avif({ quality });
      break;
    case '.jpg':
    case '.jpeg':
    default:
      pipeline.jpeg({ quality, mozjpeg: true });
      break;
  }

  await pipeline.toFile(tempPath);

  await fs.unlink(filePath);
  await fs.rename(tempPath, filePath);

  const optimizedStat = await fs.stat(filePath).catch(() => ({ size: originalSize }));
  const optimizedSize = optimizedStat.size;

  let thumbnailPath = null;

  if (options.thumbnailDir) {
    await fs.mkdir(options.thumbnailDir, { recursive: true }).catch(() => {});
    const thumbnailFilename = `${path.basename(basePath)}_thumb.jpg`;
    thumbnailPath = path.join(options.thumbnailDir, thumbnailFilename);

    await sharp(filePath)
      .resize(thumbWidth, null, { fit: 'cover' })
      .jpeg({ quality: thumbQuality })
      .toFile(thumbnailPath);
  }

  return {
    originalPath: filePath,
    thumbnailPath,
    originalSize,
    optimizedSize,
    savingsPercent: originalSize > 0
      ? Math.round((1 - optimizedSize / originalSize) * 100)
      : 0,
    width: metadata.width || 0,
    height: metadata.height || 0,
  };
}

export function optimizeUploadedImage(options = {}) {
  return async (req, _res, next) => {
    if (!req.file) return next();

    try {
      let thumbnailDir;
      if (options.category) {
        const paths = resolveUploadPaths(options.category);
        thumbnailDir = paths.thumbnailDir;
      }

      const result = await optimizeImage(req.file.path, { ...options, thumbnailDir });

      req.fileOptimization = result;

      req.file.optimizedPath = result.originalPath;
      req.file.thumbnailPath = result.thumbnailPath;

      next();
    } catch (err) {
      next(err);
    }
  };
}

export function toRelativeUrl(absolutePath) {
  if (!absolutePath) return null;
  const relativePath = path.relative(UPLOAD_ROOT, absolutePath);
  return `/uploads/${relativePath.replace(/\\/g, '/')}`;
}
