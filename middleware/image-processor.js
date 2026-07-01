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

  const targetExt = options.targetFilename ? path.extname(options.targetFilename) : ext;
  const targetPath = options.targetFilename
    ? path.join(path.dirname(filePath), options.targetFilename)
    : filePath;

  switch (targetExt) {
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

  await fs.unlink(filePath).catch(() => {});
  await fs.rename(tempPath, targetPath);

  const finalPath = targetPath;
  const optimizedStat = await fs.stat(finalPath).catch(() => ({ size: originalSize }));
  const optimizedSize = optimizedStat.size;

  let thumbnailPath = null;

  if (options.thumbnailDir) {
    await fs.mkdir(options.thumbnailDir, { recursive: true }).catch(() => {});
    const thumbnailFilename = options.targetFilename
      ? `${path.basename(options.targetFilename, targetExt)}_thumb.jpg`
      : `${path.basename(basePath)}_thumb.jpg`;
    thumbnailPath = path.join(options.thumbnailDir, thumbnailFilename);

    await sharp(finalPath)
      .resize(thumbWidth, null, { fit: 'cover' })
      .jpeg({ quality: thumbQuality })
      .toFile(thumbnailPath);
  }

  return {
    originalPath: finalPath,
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

      let targetFilename = undefined;
      if (req.body && (req.body.utrId || req.body.phone || req.body.teamName || req.body.name)) {
        const cleanUtr = (req.body.utrId || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 24);
        const cleanPhone = (req.body.phone || '').replace(/[^0-9]/g, '').slice(0, 15);
        const cleanName = (req.body.teamName || req.body.name || 'sub').toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 30);
        const shortHash = path.basename(req.file.path).replace(/\.[^/.]+$/, '').slice(0, 8);
        targetFilename = `utr_${cleanUtr || 'none'}___phone_${cleanPhone || 'none'}___${cleanName}___${shortHash}.webp`;
      }

      const result = await optimizeImage(req.file.path, { ...options, thumbnailDir, targetFilename });

      req.fileOptimization = result;

      req.file.path = result.originalPath;
      req.file.optimizedPath = result.originalPath;
      req.file.thumbnailPath = result.thumbnailPath;

      next();
    } catch (err) {
      if (req.file && req.file.path) {
        await fs.unlink(req.file.path).catch(() => {});
      }
      err.status = err.status || 400;
      err.message = `Image optimization error: ${err.message}`;
      next(err);
    }
  };
}

export function toRelativeUrl(absolutePath) {
  if (!absolutePath) return null;
  const relativePath = path.relative(UPLOAD_ROOT, absolutePath);
  return `/uploads/${relativePath.replace(/\\/g, '/')}`;
}
