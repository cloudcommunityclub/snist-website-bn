import fs from 'node:fs/promises';
import { fileTypeFromFile } from 'file-type';
import { ALLOWED_MIMES } from '../config/uploads.js';

export async function assertValidFileType(filePath, allowedMimes = ALLOWED_MIMES.IMAGE) {
  let type;

  try {
    type = await fileTypeFromFile(filePath);
  } catch (err) {
    await fs.unlink(filePath).catch(() => {});
    throw Object.assign(
      new Error(`Could not read file to verify its type: ${err.message}`),
      { status: 400, code: 'FILE_READ_ERROR' }
    );
  }

  if (!type) {
    await fs.unlink(filePath).catch(() => {});
    throw Object.assign(
      new Error(
        'Unable to verify file type. The file may be corrupted or ' +
        'has an unsupported format.'
      ),
      { status: 400, code: 'UNKNOWN_FILE_TYPE' }
    );
  }

  if (!allowedMimes.includes(type.mime)) {
    await fs.unlink(filePath).catch(() => {});
    throw Object.assign(
      new Error(
        `File content detected as "${type.mime}" which is not allowed. ` +
        `Allowed types: ${allowedMimes.join(', ')}`
      ),
      { status: 400, code: 'CONTENT_MISMATCH' }
    );
  }

  return type;
}

export function validateUploadedFile(allowedMimes) {
  return async (req, _res, next) => {
    const file = req.file;

    if (!file) return next();

    try {
      const detected = await assertValidFileType(
        file.path,
        allowedMimes ?? ALLOWED_MIMES.IMAGE
      );

      file.detectedMime = detected.mime;
      file.detectedExt = detected.ext;

      next();
    } catch (err) {
      next(err);
    }
  };
}
