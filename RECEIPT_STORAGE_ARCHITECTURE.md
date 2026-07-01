# Robust Server-Side Payment Receipt Storage Architecture (Issue #20)

## Executive Summary
This document establishes the high-concurrency, server-side storage architecture for payment receipts (UPI screenshots) in the `snist-website-bn` (`c3_backend`) repository.

Replacing Cloudflare R2 with local disk / mounted volume storage requires rigorous safeguards against memory exhaustion, directory inode bottlenecks, and orphaned incomplete uploads during traffic surges. This specification outlines the industry best practices to guarantee zero-downtime reliability under heavy concurrent load.

---

## 1. High-Concurrency & Resilience Best Practices

When hundreds of students submit payment screenshots simultaneously during registration surges, standard file upload patterns can crash the Node.js event loop or exhaust server resources. Contributors implementing upload routes **MUST** adhere to the following standards:

### A. Zero RAM Buffering (Streaming Disk Storage)
- **Anti-Pattern:** Using `multer.memoryStorage()` buffers incoming file chunks into Node.js heap memory. 50 concurrent users uploading 5 MB phone screenshots will instantly consume 250+ MB of RAM, triggering garbage collection pauses or `JavaScript heap out of memory` crashes.
- **Standard:** Use `multer.diskStorage()` or temporary disk streaming. Incoming multipart streams must be written directly to a temporary staging directory (`uploads/tmp/`) on disk.

### B. Atomic Staging Pipeline & Orphan Cleanup
To prevent corrupted files or disk clutter from aborted requests or failed database transactions:
1. **Stage:** Stream incoming uploads directly to a temporary path: `uploads/tmp/temp-<uuid>`.
2. **Validate:** Inspect file MIME types (`image/jpeg`, `image/png`, `image/webp`) and verify magic numbers before processing.
3. **Normalize & Compress:** Pass the temporary file through `sharp` to convert heavy smartphone photos into optimized WebP (`~150 KB`), stripping EXIF GPS metadata for privacy. Sharp executes out-of-process on the `libvips` C++ thread pool without blocking the Node.js event loop.
4. **Atomic Commit:** Once the MongoDB submission record is successfully validated and inserted, atomically move the processed image to its permanent partitioned directory using `fs.promises.rename()`.
5. **Rollback Guarantee:** Wrap the pipeline in `try ... finally` blocks. If database insertion or image processing fails at any point, immediately unlink (`fs.promises.unlink()`) the staged temporary file.

---

## 2. Partitioned Directory Structure

Most POSIX filesystems (ext4, XFS) suffer severe directory traversal performance degradation when a single folder contains >10,000 files. To prevent inode lock contention and slow admin dashboard lookups, permanent storage **MUST** be sharded by Year and Month:

```
uploads/
├── tmp/                                 # Temporary staging for active uploads
├── digital-india-hackathon/
│   ├── ideathon/
│   │   ├── payment-screenshots/
│   │   │   └── 2026/
│   │   │       └── 07/
│   │   │           └── utr_418293847561___phone_9876543210___team_cyber___a8f9b.webp
│   │   └── thumbnails/
│   │       └── 2026/
│   │           └── 07/
│   │               └── utr_418293847561___phone_9876543210___team_cyber___a8f9b_thumb.jpg
│   └── hackathon/
│       ├── payment-screenshots/
│       └── thumbnails/
└── pdfs/
```

### Directory Initialization
Use asynchronous, recursive directory creation (`fs.promises.mkdir(dirPath, { recursive: true })`) cached at the controller level so directory checks do not incur synchronous filesystem blocking on every request.

---

## 3. Deterministic Filename Naming Standard (Form Metadata Extraction)

To ensure payment screenshots can be audited rapidly by administrators—even during manual terminal inspections or offline CSV/ZIP reconciliations—the backend upload pipeline **MUST** generate filenames using critical identification fields extracted from the submitted form data (`FormData`).

### Standard Naming Format
```text
utr_<sanitized_utrId>___phone_<sanitized_phone>___<sanitized_team_or_name>___<short_hash>.<ext>
```
*Example:* `utr_418293847561___phone_9876543210___team_cyber_warriors___a8f9b.webp`

### Required Sanitization Logic
Never use raw user input directly in filesystem paths. Strip all non-alphanumeric characters:
```javascript
const cleanUtr = (utrId || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 24);
const cleanPhone = (phone || '').replace(/[^0-9]/g, '').slice(0, 15);
const cleanName = (teamName || name || 'unknown').toLowerCase().replace(/[^a-z0-9]/g, '_').slice(0, 30);
const shortHash = Math.random().toString(36).substring(2, 7);

const filename = `utr_${cleanUtr}___phone_${cleanPhone}___${cleanName}___${shortHash}.webp`;
```

### Verification & Audit Benefits
1. **Instant UTR Terminal Lookup:** Prefixing filenames with `utr_<utrId>` allows administrators navigating the server via SSH/bash to locate any transaction screenshot instantly (`ls *418293847561*` or `find . -name "*418293847561*"`) without querying MongoDB.
2. **Cross-Checking Submitter Identity:** Including sanitized phone numbers and team names enables manual human reconciliation directly from server file managers during high-stress registration verification windows.

---

## 4. Environment Configuration & Baremetal Portability

The file storage path is decoupled from the codebase using environment variables. Maintain the following setting in `.env`:

```env
# Root directory for storing uploaded files
# -----------------------------------------------------------------------------
# Local Laptop Testing:
UPLOAD_PATH=./uploads

# Baremetal / VPS Mounted Volume Deployment:
# UPLOAD_PATH=/mnt/storage/c3_uploads
```

When running locally on a developer laptop, images save inside `./uploads/digital-india-hackathon/...`. When deployed to the baremetal production server, pointing `UPLOAD_PATH` to a mounted RAID/SSD volume or SAN mount ensures persistent storage independent of container restarts.

---

## 5. Secure File Serving (`GET /api/admin/digital-india/screenshot`)

Receipts contain sensitive user UPI IDs and banking details. They **MUST NEVER** be served statically via public folders (`express.static()`).

### Access Control & Delivery Standard
1. **Authentication:** All requests to view receipts must provide a valid administrative secret in the `x-api-key` header or an authenticated session cookie.
2. **Path Sanitization:** Prevent directory traversal attacks (`../../etc/passwd`) by resolving filenames strictly relative to `UPLOAD_DIR` using `path.resolve(UPLOAD_DIR, filename)` and verifying the path starts with `UPLOAD_DIR`.
3. **Streaming Delivery:** Use `res.sendFile()` or `fs.createReadStream().pipe(res)` with proper caching headers (`Cache-Control: private, max-age=86400`) to stream image bytes efficiently to the admin dashboard.
4. **Backward Compatibility:** If a MongoDB record's `paymentScreenshotUrl` begins with `http://` or `https://` (legacy Cloudflare R2 receipts), either HTTP 302 redirect or stream the remote R2 URL directly.
