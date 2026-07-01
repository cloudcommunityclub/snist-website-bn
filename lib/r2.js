import { S3Client, GetObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';

let client = null;
let bucketName = null;
let configured = false;

function initR2() {
  const endpoint = process.env.R2_ENDPOINT;
  const accessKeyId = process.env.R2_ACCESS_KEY_ID;
  const secretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
  bucketName = process.env.R2_BUCKET_NAME || 'c3-uploads';

  if (!endpoint || !accessKeyId || !secretAccessKey) {
    console.warn('⚠️  R2 credentials not configured (R2_ENDPOINT, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY). Old R2-hosted screenshots will not be served.');
    return false;
  }

  client = new S3Client({
    region: 'auto',
    endpoint,
    credentials: { accessKeyId, secretAccessKey },
    requestHandler: undefined,
  });

  configured = true;
  console.log('✅ R2 client initialized for old screenshot fallback');
  return true;
}

function isConfigured() {
  return configured;
}

function getBucketName() {
  return bucketName;
}

async function fetchFromR2(key) {
  if (!configured) {
    initR2();
    if (!configured) return null;
  }

  try {
    const command = new GetObjectCommand({
      Bucket: bucketName,
      Key: key,
    });
    const response = await client.send(command);
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    return {
      body: Buffer.concat(chunks),
      contentType: response.ContentType || 'application/octet-stream',
    };
  } catch (err) {
    if (err instanceof NoSuchKey) {
      console.warn(`⚠️  R2 object not found: ${key}`);
      return null;
    }
    console.error('❌ R2 fetch error:', err.message);
    return null;
  }
}

export { initR2, isConfigured, fetchFromR2, getBucketName };
