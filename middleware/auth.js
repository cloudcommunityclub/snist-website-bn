import crypto from 'node:crypto';

export function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({ message: 'error', error: 'API key is required' });
  }

  try {
    const expected = process.env.API_KEY;
    if (!expected) {
      console.error('API_KEY is not configured in environment variables');
      return res.status(500).json({ message: 'error', error: 'Server configuration error' });
    }

    const keyBuffer = Buffer.from(String(apiKey));
    const expectedBuffer = Buffer.from(expected);

    if (keyBuffer.length !== expectedBuffer.length) {
      return res.status(403).json({ message: 'error', error: 'Invalid API key' });
    }

    if (!crypto.timingSafeEqual(keyBuffer, expectedBuffer)) {
      return res.status(403).json({ message: 'error', error: 'Invalid API key' });
    }

    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ message: 'error', error: 'Authentication error' });
  }
}
