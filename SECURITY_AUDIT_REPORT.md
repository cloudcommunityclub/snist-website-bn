# Security Audit Report: C3 Backend

**Audit Date:** 2026-03-12
**Auditor:** Security Auditor (Automated Analysis)
**Project:** Cloud Community Club (C3) Backend API
**Technology Stack:** Node.js, Express.js 5.2.1, MongoDB/Mongoose, Gmail API
**Repository:** c3_backend

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Methodology](#scope-and-methodology)
3. [Vulnerability Summary](#vulnerability-summary)
4. [Critical Findings](#critical-findings)
5. [High Severity Findings](#high-severity-findings)
6. [Medium Severity Findings](#medium-severity-findings)
7. [Low Severity Findings](#low-severity-findings)
8. [Informational Findings](#informational-findings)
9. [OWASP Top 10 Compliance](#owasp-top-10-2021-compliance-checklist)
10. [Remediation Roadmap](#priority-remediation-roadmap)
11. [Conclusion](#conclusion)

---

## Executive Summary

The C3 Backend demonstrates **good security practices** with proper input validation, rate limiting, and API key authentication. The codebase shows evidence of security-conscious development including timing-safe comparisons, NoSQL injection prevention, and proper HTML escaping.

However, several areas require attention to strengthen the overall security posture, particularly around authentication failure handling and information disclosure.

### Risk Assessment

| Severity | Count | Risk Level |
|----------|-------|------------|
| Critical | 0 | None |
| High | 3 | Elevated |
| Medium | 5 | Moderate |
| Low | 4 | Low |
| Informational | 3 | Informational |

**Overall Security Rating: B+ (Good)**

---

## Scope and Methodology

### Scope
- Source code analysis of all application files
- Configuration review (server.js, middleware, routes, models)
- Dependency version analysis
- Authentication and authorization mechanisms
- Input validation and sanitization
- Security headers and CORS configuration

### Methodology
This audit follows the OWASP Application Security Verification Standard (ASVS) and includes:
- Static Application Security Testing (SAST) via code review
- Configuration analysis
- Dependency analysis
- Authentication flow review
- Input validation testing

---

## Vulnerability Summary

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| VA-001 | API Key Auth Lacks Failure Rate Limiting | High | Open |
| VA-002 | Public Email Enumeration Endpoint | High | Open |
| VA-003 | OAuth Credentials in Memory Singleton | High | Open |
| VA-004 | Missing CSP Configuration | Medium | Open |
| VA-005 | Error Messages May Leak Information | Medium | Open |
| VA-006 | Missing Query Parameter Length Limits | Medium | Open |
| VA-007 | No CSRF Protection Documentation | Medium | Open |
| VA-008 | MongoDB URI Without Validation | Medium | Open |
| VA-009 | Missing HSTS Preload | Low | Open |
| VA-010 | CORS Wildcard Fallback | Low | Open |
| VA-011 | Request Body Logged in Plain Text | Low | Open |
| VA-012 | Missing Index Documentation | Low | Open |

---

## Critical Findings

**No critical vulnerabilities were identified.**

---

## High Severity Findings

### VA-001: API Key Authentication Lacks Rate Limiting on Auth Failures

| Attribute | Value |
|-----------|-------|
| **Location** | `middleware/auth.js:22` |
| **OWASP Category** | A07:2021 - Identification and Authentication Failures |
| **CWE** | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **Risk** | Brute-force attack on API key |

**Description:**
Failed API key attempts are logged but not rate-limited separately. An attacker can brute-force the API key without additional throttling beyond the general rate limiter (100 requests/15 min).

**Proof of Concept:**
```bash
# Attacker can attempt multiple API keys without additional throttling
for i in {1..100}; do
  curl -H "x-api-key: guess$i" https://api.example.com/api/admin/stats
done
```

**Remediation:**
```javascript
// middleware/auth.js - Add a separate rate limiter for auth failures
import rateLimit from 'express-rate-limit';

const authFailureLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 failed attempts per 15 minutes per IP
  skipSuccessfulRequests: true,
  message: { message: 'error', error: 'Too many failed authentication attempts' }
});

export function requireApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  const serverApiKey = process.env.API_KEY;

  if (!serverApiKey) {
    console.error('SECURITY WARNING: API_KEY not configured');
    return res.status(500).json({ message: 'error', error: 'Server configuration error' });
  }

  if (!apiKey || apiKey.length !== serverApiKey.length ||
      !crypto.timingSafeEqual(Buffer.from(apiKey), Buffer.from(serverApiKey))) {
    // Apply auth failure rate limiter
    return authFailureLimiter(req, res, () => {
      console.warn(`Unauthorized access attempt from IP: ${req.ip}`);
      return res.status(401).json({ message: 'error', error: 'Unauthorized' });
    });
  }

  next();
}
```

---

### VA-002: Public Email Enumeration Endpoint

| Attribute | Value |
|-----------|-------|
| **Location** | `routes/register.js:336-352` |
| **OWASP Category** | A01:2021 - Broken Access Control |
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Risk** | Membership data enumeration |

**Description:**
The `/api/register/check` endpoint is **unauthenticated** and allows anyone to check if an email is registered, potentially exposing membership data for enumeration attacks.

**Proof of Concept:**
```bash
# Anyone can check if specific emails are registered
curl "https://api.example.com/api/register/check?email=victim@example.com"
# Response: {"message":"success","data":{"registered":true,"emailSent":true}}
```

**Remediation:**
```javascript
// Option 1: Add API key requirement
router.get('/check', requireApiKey, async (req, res) => {
  // ... existing code
});

// Option 2: Add rate limiting
const checkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 checks per hour per IP
});

router.get('/check', checkLimiter, async (req, res) => {
  // ... existing code
});

// Option 3: Return less specific information
return res.status(200).json({
  message: 'success',
  data: { registered: existing ? 'maybe' : 'no' } // Ambiguous response
});
```

---

### VA-003: OAuth Credentials in Memory Singleton

| Attribute | Value |
|-----------|-------|
| **Location** | `routes/register.js:20-31` |
| **OWASP Category** | A02:2021 - Cryptographic Failures |
| **CWE** | CWE-522: Insufficiently Protected Credentials |
| **Risk** | Service disruption on token expiry |

**Description:**
OAuth2 client credentials are stored in a singleton without automatic token refresh error handling. If the refresh token expires or is revoked, the application will fail without graceful degradation.

**Current Code:**
```javascript
let oauthClient = null;
function getOAuthClient() {
  if (!oauthClient) {
    oauthClient = new OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      process.env.OAUTH_REDIRECT_URI || 'https://developers.google.com/oauthplayground'
    );
    oauthClient.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
  }
  return oauthClient;
}
```

**Remediation:**
```javascript
let oauthClient = null;

function getOAuthClient() {
  if (!oauthClient) {
    if (!process.env.CLIENT_ID || !process.env.CLIENT_SECRET || !process.env.REFRESH_TOKEN) {
      throw new Error('OAuth credentials not properly configured');
    }

    oauthClient = new OAuth2(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      process.env.OAUTH_REDIRECT_URI || 'https://developers.google.com/oauthplayground'
    );
    oauthClient.setCredentials({ refresh_token: process.env.REFRESH_TOKEN });
  }
  return oauthClient;
}

// Add token refresh error handling
async function refreshAccessToken(client) {
  try {
    const { credentials } = await client.refreshAccessToken();
    client.setCredentials(credentials);
    return client;
  } catch (error) {
    console.error('OAuth token refresh failed:', error.message);
    oauthClient = null; // Reset for next attempt
    throw new Error('Email service temporarily unavailable');
  }
}
```

---

## Medium Severity Findings

### VA-004: Missing Content Security Policy (CSP) Configuration

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:17` |
| **OWASP Category** | A05:2021 - Security Misconfiguration |
| **Risk** | XSS attack surface |

**Description:**
Helmet is used but CSP headers are not explicitly configured, leaving the application without this important protection layer.

**Remediation:**
```javascript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'same-origin' },
}));
```

---

### VA-005: Error Messages May Leak Information

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:62-68` |
| **OWASP Category** | A05:2021 - Security Misconfiguration |
| **Risk** | Information disclosure |

**Description:**
In non-production environments, `err.stack` is logged which could expose internal paths and application structure.

**Current Code:**
```javascript
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    message: 'error',
    error: 'Something went wrong!'
  });
});
```

**Remediation:**
```javascript
app.use((err, req, res, next) => {
  // Log full error in development
  if (process.env.NODE_ENV !== 'production') {
    console.error(err.stack);
  } else {
    // Log minimal info in production
    console.error(`Error: ${err.message} | Path: ${req.path} | IP: ${req.ip}`);
  }

  res.status(500).json({
    message: 'error',
    error: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  });
});
```

---

### VA-006: Missing Query Parameter Length Limits

| Attribute | Value |
|-----------|-------|
| **Location** | `routes/admin.js:83-144` |
| **OWASP Category** | A04:2021 - Insecure Design |
| **Risk** | DoS via large queries |

**Description:**
While global body limits exist (10kb), the admin endpoints don't have additional validation for query parameter lengths, potentially allowing resource-intensive regex operations.

**Remediation:**
```javascript
// Add maximum length validation for search queries
const MAX_SEARCH_LENGTH = 100;

router.get('/members', requireApiKey, async (req, res) => {
  const { search = '', ...otherParams } = req.query;

  if (search.length > MAX_SEARCH_LENGTH) {
    return res.status(400).json({
      message: 'error',
      error: 'Search query too long'
    });
  }
  // ... rest of handler
});
```

---

### VA-007: No CSRF Protection Documentation

| Attribute | Value |
|-----------|-------|
| **Location** | Global |
| **OWASP Category** | A01:2021 - Broken Access Control |
| **Risk** | Potential CSRF if cookies implemented |

**Description:**
While CSRF is less critical for API-only backends using header-based authentication, the CORS configuration with `credentials: true` could enable CSRF if cookies are ever implemented.

**Current Mitigation:** API key in header provides protection.

**Remediation:**
Document the security model clearly:
```javascript
// Add security documentation comment
/**
 * SECURITY NOTE:
 * This API uses header-based authentication (x-api-key) which provides
 * inherent CSRF protection. The 'credentials: true' CORS setting is
 * for future cookie-based features but should be reviewed if cookies
 * are implemented.
 */
```

---

### VA-008: MongoDB URI Without Validation

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:72` |
| **OWASP Category** | A02:2021 - Cryptographic Failures |
| **Risk** | Connection to wrong database |

**Description:**
MongoDB URI with credentials is passed via environment variable without format validation.

**Remediation:**
```javascript
function validateMongoUri(uri) {
  if (!uri) {
    throw new Error('MONGO_URI environment variable is required');
  }

  try {
    const url = new URL(uri);
    if (!['mongodb:', 'mongodb+srv:'].includes(url.protocol)) {
      throw new Error('Invalid MongoDB URI protocol');
    }
    return uri;
  } catch (e) {
    throw new Error('Invalid MONGO_URI format');
  }
}

// Usage
const validatedUri = validateMongoUri(process.env.MONGO_URI);
mongoose.connect(validatedUri);
```

---

## Low Severity Findings

### VA-009: Missing HSTS Preload

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:17` |
| **OWASP Category** | A05:2021 - Security Misconfiguration |

**Description:**
HSTS is enabled by Helmet but not configured with `preload` directive for maximum browser protection.

**Remediation:**
```javascript
app.use(helmet.hsts({
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: true
}));
```

---

### VA-010: CORS Wildcard Fallback

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:23` |
| **OWASP Category** | A01:2021 - Broken Access Control |

**Description:**
Default CORS origins include localhost which could be problematic in production if `ALLOWED_ORIGINS` environment variable is not set.

**Remediation:**
```javascript
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : (process.env.NODE_ENV === 'production'
    ? [] // Fail safe in production
    : ['http://localhost:3000']); // Only allow localhost in development
```

---

### VA-011: Request Body Logged in Plain Text

| Attribute | Value |
|-----------|-------|
| **Location** | `server.js:43-45` |
| **OWASP Category** | A09:2021 - Security Logging and Monitoring Failures |

**Description:**
Request body is logged which could contain sensitive data (PII like emails, phone numbers).

**Remediation:**
```javascript
// Redact sensitive fields from logs
const SENSITIVE_FIELDS = ['email', 'mobile', 'password', 'token'];

function redactBody(body) {
  const redacted = { ...body };
  for (const field of SENSITIVE_FIELDS) {
    if (redacted[field]) {
      redacted[field] = '[REDACTED]';
    }
  }
  return redacted;
}

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Body:', redactBody(req.body));
  }
  next();
});
```

---

### VA-012: Missing Index Documentation

| Attribute | Value |
|-----------|-------|
| **Location** | `models/registration2026.js`, `models/recruitment.js` |
| **OWASP Category** | A04:2021 - Insecure Design |

**Description:**
While `unique: true` creates an index, the indexing strategy is not documented for query optimization.

**Remediation:**
Add explicit indexes and documentation:
```javascript
// Explicit indexes for query optimization
Registration2026Schema.index({ createdAt: -1 });
Registration2026Schema.index({ department: 1, year: 1 });
Registration2026Schema.index({ emailSent: 1 });

// Document indexes
/**
 * Indexes:
 * - email: unique (auto-created)
 * - createdAt: -1 (for sorting by date)
 * - department + year: compound (for filtering)
 * - emailSent: single (for status filtering)
 */
```

---

## Informational Findings

### Good Security Practices Observed

The following security best practices are properly implemented:

| Practice | Location | Implementation |
|----------|----------|----------------|
| Timing-safe API key comparison | `middleware/auth.js:22` | `crypto.timingSafeEqual()` |
| Input type validation | `routes/register.js:96`, `routes/recruitment.js:44` | `typeof` checks prevent NoSQL injection |
| Rate limiting | All public endpoints | `express-rate-limit` (100 req/15min) |
| HTML escaping | `routes/register.js:34-40` | `escHtml()` function |
| Request body size limits | `server.js:34-35` | 10kb limit |
| Email domain validation | `routes/recruitment.js:72-79` | Whitelisted domains |
| Regex escaping for search | `routes/admin.js:23-25` | `escapeRegex()` function |
| Environment file protection | `.gitignore` | `.env` excluded |
| API key redaction in logs | `server.js:41` | `[REDACTED]` in logs |
| Explicit `$eq` operator | All MongoDB queries | Prevents NoSQL injection |
| Input length limits | All input handlers | Prevents ReDoS |

---

### Dependency Status

| Package | Version | Latest | Status |
|---------|---------|--------|--------|
| express | 5.2.1 | 5.x | Current |
| mongoose | 9.1.5 | 9.x | Current |
| helmet | 8.0.0 | 8.x | Current |
| googleapis | 170.1.0 | 170.x | Current |
| express-rate-limit | 8.2.1 | 8.x | Current |
| cors | 2.8.6 | 2.x | Current |
| dotenv | 17.2.3 | 17.x | Current |

**Recommendations:**
- Enable Dependabot for automated dependency updates
- Run `npm audit` regularly in CI/CD pipeline
- Consider using `npm audit fix --only=prod` for production dependencies

---

### Test Coverage Analysis

The test file (`tests/api.test.js`) covers:
- Health check endpoint
- Basic registration validation
- Successful registration flow

**Missing Security Tests:**
- Authentication failure scenarios
- Rate limiting verification
- Input validation edge cases (empty, too long, wrong types)
- NoSQL injection attempts
- XSS in input fields
- CORS policy enforcement
- Error handling behavior

**Recommended Additional Tests:**
```javascript
describe('Security Tests', () => {
  test('POST /api/register - NoSQL injection attempt', async () => {
    const res = await request(app)
      .post('/api/register')
      .set('x-api-key', 'test-key')
      .send({ email: { $ne: '' }, name: 'Attacker' });
    expect(res.statusCode).toBe(400);
  });

  test('GET /api/admin/stats - Missing API key', async () => {
    const res = await request(app).get('/api/admin/stats');
    expect(res.statusCode).toBe(401);
  });

  test('POST /api/register - Rate limiting', async () => {
    // Make 101 requests
    for (let i = 0; i < 101; i++) {
      await request(app)
        .post('/api/register')
        .set('x-api-key', 'test-key')
        .send({ email: `test${i}@example.com` });
    }
    // 101st should be rate limited
    const res = await request(app)
      .post('/api/register')
      .set('x-api-key', 'test-key')
      .send({});
    expect(res.statusCode).toBe(429);
  });
});
```

---

## OWASP Top 10 (2021) Compliance Checklist

| # | Category | Status | Score | Notes |
|---|----------|--------|-------|-------|
| A01 | Broken Access Control | ⚠️ Partial | 7/10 | Email enumeration endpoint unprotected |
| A02 | Cryptographic Failures | ⚠️ Partial | 7/10 | OAuth token handling could be improved |
| A03 | Injection | ✅ Good | 9/10 | Type checking prevents NoSQL injection |
| A04 | Insecure Design | ⚠️ Partial | 7/10 | Missing some rate limits |
| A05 | Security Misconfiguration | ⚠️ Partial | 7/10 | CSP not configured |
| A06 | Vulnerable Components | ✅ Good | 9/10 | Dependencies are current |
| A07 | Auth Failures | ⚠️ Partial | 6/10 | No auth failure rate limiting |
| A08 | Software/Data Integrity | ✅ Good | 8/10 | NPM packages from official registry |
| A09 | Logging/Monitoring | ⚠️ Partial | 6/10 | Sensitive data in logs |
| A10 | SSRF | ✅ N/A | 10/10 | No external URL fetching |

**Overall Compliance Score: 76/100 (B+)**

---

## Priority Remediation Roadmap

### Immediate (1-7 days)
| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | Add rate limiting to `/api/register/check` endpoint | Low | High |
| 2 | Add authentication failure rate limiting | Low | High |
| 3 | Redact sensitive fields from request logs | Low | Medium |

### Short-term (1-4 weeks)
| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 4 | Configure explicit CSP headers | Medium | Medium |
| 5 | Add production-specific error handling | Low | Medium |
| 6 | Expand test coverage for security cases | Medium | High |
| 7 | Add query parameter length validation | Low | Low |

### Long-term (1-3 months)
| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 8 | Implement token refresh error handling for OAuth | Medium | Medium |
| 9 | Add security monitoring/alerting | High | High |
| 10 | Consider implementing request signing for API calls | High | Medium |
| 11 | Add HSTS preload configuration | Low | Low |

---

## Conclusion

The C3 Backend demonstrates **mature security practices** for a membership management API. The codebase shows clear evidence of security-conscious development with:

### Strengths
- Proper input validation with explicit type checking
- Timing-safe API key comparison preventing timing attacks
- Rate limiting on public endpoints
- HTML escaping in email templates
- Regex escaping for search queries
- Request body size limits
- Environment variable protection

### Areas for Improvement
- Authentication failure rate limiting
- Email enumeration prevention
- OAuth token refresh handling
- CSP header configuration
- Log sanitization

The identified issues are mostly **enhancements** rather than critical vulnerabilities. Implementing the recommended fixes will bring the security posture to an **A-level** rating.

---

## Appendix A: Files Reviewed

| File | Lines | Purpose |
|------|-------|---------|
| `server.js` | 89 | Main application entry |
| `middleware/auth.js` | 33 | Authentication middleware |
| `routes/register.js` | 353 | Registration endpoints |
| `routes/admin.js` | 287 | Admin endpoints |
| `routes/recruitment.js` | 181 | Recruitment endpoints |
| `models/registration2026.js` | 75 | Registration schema |
| `models/recruitment.js` | 72 | Recruitment schema |
| `tests/api.test.js` | 71 | API tests |
| `.gitignore` | 5 | Git ignore rules |
| `package.json` | 34 | Dependencies |

---

## Appendix B: References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ASVS 4.0.3](https://owasp.org/www-pdf-archive/OWASP_Application_Security_Verification_Standard_4.0.3.pdf)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [Express.js Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Helmet.js Documentation](https://helmetjs.github.io/)

---

**Report Generated:** 2026-03-12
**Audit Version:** 1.0
**Next Review Recommended:** 2026-06-12 (3 months)
