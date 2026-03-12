import { Router } from "express";
import { google } from 'googleapis';
import dotenv from "dotenv";
import rateLimit from 'express-rate-limit';
import Registration2026 from "../models/registration2026.js";
import { requireApiKey } from "../middleware/auth.js";
dotenv.config();
const router = Router();
const OAuth2 = google.auth.OAuth2;

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'error', error: 'Too many requests from this IP, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limiter for the email-check endpoint to prevent membership enumeration
const checkLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 checks per hour per IP
  message: { message: 'error', error: 'Too many check requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Singleton OAuth2 client — initialized once at module load
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

    // Reset singleton on token errors so the next request re-initializes cleanly
    oauthClient.on('tokens', (tokens) => {
      if (tokens.refresh_token) {
        oauthClient.setCredentials({ refresh_token: tokens.refresh_token });
      }
    });
  }
  return oauthClient;
}

// Helper function to HTML-escape user-supplied values in email templates
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Helper function to encode email body for Gmail API
function makeBody(to, from, subject, message) {
  // RFC 2047 Encoding for Subject: =?utf-8?B?...?=
  const encodedSubject = `=?utf-8?B?${Buffer.from(subject).toString('base64')}?=`;

  const str = [
    "Content-Type: text/html; charset=\"UTF-8\"\n",
    "MIME-Version: 1.0\n",
    "Content-Transfer-Encoding: 7bit\n",
    "to: ", to, "\n",
    "from: ", from, "\n",
    "subject: ", encodedSubject, "\n\n",
    message
  ].join('');

  return Buffer.from(str).toString("base64").replace(/\+/g, '-').replace(/\//g, '_');
}

// GET route for registration endpoint
router.get("/", (req, res) => {
  res.status(200).json({
    message: "Registration API is working",
    instructions: "Please use POST method to register a new member",
    endpoints: {
      register: "POST /api/register - Register a new member"
    }
  });
});

// POST route for form submission (protected with API key)
router.post("/", apiLimiter, requireApiKey, async (req, res) => {
  try {
    const {
      name,
      email,
      mobile,
      rollNumber,
      department,
      year,
      interests,
      experience,
      expectations,
      referral
    } = req.body;

    // Validate required fields
    if (!name || !email || !mobile || !rollNumber || !department || !year || !interests || interests.length === 0) {
      return res.status(400).json({
        message: "error",
        error: "All required fields must be provided"
      });
    }

    // Explicit type checking to prevent NoSQL injection via object payloads
    if (typeof name !== 'string' || typeof email !== 'string' || typeof mobile !== 'string' || typeof rollNumber !== 'string') {
      return res.status(400).json({
        message: "error",
        error: "Invalid input types"
      });
    }

    // Limit length to prevent DoS
    if (email.length > 254 || name.length > 200 || mobile.length > 50 || rollNumber.length > 50) {
      return res.status(400).json({
        message: "error",
        error: "Input fields exceed maximum allowed length"
      });
    }

    // Upsert: Update existing member or create new one
    // This allows users to retry if email sending failed previously
    const memberData = {
      name,
      email,
      mobile,
      rollNumber,
      department,
      year,
      interests,
      experience,
      expectations,
      referral,
    };

    await Registration2026.findOneAndUpdate(
      { email: { $eq: email } },
      { $set: memberData, $setOnInsert: { emailSent: false, createdAt: new Date() } },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Send welcome email using Direct Gmail API (Port 443)
    try {
      const oauth2Client = getOAuthClient();
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

      const htmlBody = `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Welcome to C3</title>
  <style type="text/css">
    /* Reset styles */
    body { margin: 0; padding: 0; min-width: 100%; width: 100% !important; background-color: #f4f4f7; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
    
    /* Utility */
    .capitalize { text-transform: capitalize; }
    .uppercase { text-transform: uppercase; }
    
    /* Mobile Responsiveness */
    @media only screen and (max-width: 600px) {
      .width-full { width: 100% !important; max-width: 100% !important; }
      .mobile-pad { padding: 20px !important; }
    }
  </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f7;">

  <table width="100%" border="0" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f4f4f7;">
    <tr>
      <td align="center" style="padding: 40px 0;">
        
        <table width="600" border="0" cellpadding="0" cellspacing="0" class="width-full" style="width: 600px; max-width: 600px; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); overflow: hidden;">
          
          <tr>
            <td align="center" style="padding: 40px 40px 20px 40px; background-color: #ffffff;">
               <div style="font-size: 48px; margin-bottom: 10px;">☁️</div> 
               <h1 style="margin: 0; font-size: 24px; color: #111827; font-weight: 800; letter-spacing: -0.5px;">Cloud Community Club</h1>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding: 0 40px 30px 40px;">
              <p style="margin: 0; font-size: 16px; color: #6b7280; line-height: 1.6;">
                Welcome aboard, <strong style="color: #111827; text-transform: capitalize;">${escHtml(name)}</strong>!
              </p>
              <p style="margin: 10px 0 0 0; font-size: 16px; color: #6b7280; line-height: 1.6;">
                Your application has been accepted. You are now an official member of C³.
              </p>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding: 0 40px 40px 40px;">
              <table width="100%" border="0" cellpadding="0" cellspacing="0" style="background: #4F46E5; /* Fallback for gradients */ background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); border-radius: 16px; overflow: hidden; box-shadow: 0 10px 20px rgba(79, 70, 229, 0.3);">
                <tr>
                  <td style="padding: 30px;">
                    
                    <table width="100%" border="0" cellpadding="0" cellspacing="0">
                      <tr>
                        <td align="left" style="color: rgba(255,255,255,0.7); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                          Membership Pass
                        </td>
                        <td align="right" style="color: #ffffff; font-size: 14px; font-weight: bold;">
                          2026
                        </td>
                      </tr>
                    </table>

                    <div style="margin-top: 20px; margin-bottom: 5px; font-size: 22px; color: #ffffff; font-weight: bold; text-transform: capitalize;">
                      ${escHtml(name)}
                    </div>
                    
                    <table width="100%" border="0" cellpadding="0" cellspacing="0" style="margin-top: 15px;">
                      <tr>
                        <td width="50%" valign="top">
                          <div style="color: rgba(255,255,255,0.7); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
                            Student ID
                          </div>
                          <div style="color: #ffffff; font-size: 14px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px;">
                            ${escHtml(rollNumber)}
                          </div>
                        </td>
                        
                        <td width="1" style="background-color: rgba(255,255,255,0.2);"></td>
                        <td width="20"></td>

                        <td valign="top">
                          <div style="color: rgba(255,255,255,0.7); font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">
                            Department
                          </div>
                          <div style="color: #ffffff; font-size: 14px; font-weight: 600;">
                            ${escHtml(department)}
                          </div>
                        </td>
                      </tr>
                    </table>

                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td style="padding: 0 40px 40px 40px; background-color: #ffffff;">
              <div style="border-top: 1px solid #e5e7eb; margin-bottom: 30px;"></div>
              
              <h3 style="margin: 0 0 20px 0; font-size: 14px; text-transform: uppercase; color: #9CA3AF; letter-spacing: 1px;">
                Your Next Steps
              </h3>
              
              <table width="100%" border="0" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="24" valign="top" style="padding-bottom: 15px;">
                    <span style="color: #10B981; font-weight: bold; font-size: 18px;">✓</span>
                  </td>
                  <td style="padding-bottom: 15px; color: #374151; font-size: 15px; line-height: 1.4;">
                    <strong>Subscribed to Newsletter</strong><br>
                    <span style="color: #6b7280; font-size: 13px;">You'll get updates on workshops & tech talks.</span>
                  </td>
                </tr>
                <tr>
                  <td width="24" valign="top">
                    <span style="color: #4F46E5; font-weight: bold; font-size: 18px;">➜</span>
                  </td>
                  <td style="color: #374151; font-size: 15px; line-height: 1.4;">
                    <strong>Wait for Hackathons</strong><br>
                    <span style="color: #6b7280; font-size: 13px;">We will notify you when registration opens.</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>

          <tr>
            <td align="center" style="padding: 30px; background-color: #f9fafb; border-top: 1px solid #e5e7eb;">
               <p style="margin: 0; color: #9CA3AF; font-size: 12px;">
                 © 2026 Cloud Community Club (C³).<br>
                 Sreenidhi Institute of Science and Technology.
               </p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>
      `;

      const rawMessage = makeBody(
        email,
        `Cloud Community Club (C³) <${process.env.EMAIL_USER}>`,
        "🎉 Welcome to Cloud Community Club (C³) Membership!",
        htmlBody
      );

      await gmail.users.messages.send({
        userId: 'me',
        requestBody: {
          raw: rawMessage
        }
      });

      console.log("✅ Email sent successfully via Gmail API");

      await Registration2026.updateOne(
        { email: { $eq: email } },
        { $set: { emailSent: true, emailSentAt: new Date() } }
      );

    } catch (emailError) {
      console.error('❌ API Error (Email Failed):', emailError.message);
      // Don't fail the registration if email fails
    }

    // Send success response
    return res.status(200).json({
      message: "success",
      data: {
        name,
        email,
        department,
        year
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({
      message: "error",
      error: "An error occurred during registration"
    });
  }
});

/**
 * GET /api/register/check?email=...
 * Check if an email is already registered (for frontend pre-check)
 */
router.get('/check', checkLimiter, async (req, res) => {
  try {
    const { email } = req.query;
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ message: 'error', error: 'Email query parameter is required' });
    }
    const normalizedEmail = email.trim().toLowerCase();
    const existing = await Registration2026.findOne({ email: { $eq: normalizedEmail } }).select('email emailSent createdAt').lean();
    return res.status(200).json({
      message: 'success',
      data: { registered: !!existing, emailSent: existing?.emailSent ?? false }
    });
  } catch (error) {
    console.error('Check email error:', error);
    return res.status(500).json({ message: 'error', error: 'An error occurred' });
  }
});

export default router;