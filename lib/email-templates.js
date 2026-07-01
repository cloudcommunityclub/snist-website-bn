import { sendEmail, escHtml } from './mailer.js';

export async function sendIdeathonConfirmation(to, data) {
  const htmlBody = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Ideathon Submission Confirmed</title>
  <style type="text/css">
    body { margin: 0; padding: 0; min-width: 100%; background-color: #f4f4f7; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; }
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
              <div style="font-size: 48px; margin-bottom: 10px;">🚀</div>
              <h1 style="margin: 0; font-size: 24px; color: #111827; font-weight: 800; letter-spacing: -0.5px;">Submission Received!</h1>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding: 0 40px 30px 40px;">
              <p style="margin: 0; font-size: 16px; color: #6b7280; line-height: 1.6;">
                Hey <strong style="color: #111827;">${escHtml(data.name)}</strong>,
              </p>
              <p style="margin: 10px 0 0 0; font-size: 16px; color: #6b7280; line-height: 1.6;">
                Your Digital India Ideathon submission for team <strong style="color: #111827;">${escHtml(data.teamName)}</strong> has been received successfully.
              </p>
            </td>
          </tr>
          <tr>
            <td align="center" style="padding: 0 40px 40px 40px;">
              <table width="100%" border="0" cellpadding="0" cellspacing="0" style="background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); border-radius: 16px; overflow: hidden; box-shadow: 0 10px 20px rgba(79, 70, 229, 0.3);">
                <tr>
                  <td style="padding: 30px;">
                    <div style="color: rgba(255,255,255,0.7); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Referral Code</div>
                    <div style="margin-top: 8px; font-size: 28px; color: #ffffff; font-weight: bold; letter-spacing: 4px; font-family: 'Courier New', monospace;">${escHtml(data.referralCode)}</div>
                    <div style="margin-top: 15px; color: rgba(255,255,255,0.7); font-size: 12px; line-height: 1.5;">
                      Share this code with friends — you earn points for every successful referral!
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding: 0 40px 40px 40px;">
              <div style="border-top: 1px solid #e5e7eb; margin-bottom: 30px;"></div>
              <h3 style="margin: 0 0 20px 0; font-size: 14px; text-transform: uppercase; color: #9CA3AF; letter-spacing: 1px;">What Happens Next?</h3>
              <table width="100%" border="0" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="24" valign="top" style="padding-bottom: 15px;">
                    <span style="color: #10B981; font-weight: bold; font-size: 18px;">✓</span>
                  </td>
                  <td style="padding-bottom: 15px; color: #374151; font-size: 15px; line-height: 1.4;">
                    <strong>Payment Verification</strong><br>
                    <span style="color: #6b7280; font-size: 13px;">Our team will verify your payment screenshot within 24-48 hours.</span>
                  </td>
                </tr>
                <tr>
                  <td width="24" valign="top" style="padding-bottom: 15px;">
                    <span style="color: #4F46E5; font-weight: bold; font-size: 18px;">➜</span>
                  </td>
                  <td style="padding-bottom: 15px; color: #374151; font-size: 15px; line-height: 1.4;">
                    <strong>Shortlist Announcement</strong><br>
                    <span style="color: #6b7280; font-size: 13px;">Shortlisted teams will be notified via email and WhatsApp.</span>
                  </td>
                </tr>
                <tr>
                  <td width="24" valign="top">
                    <span style="color: #F59E0B; font-weight: bold; font-size: 18px;">★</span>
                  </td>
                  <td style="color: #374151; font-size: 15px; line-height: 1.4;">
                    <strong>Refer & Earn</strong><br>
                    <span style="color: #6b7280; font-size: 13px;">Share your referral code with friends and earn points!</span>
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
</html>`;

  await sendEmail(to, '🚀 Ideathon Submission Confirmed — Cloud Community Club (C³)', htmlBody);
}
