import nodemailer from 'nodemailer';

let transporter = null;

function getTransporter() {
  if (!transporter) {
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587', 10);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    if (!host || !user || !pass) {
      throw new Error('SMTP mail credentials are not configured in environment variables (SMTP_HOST, SMTP_USER, SMTP_PASS).');
    }

    transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: { user, pass },
      tls: { rejectUnauthorized: false },
    });
  }
  return transporter;
}

export function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export async function sendEmail(to, subject, htmlBody) {
  const client = getTransporter();
  const from = process.env.EMAIL_FROM || `Cloud Community Club (C³) <${process.env.SMTP_USER}>`;
  await client.sendMail({ from, to, subject, html: htmlBody });
}
