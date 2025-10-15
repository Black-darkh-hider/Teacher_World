import nodemailer from 'nodemailer';

let transporter;

export function getMailer() {
  if (!transporter) {
    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT || 587);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

    transporter = nodemailer.createTransport({
      host,
      port,
      secure: port === 465,
      auth: user && pass ? { user, pass } : undefined,
    });
  }
  return transporter;
}

export async function sendEmail({ to, subject, html, text }) {
  const from = process.env.SMTP_FROM || 'no-reply@example.com';
  const info = await getMailer().sendMail({ from, to, subject, html, text });
  return info;
}
