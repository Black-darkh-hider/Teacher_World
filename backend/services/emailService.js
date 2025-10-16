const nodemailer = require('nodemailer');
const logger = require('./logger');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  initializeTransporter() {
    // Configure email transporter based on environment
    if (process.env.NODE_ENV === 'production') {
      // Production email configuration (e.g., SendGrid, AWS SES, etc.)
      this.transporter = nodemailer.createTransporter({
        service: process.env.EMAIL_SERVICE || 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      });
    } else {
      // Development/Demo configuration using Ethereal Email
      this.transporter = nodemailer.createTransporter({
        host: 'smtp.ethereal.email',
        port: 587,
        auth: {
          user: 'ethereal.user@ethereal.email',
          pass: 'ethereal.pass'
        }
      });
    }
  }

  async sendOTP(email, otp, type = 'password_reset') {
    try {
      const subject = this.getSubjectByType(type);
      const htmlContent = this.getHTMLTemplate(otp, type);
      const textContent = this.getTextTemplate(otp, type);

      const mailOptions = {
        from: process.env.EMAIL_FROM || 'Teacher World <noreply@teacherworld.com>',
        to: email,
        subject: subject,
        text: textContent,
        html: htmlContent
      };

      if (process.env.NODE_ENV === 'production') {
        const info = await this.transporter.sendMail(mailOptions);
        logger.info(`OTP email sent to ${email}`, { messageId: info.messageId });
        return { success: true, messageId: info.messageId };
      } else {
        // In development, log the OTP instead of sending email
        logger.info(`[DEMO MODE] OTP for ${email}: ${otp} (Type: ${type})`);
        console.log(`*** DEMO MODE - OTP for ${email}: ${otp} (Type: ${type}) ***`);
        return { success: true, demo: true, otp: otp };
      }
    } catch (error) {
      logger.error('Failed to send OTP email', { email, error: error.message });
      throw new Error('Failed to send OTP email');
    }
  }

  getSubjectByType(type) {
    const subjects = {
      password_reset: 'Teacher World - Password Reset OTP',
      username_reset: 'Teacher World - Username Reset OTP',
      account_verification: 'Teacher World - Account Verification OTP',
      login_verification: 'Teacher World - Login Verification OTP'
    };
    return subjects[type] || 'Teacher World - Verification Code';
  }

  getHTMLTemplate(otp, type) {
    const titles = {
      password_reset: 'Password Reset Request',
      username_reset: 'Username Reset Request',
      account_verification: 'Account Verification',
      login_verification: 'Login Verification'
    };

    const messages = {
      password_reset: 'You have requested to reset your password. Use the OTP below to proceed:',
      username_reset: 'You have requested to reset your username. Use the OTP below to proceed:',
      account_verification: 'Please verify your account using the OTP below:',
      login_verification: 'Please verify your login attempt using the OTP below:'
    };

    const title = titles[type] || 'Verification Required';
    const message = messages[type] || 'Please use the OTP below to verify your request:';

    return `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${title}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .otp-box { background: white; border: 2px solid #667eea; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0; }
            .otp-code { font-size: 32px; font-weight: bold; color: #667eea; letter-spacing: 5px; margin: 10px 0; }
            .warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .footer { text-align: center; margin-top: 30px; color: #666; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🎓 Teacher World</h1>
                <h2>${title}</h2>
            </div>
            <div class="content">
                <p>Hello,</p>
                <p>${message}</p>
                
                <div class="otp-box">
                    <p><strong>Your OTP Code:</strong></p>
                    <div class="otp-code">${otp}</div>
                    <p><small>This code will expire in 5 minutes</small></p>
                </div>
                
                <div class="warning">
                    <strong>⚠️ Security Notice:</strong>
                    <ul>
                        <li>Never share this OTP with anyone</li>
                        <li>Teacher World will never ask for your OTP via phone or email</li>
                        <li>If you didn't request this, please ignore this email</li>
                    </ul>
                </div>
                
                <p>If you have any questions, please contact our support team.</p>
                <p>Best regards,<br>The Teacher World Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
                <p>&copy; 2024 Teacher World. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>
    `;
  }

  getTextTemplate(otp, type) {
    const titles = {
      password_reset: 'Password Reset Request',
      username_reset: 'Username Reset Request',
      account_verification: 'Account Verification',
      login_verification: 'Login Verification'
    };

    const messages = {
      password_reset: 'You have requested to reset your password.',
      username_reset: 'You have requested to reset your username.',
      account_verification: 'Please verify your account.',
      login_verification: 'Please verify your login attempt.'
    };

    const title = titles[type] || 'Verification Required';
    const message = messages[type] || 'Please verify your request.';

    return `
Teacher World - ${title}

Hello,

${message} Use the OTP below to proceed:

Your OTP Code: ${otp}

This code will expire in 5 minutes.

SECURITY NOTICE:
- Never share this OTP with anyone
- Teacher World will never ask for your OTP via phone or email
- If you didn't request this, please ignore this email

If you have any questions, please contact our support team.

Best regards,
The Teacher World Team

---
This is an automated message. Please do not reply to this email.
© 2024 Teacher World. All rights reserved.
    `.trim();
  }

  async verifyConnection() {
    try {
      await this.transporter.verify();
      logger.info('Email service connection verified');
      return true;
    } catch (error) {
      logger.error('Email service connection failed', { error: error.message });
      return false;
    }
  }
}

module.exports = new EmailService();