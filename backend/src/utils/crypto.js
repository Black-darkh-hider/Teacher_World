import crypto from 'crypto';

export function hashOtp(otp, secret) {
  const key = secret || process.env.OTP_HASH_SECRET || 'dev_otp_secret_change';
  return crypto.createHmac('sha256', key).update(String(otp)).digest('hex');
}

export function generateOtp() {
  // 6-digit numeric OTP
  return Math.floor(100000 + Math.random() * 900000).toString();
}
