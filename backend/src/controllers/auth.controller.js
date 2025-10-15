import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { validationResult } from 'express-validator';
import { User, OtpToken, RefreshSession } from '../models/index.js';
import { hashOtp, generateOtp } from '../utils/crypto.js';
import { sendEmail } from '../services/mailer.service.js';
import crypto from 'crypto';

async function buildTokens(user) {
  const accessToken = jwt.sign(
    { sub: user.id, role: user.role },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' }
  );
  const jti = crypto.randomUUID();
  const refreshToken = jwt.sign(
    { sub: user.id, jti },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES || '7d' }
  );
  const expiresAt = new Date(Date.now() + parseExpiryToMs(process.env.JWT_REFRESH_EXPIRES || '7d'));
  await RefreshSession.create({ userId: user.id, jti, expiresAt });
  return { accessToken, refreshToken };
}

export async function register(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, password, role } = req.body;
  const existing = await User.findOne({ where: { email } });
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = await User.create({ email, passwordHash, role: role || 'teacher' });

  await issueAndSendOtp(user, 'register');
  return res.status(201).json({ message: 'Registered. OTP sent to email.' });
}

export async function resendOtp(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, purpose } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (purpose === 'register' && user.isVerified) return res.status(400).json({ error: 'Already verified' });
  await issueAndSendOtp(user, purpose || 'register');
  return res.json({ message: 'OTP sent' });
}

export async function verifyOtp(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, otp, purpose } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const item = await OtpToken.findOne({
    where: { userId: user.id, purpose: purpose || 'register', used: false },
    order: [['createdAt', 'DESC']],
  });
  if (!item) return res.status(400).json({ error: 'No OTP found' });
  if (item.expiresAt < new Date()) return res.status(400).json({ error: 'OTP expired' });

  const submittedHash = hashOtp(otp, process.env.OTP_HASH_SECRET);
  if (submittedHash !== item.otpHash) {
    item.attempts += 1;
    await item.save();
    return res.status(400).json({ error: 'Invalid OTP' });
  }

  item.used = true;
  await item.save();

  if (item.purpose === 'register') {
    user.isVerified = true;
    await user.save();
  }

  return res.json({ message: 'OTP verified' });
}

export async function login(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.isVerified) return res.status(403).json({ error: 'Email not verified' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const tokens = await buildTokens(user);
  return res.json({ user: { id: user.id, email: user.email, role: user.role }, ...tokens });
}

// Optional 2-step login with OTP sent to email
export async function loginInit(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.isVerified) return res.status(403).json({ error: 'Email not verified' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  await issueAndSendOtp(user, 'login');
  return res.json({ message: 'Login OTP sent' });
}

export async function verifyLoginOtp(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { email, otp } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(404).json({ error: 'User not found' });
  const item = await OtpToken.findOne({ where: { userId: user.id, purpose: 'login', used: false }, order: [['createdAt', 'DESC']] });
  if (!item) return res.status(400).json({ error: 'No OTP found' });
  if (item.expiresAt < new Date()) return res.status(400).json({ error: 'OTP expired' });
  const submittedHash = hashOtp(otp, process.env.OTP_HASH_SECRET);
  if (submittedHash !== item.otpHash) {
    item.attempts += 1;
    await item.save();
    return res.status(400).json({ error: 'Invalid OTP' });
  }
  item.used = true;
  await item.save();
  const tokens = await buildTokens(user);
  return res.json({ user: { id: user.id, email: user.email, role: user.role }, ...tokens });
}

export async function refreshToken(req, res) {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Missing refresh token' });
  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const session = await RefreshSession.findOne({ where: { jti: payload.jti, userId: payload.sub, revoked: false } });
    if (!session || session.expiresAt < new Date()) return res.status(401).json({ error: 'Invalid refresh token' });
    const user = await User.findByPk(payload.sub);
    if (!user) return res.status(401).json({ error: 'Invalid refresh token' });
    // rotate: revoke old, issue new
    session.revoked = true;
    await session.save();
    const tokens = await buildTokens(user);
    return res.json(tokens);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
}

export async function logout(req, res) {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.json({ message: 'Logged out' });
  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const session = await RefreshSession.findOne({ where: { jti: payload.jti, userId: payload.sub, revoked: false } });
    if (session) {
      session.revoked = true;
      await session.save();
    }
  } catch (_) {}
  return res.json({ message: 'Logged out' });
}

function parseExpiryToMs(s) {
  // supports m, h, d
  const match = String(s).match(/^(\d+)([mhd])$/);
  if (!match) return 7 * 24 * 60 * 60 * 1000;
  const num = Number(match[1]);
  const unit = match[2];
  if (unit === 'm') return num * 60 * 1000;
  if (unit === 'h') return num * 60 * 60 * 1000;
  if (unit === 'd') return num * 24 * 60 * 60 * 1000;
  return 7 * 24 * 60 * 60 * 1000;
}

async function issueAndSendOtp(user, purpose) {
  const plainOtp = generateOtp();
  const otpHash = hashOtp(plainOtp, process.env.OTP_HASH_SECRET);
  const expiresAt = new Date(Date.now() + Number(process.env.OTP_TTL_MINUTES || 10) * 60 * 1000);
  await OtpToken.create({ userId: user.id, purpose, otpHash, expiresAt });

  const subject = `Your OTP for ${purpose === 'register' ? 'registration' : 'login'}`;
  const html = `<p>Your OTP is <b>${plainOtp}</b>. It will expire in ${process.env.OTP_TTL_MINUTES || 10} minutes.</p>`;
  const text = `Your OTP is ${plainOtp}. It will expire in ${process.env.OTP_TTL_MINUTES || 10} minutes.`;

  // Send email (production) or log (dev without SMTP)
  if (process.env.SMTP_HOST) {
    await sendEmail({ to: user.email, subject, html, text });
  } else {
    console.log('OTP for', user.email, '->', plainOtp);
  }
}
