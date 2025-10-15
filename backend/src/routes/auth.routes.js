import { Router } from 'express';
import { body } from 'express-validator';
import { login, register, verifyOtp, resendOtp, refreshToken, loginInit, verifyLoginOtp, logout } from '../controllers/auth.controller.js';

const router = Router();

router.post(
  '/register',
  [body('email').isEmail(), body('password').isLength({ min: 6 }), body('role').optional().isIn(['teacher', 'employer'])],
  register
);

router.post('/resend-otp', [body('email').isEmail(), body('purpose').optional().isIn(['register', 'login'])], resendOtp);

router.post('/verify-otp', [body('email').isEmail(), body('otp').isLength({ min: 6, max: 6 })], verifyOtp);

router.post('/login', [body('email').isEmail(), body('password').isLength({ min: 6 })], login);

// Optional: two-step email OTP login
router.post('/login/init', [body('email').isEmail(), body('password').isLength({ min: 6 })], loginInit);
router.post('/login/verify', [body('email').isEmail(), body('otp').isLength({ min: 6, max: 6 })], verifyLoginOtp);

router.post('/refresh', refreshToken);
router.post('/logout', logout);

export default router;
