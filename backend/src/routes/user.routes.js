import { Router } from 'express';
import { body } from 'express-validator';
import { requireAuth } from '../middlewares/auth.middleware.js';
import { getMe, updateMe, upload, uploadResume, uploadCertificate, listCertificates, deleteCertificate } from '../controllers/user.controller.js';

const router = Router();

router.get('/me', requireAuth, getMe);

router.put(
  '/me',
  requireAuth,
  [body('name').optional().isString(), body('contact').optional().isString(), body('address').optional().isString(), body('city').optional().isString(), body('qualifications').optional().isString()],
  updateMe
);

router.post('/me/resume', requireAuth, upload.single('resume'), uploadResume);
router.post('/me/certificates', requireAuth, upload.single('certificate'), uploadCertificate);
router.get('/me/certificates', requireAuth, listCertificates);
router.delete('/me/certificates/:id', requireAuth, deleteCertificate);

export default router;
