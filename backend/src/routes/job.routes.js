import { Router } from 'express';
import { body, query } from 'express-validator';
import { requireAuth, requireRole } from '../middlewares/auth.middleware.js';
import { createJob, searchJobs, applyJob } from '../controllers/job.controller.js';

const router = Router();

router.post(
  '/',
  requireAuth,
  requireRole('employer'),
  [body('title').isString(), body('description').isString(), body('city').optional().isString(), body('salary').optional().isString(), body('tags').optional().isString(), body('latitude').optional().isFloat(), body('longitude').optional().isFloat()],
  createJob
);

router.get('/search', [query('q').optional().isString(), query('city').optional().isString(), query('tags').optional().isString(), query('lat').optional().isFloat(), query('lng').optional().isFloat(), query('radiusKm').optional().isFloat()], searchJobs);

router.post('/apply', requireAuth, [body('jobId').isString(), body('coverLetter').optional().isString()], applyJob);

export default router;
