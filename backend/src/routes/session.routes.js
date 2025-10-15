import { Router } from 'express';
import { body } from 'express-validator';
import { requireAuth } from '../middlewares/auth.middleware.js';
import { createSession, listSessions } from '../controllers/session.controller.js';

const router = Router();

router.post('/', requireAuth, [body('title').isString(), body('startsAt').optional().isISO8601()], createSession);
router.get('/', requireAuth, listSessions);

export default router;
