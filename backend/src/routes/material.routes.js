import { Router } from 'express';
import { body, query } from 'express-validator';
import { requireAuth } from '../middlewares/auth.middleware.js';
import { uploadMaterial, createMaterial, listMaterials } from '../controllers/material.controller.js';

const router = Router();

router.post(
  '/',
  requireAuth,
  uploadMaterial.single('file'),
  [body('subject').isString(), body('title').isString(), body('type').isIn(['file', 'link']), body('grade').optional().isString(), body('linkUrl').optional().isURL()],
  createMaterial
);

router.get('/', [query('subject').optional().isString(), query('grade').optional().isString(), query('q').optional().isString()], listMaterials);

export default router;
