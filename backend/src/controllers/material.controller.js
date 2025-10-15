import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { validationResult } from 'express-validator';
import { Material } from '../models/index.js';
import { Op } from 'sequelize';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = multer.diskStorage({
  destination: (_req, file, cb) => cb(null, path.join(__dirname, '../../uploads/materials')),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${req.user.sub}-${Date.now()}${ext}`);
  },
});

function fileFilter(_req, file, cb) {
  const allowed = ['.pdf', '.png', '.jpg', '.jpeg'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (!allowed.includes(ext)) return cb(new Error('Invalid file type'));
  cb(null, true);
}

export const uploadMaterial = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } });

export async function createMaterial(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { subject, grade, title, type, linkUrl } = req.body;
  const fileUrl = req.file ? `/uploads/materials/${req.file.filename}` : undefined;
  const material = await Material.create({ uploaderId: req.user.sub, subject, grade, title, type, fileUrl, linkUrl });
  return res.status(201).json(material);
}

export async function listMaterials(req, res) {
  const { subject, grade, q } = req.query;
  const where = {};
  if (subject) where.subject = subject;
  if (grade) where.grade = grade;
  if (q) where.title = { [Op.like]: `%${q}%` };
  const items = await Material.findAll({ where, order: [['createdAt', 'DESC']] });
  return res.json(items);
}
