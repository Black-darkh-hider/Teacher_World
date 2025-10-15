import { validationResult } from 'express-validator';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import { User, Certificate } from '../models/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'resume') cb(null, path.join(__dirname, '../../uploads/resumes'));
    else cb(null, path.join(__dirname, '../../uploads/certificates'));
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safe = `${req.user.sub}-${Date.now()}${ext}`;
    cb(null, safe);
  },
});

function fileFilter(_req, file, cb) {
  const allowed = ['.pdf', '.png', '.jpg', '.jpeg'];
  const ext = path.extname(file.originalname).toLowerCase();
  if (!allowed.includes(ext)) return cb(new Error('Invalid file type'));
  cb(null, true);
}

export const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

export async function getMe(req, res) {
  const me = await User.findByPk(req.user.sub, { attributes: { exclude: ['passwordHash'] } });
  return res.json(me);
}

export async function updateMe(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, contact, address, city, qualifications } = req.body;
  const user = await User.findByPk(req.user.sub);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.name = name ?? user.name;
  user.contact = contact ?? user.contact;
  user.address = address ?? user.address;
  user.city = city ?? user.city;
  user.qualifications = qualifications ?? user.qualifications;
  await user.save();
  return res.json({ message: 'Updated' });
}

export async function uploadResume(req, res) {
  if (!req.file) return res.status(400).json({ error: 'File required' });
  const user = await User.findByPk(req.user.sub);
  user.resumeUrl = `/uploads/resumes/${req.file.filename}`;
  await user.save();
  return res.json({ resumeUrl: user.resumeUrl });
}

export async function uploadCertificate(req, res) {
  if (!req.file) return res.status(400).json({ error: 'File required' });
  const cert = await Certificate.create({ userId: req.user.sub, title: req.body.title, fileUrl: `/uploads/certificates/${req.file.filename}` });
  return res.json(cert);
}

export async function listCertificates(req, res) {
  const certs = await Certificate.findAll({ where: { userId: req.user.sub } });
  return res.json(certs);
}

export async function deleteCertificate(req, res) {
  const id = req.params.id;
  const cert = await Certificate.findByPk(id);
  if (!cert || cert.userId !== req.user.sub) return res.status(404).json({ error: 'Not found' });
  await cert.destroy();
  return res.json({ message: 'Deleted' });
}
