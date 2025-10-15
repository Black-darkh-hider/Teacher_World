import jwt from 'jsonwebtoken';
import { User } from '../models/index.js';

export function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function requireRole(role) {
  return async (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const user = await User.findByPk(req.user.sub);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.role !== role && user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
  };
}
