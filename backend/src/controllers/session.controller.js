import { validationResult } from 'express-validator';
import { Session } from '../models/index.js';
import { randomUUID } from 'crypto';

export async function createSession(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { title, startsAt } = req.body;
  const meetingId = `teacherworld-${randomUUID()}`;
  const session = await Session.create({ hostId: req.user.sub, title, startsAt, meetingId, provider: 'jitsi' });
  return res.status(201).json(session);
}

export async function listSessions(req, res) {
  const items = await Session.findAll({ where: { hostId: req.user.sub }, order: [['createdAt', 'DESC']] });
  return res.json(items);
}
