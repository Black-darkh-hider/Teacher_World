import { Op, fn, col, literal } from 'sequelize';
import { validationResult } from 'express-validator';
import { Job, JobApplication, User, sequelize } from '../models/index.js';

export async function createJob(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { title, description, requiredQualifications, city, salary, tags, latitude, longitude } = req.body;
  const job = await Job.create({ employerId: req.user.sub, title, description, requiredQualifications, city, salary, tags, latitude, longitude });
  return res.status(201).json(job);
}

export async function searchJobs(req, res) {
  const { q, city, tags, lat, lng, radiusKm } = req.query;
  const where = {};
  if (q) where[Op.or] = [{ title: { [Op.like]: `%${q}%` } }, { description: { [Op.like]: `%${q}%` } }];
  if (city) where.city = city;
  if (tags) where.tags = { [Op.like]: `%${tags}%` };

  let geoOrder = [];
  if (lat && lng && radiusKm && sequelize.getDialect() !== 'sqlite') {
    // Haversine distance filter using raw SQL
    const distance = literal(
      `(6371 * acos(cos(radians(${Number(lat)})) * cos(radians(latitude)) * cos(radians(longitude) - radians(${Number(lng)})) + sin(radians(${Number(lat)})) * sin(radians(latitude))))`
    );
    where[Op.and] = [literal(`${distance.sql || distance.val} <= ${Number(radiusKm)}`)];
    geoOrder = [[distance, 'ASC']];
  }

  const jobs = await Job.findAll({ where, order: geoOrder.length ? geoOrder : [['createdAt', 'DESC']] });
  return res.json(jobs);
}

export async function applyJob(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { jobId, coverLetter } = req.body;
  const job = await Job.findByPk(jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const application = await JobApplication.create({ jobId: job.id, teacherId: req.user.sub, coverLetter });

  // Notify employer (email optional)
  const employer = await User.findByPk(job.employerId);
  if (process.env.SMTP_HOST && employer) {
    // best-effort; do not await
    import('../services/mailer.service.js').then(({ sendEmail }) =>
      sendEmail({
        to: employer.email,
        subject: 'New Job Application',
        html: `<p>You have a new application for <b>${job.title}</b>.</p>`,
        text: `New application for ${job.title}`,
      }).catch(() => {})
    );
  }

  return res.status(201).json(application);
}
