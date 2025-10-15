
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { body, query, param, validationResult } = require("express-validator");
const multer = require("multer");
const nodemailer = require("nodemailer");
const { customAlphabet } = require("nanoid");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();

// CORS
const allowedOrigin = process.env.FRONTEND_ORIGIN || "*";
app.use(
  cors({
    origin: allowedOrigin === "*" ? true : allowedOrigin,
    credentials: true,
  })
);
app.use(bodyParser.json({ limit: "2mb" }));

// Static frontend (optional)
app.use("/", express.static(path.join(__dirname, "..", "frontend")));

// Static uploads
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use("/uploads", express.static(uploadsDir));

// SQLite DB setup and helpers
const dbFile = path.join(__dirname, "database.db");
const db = new sqlite3.Database(dbFile);

const dbRun = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
const dbGet = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
const dbAll = (sql, params = []) =>
  new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });

db.serialize(async () => {
  db.run("PRAGMA foreign_keys = ON");
  // Base tables
  await dbRun(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      is_verified INTEGER DEFAULT 0,
      role TEXT DEFAULT 'teacher',
      name TEXT,
      contact TEXT,
      address TEXT,
      city TEXT,
      qualifications TEXT,
      created_at INTEGER,
      updated_at INTEGER
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      purpose TEXT NOT NULL,
      otp_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      attempt_count INTEGER DEFAULT 0,
      created_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked INTEGER DEFAULT 0,
      created_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      employer_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      qualifications TEXT,
      city TEXT,
      salary TEXT,
      tags TEXT,
      lat REAL,
      lng REAL,
      created_at INTEGER,
      updated_at INTEGER,
      FOREIGN KEY(employer_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS job_applications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id INTEGER NOT NULL,
      teacher_id INTEGER NOT NULL,
      cover_letter TEXT,
      status TEXT DEFAULT 'applied',
      created_at INTEGER,
      FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE,
      FOREIGN KEY(teacher_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS user_files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_name TEXT,
      mime_type TEXT,
      size INTEGER,
      created_at INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS study_materials (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      uploader_id INTEGER NOT NULL,
      subject TEXT,
      grade TEXT,
      title TEXT,
      description TEXT,
      type TEXT CHECK (type IN ('file','link')) NOT NULL,
      file_id INTEGER,
      link_url TEXT,
      created_at INTEGER,
      FOREIGN KEY(uploader_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(file_id) REFERENCES user_files(id) ON DELETE SET NULL
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      creator_id INTEGER NOT NULL,
      room_name TEXT NOT NULL,
      jitsi_url TEXT NOT NULL,
      scheduled_at INTEGER,
      created_at INTEGER,
      FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  await dbRun(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT,
      phone TEXT,
      subject TEXT,
      message TEXT
  )`);

  // Attempt to migrate old users table columns if present
  const existingUserCols = await dbAll("PRAGMA table_info(users)");
  const colNames = new Set(existingUserCols.map((c) => c.name));
  const addCol = async (name, type) => {
    try {
      await dbRun(`ALTER TABLE users ADD COLUMN ${name} ${type}`);
    } catch (_) {
      // ignore if exists
    }
  };
  if (!colNames.has("password_hash")) await addCol("password_hash", "TEXT");
  if (!colNames.has("is_verified")) await addCol("is_verified", "INTEGER DEFAULT 0");
  if (!colNames.has("role")) await addCol("role", "TEXT DEFAULT 'teacher'");
  if (!colNames.has("name")) await addCol("name", "TEXT");
  if (!colNames.has("contact")) await addCol("contact", "TEXT");
  if (!colNames.has("address")) await addCol("address", "TEXT");
  if (!colNames.has("city")) await addCol("city", "TEXT");
  if (!colNames.has("qualifications")) await addCol("qualifications", "TEXT");
  if (!colNames.has("created_at")) await addCol("created_at", "INTEGER");
  if (!colNames.has("updated_at")) await addCol("updated_at", "INTEGER");
});

// Rate limiters
const otpLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });

// Email transporter
const smtpTransporter = (() => {
  if (
    process.env.EMAIL_HOST &&
    process.env.EMAIL_PORT &&
    process.env.EMAIL_USER &&
    process.env.EMAIL_PASS
  ) {
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST,
      port: Number(process.env.EMAIL_PORT),
      secure: Number(process.env.EMAIL_PORT) === 465,
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
  }
  return nodemailer.createTransport({ jsonTransport: true });
})();

async function sendEmail({ to, subject, text, html }) {
  const from = process.env.EMAIL_FROM || "no-reply@teacherworld.local";
  const info = await smtpTransporter.sendMail({ from, to, subject, text, html });
  if (smtpTransporter.options.jsonTransport) {
    // eslint-disable-next-line no-console
    console.log("[Email JSON Transport]", info.message);
  }
  return info;
}

// Utils
const OTP_SECRET = process.env.OTP_SECRET || "dev-otp-secret";
const JWT_SECRET = process.env.JWT_SECRET || "dev-jwt-secret";
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || "15m";
const REFRESH_TOKEN_TTL_MS = Number(process.env.REFRESH_TOKEN_TTL_MS || 7 * 24 * 60 * 60 * 1000);
const generateOtpCode = () => Math.floor(100000 + Math.random() * 900000).toString();
function hashOtp(otp, email, purpose) {
  return crypto.createHmac("sha256", OTP_SECRET).update(`${email}|${purpose}|${otp}`).digest("hex");
}
function generateAccessToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL });
}
function generateRefreshTokenValue() {
  return crypto.randomBytes(48).toString("hex");
}
function hashToken(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
const nowMs = () => Date.now();
const nanoid = customAlphabet("abcdefghijklmnopqrstuvwxyz0123456789", 21);

// Async handler wrapper
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Auth middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ success: false, message: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.sub, role: payload.role };
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
}
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) return res.status(403).json({ success: false, message: "Forbidden" });
    next();
  };
}

// Validation error formatter
function handleValidation(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
}

// Contact endpoint (kept)
app.post(
  "/api/contact",
  [
    body("name").isString().trim().notEmpty(),
    body("email").isEmail().normalizeEmail(),
    body("subject").isString().trim().notEmpty(),
    body("message").isString().trim().notEmpty(),
    body("phone").optional().isString().trim(),
  ],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { name, email, phone, subject, message } = req.body;
    await dbRun(
      "INSERT INTO messages (name, email, phone, subject, message) VALUES (?, ?, ?, ?, ?)",
      [name, email, phone || "", subject, message]
    );
    return res.json({ success: true, message: "Message saved successfully!" });
  })
);

// Auth: register -> send OTP
app.post(
  "/api/auth/register",
  authLimiter,
  [
    body("email").isEmail().normalizeEmail(),
    body("password").isString().isLength({ min: 8 }),
    body("name").optional().isString(),
    body("role").optional().isIn(["teacher", "employer"]).withMessage("Invalid role"),
  ],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { email, password, name } = req.body;
    const desiredRole = req.body.role === "employer" ? "employer" : "teacher";
    const existing = await dbGet("SELECT id, is_verified FROM users WHERE email = ?", [email]);
    if (existing && existing.is_verified) {
      return res.status(400).json({ success: false, message: "User already registered" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const timestamp = nowMs();
    let userId;
    if (existing) {
      await dbRun(
        "UPDATE users SET password_hash = ?, name = ?, role = COALESCE(role, ?), updated_at = ? WHERE id = ?",
        [passwordHash, name || null, desiredRole, timestamp, existing.id]
      );
      userId = existing.id;
    } else {
      const result = await dbRun(
        "INSERT INTO users (email, password_hash, name, is_verified, role, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?, ?)",
        [email, passwordHash, name || null, desiredRole, timestamp, timestamp]
      );
      userId = result.lastID;
    }

    const purpose = "register";
    const otp = generateOtpCode();
    const otpHash = hashOtp(otp, email, purpose);
    const expiresAt = nowMs() + 10 * 60 * 1000;
    await dbRun(
      "INSERT INTO otp_codes (user_id, purpose, otp_hash, expires_at, used, attempt_count, created_at) VALUES (?, ?, ?, ?, 0, 0, ?)",
      [userId, purpose, otpHash, expiresAt, timestamp]
    );

    await sendEmail({
      to: email,
      subject: "Your TeacherWorld verification code",
      text: `Your verification code is ${otp}. It expires in 10 minutes.`,
      html: `<p>Your verification code is <b>${otp}</b>. It expires in 10 minutes.</p>`,
    });

    return res.json({ success: true, message: "OTP sent to email." });
  })
);

// Resend OTP
app.post(
  "/api/auth/resend-otp",
  otpLimiter,
  [body("email").isEmail().normalizeEmail(), body("purpose").optional().isIn(["register"])],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { email } = req.body;
    const user = await dbGet("SELECT id, is_verified FROM users WHERE email = ?", [email]);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.is_verified) return res.status(400).json({ success: false, message: "Already verified" });

    const lastOtp = await dbGet(
      "SELECT created_at FROM otp_codes WHERE user_id = ? AND purpose = 'register' ORDER BY id DESC LIMIT 1",
      [user.id]
    );
    if (lastOtp && nowMs() - lastOtp.created_at < 60 * 1000) {
      return res.status(429).json({ success: false, message: "Please wait before requesting another OTP" });
    }

    const otp = generateOtpCode();
    const otpHash = hashOtp(otp, email, "register");
    const expiresAt = nowMs() + 10 * 60 * 1000;
    await dbRun(
      "INSERT INTO otp_codes (user_id, purpose, otp_hash, expires_at, used, attempt_count, created_at) VALUES (?, 'register', ?, ?, 0, 0, ?)",
      [user.id, otpHash, expiresAt, nowMs()]
    );

    await sendEmail({
      to: email,
      subject: "Your TeacherWorld verification code",
      text: `Your verification code is ${otp}. It expires in 10 minutes.`,
      html: `<p>Your verification code is <b>${otp}</b>. It expires in 10 minutes.</p>`,
    });

    return res.json({ success: true, message: "OTP sent to email." });
  })
);

// Verify OTP
app.post(
  "/api/auth/verify-otp",
  otpLimiter,
  [body("email").isEmail().normalizeEmail(), body("otp").isString().isLength({ min: 6, max: 6 })],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { email, otp } = req.body;
    const user = await dbGet("SELECT id, is_verified FROM users WHERE email = ?", [email]);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.is_verified) return res.status(400).json({ success: false, message: "Already verified" });

    const record = await dbGet(
      "SELECT * FROM otp_codes WHERE user_id = ? AND purpose = 'register' AND used = 0 ORDER BY id DESC LIMIT 1",
      [user.id]
    );
    if (!record) return res.status(400).json({ success: false, message: "No OTP. Please request a new one." });
    if (record.expires_at < nowMs()) return res.status(400).json({ success: false, message: "OTP expired" });
    const expectedHash = hashOtp(otp, email, "register");
    if (expectedHash !== record.otp_hash) {
      await dbRun("UPDATE otp_codes SET attempt_count = attempt_count + 1 WHERE id = ?", [record.id]);
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    await dbRun("UPDATE otp_codes SET used = 1 WHERE id = ?", [record.id]);
    await dbRun("UPDATE users SET is_verified = 1, updated_at = ? WHERE id = ?", [nowMs(), user.id]);
    return res.json({ success: true, message: "Email verified successfully." });
  })
);

// Login -> issue JWT and refresh token
app.post(
  "/api/auth/login",
  authLimiter,
  [body("email").isEmail().normalizeEmail(), body("password").isString().isLength({ min: 8 })],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { email, password } = req.body;
    const user = await dbGet("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });
    if (!user.is_verified) return res.status(403).json({ success: false, message: "Email not verified" });
    if (!user.password_hash) return res.status(401).json({ success: false, message: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const accessToken = generateAccessToken(user);
    const refreshValue = generateRefreshTokenValue();
    const refreshHash = hashToken(refreshValue);
    await dbRun(
      "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
      [user.id, refreshHash, nowMs() + REFRESH_TOKEN_TTL_MS, nowMs()]
    );
    return res.json({ success: true, accessToken, refreshToken: refreshValue });
  })
);

// Refresh token rotation
app.post(
  "/api/auth/refresh",
  authLimiter,
  [body("refreshToken").isString()],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { refreshToken } = req.body;
    const tokenHash = hashToken(refreshToken);
    const row = await dbGet(
      "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
      [tokenHash]
    );
    if (!row || row.expires_at < nowMs()) return res.status(401).json({ success: false, message: "Invalid refresh token" });
    const user = await dbGet("SELECT * FROM users WHERE id = ?", [row.user_id]);
    if (!user) return res.status(401).json({ success: false, message: "Invalid refresh token" });

    // Rotate
    await dbRun("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", [row.id]);
    const newValue = generateRefreshTokenValue();
    await dbRun(
      "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at) VALUES (?, ?, ?, 0, ?)",
      [user.id, hashToken(newValue), nowMs() + REFRESH_TOKEN_TTL_MS, nowMs()]
    );
    const accessToken = generateAccessToken(user);
    return res.json({ success: true, accessToken, refreshToken: newValue });
  })
);

// Logout
app.post(
  "/api/auth/logout",
  authLimiter,
  [body("refreshToken").isString()],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { refreshToken } = req.body;
    const tokenHash = hashToken(refreshToken);
    await dbRun("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", [tokenHash]);
    return res.json({ success: true });
  })
);

// Profile endpoints
app.get(
  "/api/me",
  requireAuth,
  asyncHandler(async (req, res) => {
    const user = await dbGet(
      "SELECT id, email, role, name, contact, address, city, qualifications, created_at, updated_at FROM users WHERE id = ?",
      [req.user.id]
    );
    return res.json({ success: true, user });
  })
);

app.put(
  "/api/me",
  requireAuth,
  [
    body("name").optional().isString(),
    body("contact").optional().isString(),
    body("address").optional().isString(),
    body("city").optional().isString(),
    body("qualifications").optional().isString(),
  ],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { name, contact, address, city, qualifications } = req.body;
    const ts = nowMs();
    await dbRun(
      "UPDATE users SET name = COALESCE(?, name), contact = COALESCE(?, contact), address = COALESCE(?, address), city = COALESCE(?, city), qualifications = COALESCE(?, qualifications), updated_at = ? WHERE id = ?",
      [name || null, contact || null, address || null, city || null, qualifications || null, ts, req.user.id]
    );
    return res.json({ success: true });
  })
);

// Multer setup for uploads
const allowedMime = new Set(["application/pdf", "image/png", "image/jpeg"]);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const safeBase = file.originalname.replace(/[^a-z0-9.\-_]/gi, "_").toLowerCase();
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${safeBase}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (allowedMime.has(file.mimetype)) cb(null, true);
    else cb(new Error("Invalid file type"));
  },
});

// Upload resume (one)
app.post(
  "/api/me/resume",
  requireAuth,
  upload.single("file"),
  asyncHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "File required" });
    const ts = nowMs();
    const existing = await dbGet("SELECT * FROM user_files WHERE user_id = ? AND type = 'resume'", [req.user.id]);
    if (existing) {
      try { fs.unlinkSync(path.join(uploadsDir, existing.filename)); } catch (_) {}
      await dbRun("DELETE FROM user_files WHERE id = ?", [existing.id]);
    }
    const result = await dbRun(
      "INSERT INTO user_files (user_id, type, filename, original_name, mime_type, size, created_at) VALUES (?, 'resume', ?, ?, ?, ?, ?)",
      [req.user.id, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, ts]
    );
    return res.json({ success: true, fileId: result.lastID, url: `/uploads/${req.file.filename}` });
  })
);

// Upload certificates (multiple)
app.post(
  "/api/me/certificates",
  requireAuth,
  upload.array("files", 10),
  asyncHandler(async (req, res) => {
    if (!req.files || req.files.length === 0)
      return res.status(400).json({ success: false, message: "Files required" });
    const ts = nowMs();
    for (const f of req.files) {
      await dbRun(
        "INSERT INTO user_files (user_id, type, filename, original_name, mime_type, size, created_at) VALUES (?, 'certificate', ?, ?, ?, ?, ?)",
        [req.user.id, f.filename, f.originalname, f.mimetype, f.size, ts]
      );
    }
    return res.json({ success: true });
  })
);

// List my files
app.get(
  "/api/me/files",
  requireAuth,
  asyncHandler(async (req, res) => {
    const files = await dbAll("SELECT id, type, filename, original_name, mime_type, size, created_at FROM user_files WHERE user_id = ? ORDER BY created_at DESC", [req.user.id]);
    const withUrls = files.map((f) => ({ ...f, url: `/uploads/${f.filename}` }));
    return res.json({ success: true, files: withUrls });
  })
);

// Delete a file
app.delete(
  "/api/me/files/:fileId",
  requireAuth,
  [param("fileId").isInt()],
  asyncHandler(async (req, res) => {
    const file = await dbGet("SELECT * FROM user_files WHERE id = ? AND user_id = ?", [req.params.fileId, req.user.id]);
    if (!file) return res.status(404).json({ success: false, message: "File not found" });
    try { fs.unlinkSync(path.join(uploadsDir, file.filename)); } catch (_) {}
    await dbRun("DELETE FROM user_files WHERE id = ?", [file.id]);
    return res.json({ success: true });
  })
);

// Employer: create job
app.post(
  "/api/jobs",
  requireAuth,
  requireRole("employer"),
  [
    body("title").isString().trim().notEmpty(),
    body("description").isString().trim().notEmpty(),
    body("qualifications").optional().isString(),
    body("city").optional().isString(),
    body("salary").optional().isString(),
    body("tags").optional().isArray(),
    body("lat").optional().isFloat({ min: -90, max: 90 }),
    body("lng").optional().isFloat({ min: -180, max: 180 }),
  ],
  asyncHandler(async (req, res) => {
    if (handleValidation(req, res)) return;
    const { title, description, qualifications, city, salary, tags, lat, lng } = req.body;
    const ts = nowMs();
    const result = await dbRun(
      "INSERT INTO jobs (employer_id, title, description, qualifications, city, salary, tags, lat, lng, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      [req.user.id, title, description, qualifications || null, city || null, salary || null, (tags || []).join(","), lat || null, lng || null, ts, ts]
    );
    return res.json({ success: true, jobId: result.lastID });
  })
);

// Employer: update job
app.put(
  "/api/jobs/:id",
  requireAuth,
  requireRole("employer"),
  [param("id").isInt()],
  asyncHandler(async (req, res) => {
    const job = await dbGet("SELECT * FROM jobs WHERE id = ? AND employer_id = ?", [req.params.id, req.user.id]);
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    const { title, description, qualifications, city, salary, tags, lat, lng } = req.body;
    const ts = nowMs();
    await dbRun(
      "UPDATE jobs SET title = COALESCE(?, title), description = COALESCE(?, description), qualifications = COALESCE(?, qualifications), city = COALESCE(?, city), salary = COALESCE(?, salary), tags = COALESCE(?, tags), lat = COALESCE(?, lat), lng = COALESCE(?, lng), updated_at = ? WHERE id = ?",
      [title || null, description || null, qualifications || null, city || null, salary || null, (tags || null) ? (tags || []).join(",") : null, lat || null, lng || null, ts, job.id]
    );
    return res.json({ success: true });
  })
);

// Employer: delete job
app.delete(
  "/api/jobs/:id",
  requireAuth,
  requireRole("employer"),
  [param("id").isInt()],
  asyncHandler(async (req, res) => {
    await dbRun("DELETE FROM jobs WHERE id = ? AND employer_id = ?", [req.params.id, req.user.id]);
    return res.json({ success: true });
  })
);

// Employer: list own jobs
app.get(
  "/api/employer/jobs",
  requireAuth,
  requireRole("employer"),
  asyncHandler(async (req, res) => {
    const jobs = await dbAll("SELECT * FROM jobs WHERE employer_id = ? ORDER BY created_at DESC", [req.user.id]);
    return res.json({ success: true, jobs });
  })
);

// Public/Teacher: search jobs
app.get(
  "/api/jobs",
  [
    query("q").optional().isString(),
    query("city").optional().isString(),
    query("tags").optional().isString(),
    query("page").optional().isInt({ min: 1 }),
    query("pageSize").optional().isInt({ min: 1, max: 100 }),
  ],
  asyncHandler(async (req, res) => {
    const q = (req.query.q || "").trim();
    const city = (req.query.city || "").trim();
    const tags = (req.query.tags || "").trim();
    const page = parseInt(req.query.page || "1", 10);
    const pageSize = parseInt(req.query.pageSize || "20", 10);
    const offset = (page - 1) * pageSize;

    let where = [];
    let params = [];
    if (q) {
      where.push("(title LIKE ? OR description LIKE ?)");
      params.push(`%${q}%`, `%${q}%`);
    }
    if (city) {
      where.push("city = ?");
      params.push(city);
    }
    if (tags) {
      const taglist = tags.split(",").map((t) => t.trim()).filter(Boolean);
      for (const t of taglist) {
        where.push("tags LIKE ?");
        params.push(`%${t}%`);
      }
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const jobs = await dbAll(
      `SELECT * FROM jobs ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );
    return res.json({ success: true, jobs, page, pageSize });
  })
);

// Teacher: apply to a job
app.post(
  "/api/jobs/:id/apply",
  requireAuth,
  [param("id").isInt(), body("coverLetter").optional().isString()],
  asyncHandler(async (req, res) => {
    // Teachers only
    const me = await dbGet("SELECT role, email FROM users WHERE id = ?", [req.user.id]);
    if (!me || me.role !== "teacher") return res.status(403).json({ success: false, message: "Only teachers can apply" });
    const job = await dbGet("SELECT jobs.*, users.email as employer_email FROM jobs JOIN users ON jobs.employer_id = users.id WHERE jobs.id = ?", [req.params.id]);
    if (!job) return res.status(404).json({ success: false, message: "Job not found" });
    const ts = nowMs();
    await dbRun(
      "INSERT INTO job_applications (job_id, teacher_id, cover_letter, status, created_at) VALUES (?, ?, ?, 'applied', ?)",
      [job.id, req.user.id, req.body.coverLetter || null, ts]
    );

    await sendEmail({
      to: job.employer_email,
      subject: "New job application",
      text: `A teacher (${me.email}) applied to your job '${job.title}'.`,
    });

    return res.json({ success: true });
  })
);

// Teacher: list my applications
app.get(
  "/api/teacher/applications",
  requireAuth,
  asyncHandler(async (req, res) => {
    const me = await dbGet("SELECT role FROM users WHERE id = ?", [req.user.id]);
    if (!me || me.role !== "teacher") return res.status(403).json({ success: false, message: "Forbidden" });
    const apps = await dbAll(
      "SELECT job_applications.*, jobs.title, jobs.city FROM job_applications JOIN jobs ON job_applications.job_id = jobs.id WHERE job_applications.teacher_id = ? ORDER BY job_applications.created_at DESC",
      [req.user.id]
    );
    return res.json({ success: true, applications: apps });
  })
);

// Study materials: upload file
app.post(
  "/api/study-materials/upload",
  requireAuth,
  upload.single("file"),
  [
    body("subject").isString(),
    body("grade").isString(),
    body("title").isString(),
    body("description").optional().isString(),
  ],
  asyncHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "File required" });
    const ts = nowMs();
    const fileRes = await dbRun(
      "INSERT INTO user_files (user_id, type, filename, original_name, mime_type, size, created_at) VALUES (?, 'material', ?, ?, ?, ?, ?)",
      [req.user.id, req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, ts]
    );
    const materialRes = await dbRun(
      "INSERT INTO study_materials (uploader_id, subject, grade, title, description, type, file_id, created_at) VALUES (?, ?, ?, ?, ?, 'file', ?, ?)",
      [req.user.id, req.body.subject, req.body.grade, req.body.title, req.body.description || null, fileRes.lastID, ts]
    );
    return res.json({ success: true, id: materialRes.lastID, url: `/uploads/${req.file.filename}` });
  })
);

// Study materials: add link
app.post(
  "/api/study-materials/link",
  requireAuth,
  [body("subject").isString(), body("grade").isString(), body("title").isString(), body("linkUrl").isURL()],
  asyncHandler(async (req, res) => {
    const ts = nowMs();
    const result = await dbRun(
      "INSERT INTO study_materials (uploader_id, subject, grade, title, description, type, link_url, created_at) VALUES (?, ?, ?, ?, ?, 'link', ?, ?)",
      [req.user.id, req.body.subject, req.body.grade, req.body.title, req.body.description || null, req.body.linkUrl, ts]
    );
    return res.json({ success: true, id: result.lastID });
  })
);

// Study materials: search
app.get(
  "/api/study-materials",
  [query("subject").optional().isString(), query("grade").optional().isString(), query("q").optional().isString()],
  asyncHandler(async (req, res) => {
    const subject = (req.query.subject || "").trim();
    const grade = (req.query.grade || "").trim();
    const q = (req.query.q || "").trim();
    let where = [];
    let params = [];
    if (subject) { where.push("subject = ?"); params.push(subject); }
    if (grade) { where.push("grade = ?"); params.push(grade); }
    if (q) { where.push("(title LIKE ? OR description LIKE ?)"); params.push(`%${q}%`, `%${q}%`); }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const rows = await dbAll(`SELECT * FROM study_materials ${whereSql} ORDER BY created_at DESC`, params);
    const result = [];
    for (const r of rows) {
      if (r.type === "file" && r.file_id) {
        const f = await dbGet("SELECT filename FROM user_files WHERE id = ?", [r.file_id]);
        result.push({ ...r, url: f ? `/uploads/${f.filename}` : null });
      } else {
        result.push(r);
      }
    }
    return res.json({ success: true, materials: result });
  })
);

// Live sessions (Jitsi)
app.post(
  "/api/sessions",
  requireAuth,
  [body("title").optional().isString(), body("scheduledAt").optional().isISO8601(), body("invitees").optional().isArray()],
  asyncHandler(async (req, res) => {
    const base = process.env.JITSI_BASE_URL || "https://meet.jit.si";
    const room = `${nanoid()}-${Date.now()}`;
    const jitsiUrl = `${base}/${room}`;
    const ts = nowMs();
    const scheduledAt = req.body.scheduledAt ? new Date(req.body.scheduledAt).getTime() : null;
    const result = await dbRun(
      "INSERT INTO sessions (creator_id, room_name, jitsi_url, scheduled_at, created_at) VALUES (?, ?, ?, ?, ?)",
      [req.user.id, req.body.title || room, jitsiUrl, scheduledAt, ts]
    );

    const invitees = Array.isArray(req.body.invitees) ? req.body.invitees : [];
    if (invitees.length) {
      for (const to of invitees) {
        await sendEmail({
          to,
          subject: "Class session invite",
          text: `You are invited to a live session: ${jitsiUrl}`,
        });
      }
    }
    return res.json({ success: true, id: result.lastID, url: jitsiUrl });
  })
);

app.get(
  "/api/sessions",
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = await dbAll("SELECT * FROM sessions WHERE creator_id = ? ORDER BY created_at DESC", [req.user.id]);
    return res.json({ success: true, sessions: rows });
  })
);

// Health
app.get("/api/health", (req, res) => res.json({ ok: true }));

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  // eslint-disable-next-line no-console
  console.error(err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: err.message });
  }
  return res.status(500).json({ success: false, message: "Internal Server Error" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
