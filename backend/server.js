
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve frontend static files (optional)
app.use('/', express.static(path.join(__dirname, '..', 'frontend')));

// DB Setup
const dbFile = path.join(__dirname, "database.db");
const db = new sqlite3.Database(dbFile);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      otp TEXT,
      expiry INTEGER
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT,
      phone TEXT,
      subject TEXT,
      message TEXT
  )`);
});

// Helper to delete old OTPs
function cleanupOtps() {
  const now = Date.now();
  db.run("DELETE FROM otps WHERE expiry < ?", [now]);
}

// Contact endpoint
app.post("/api/contact", (req, res) => {
  const { name, email, phone, subject, message } = req.body;
  if (!name || !email || !subject || !message) {
    return res.status(400).json({ success:false, message: "Missing required fields" });
  }
  db.run(
    "INSERT INTO messages (name, email, phone, subject, message) VALUES (?, ?, ?, ?, ?)",
    [name, email, phone || '', subject, message],
    function (err) {
      if (err) return res.status(500).json({ success:false, error: err.message });
      res.json({ success: true, message: "Message saved successfully!" });
    }
  );
});

// Request OTP
app.post("/api/request-otp", (req, res) => {
  const { email, username } = req.body;
  if (!email && !username) {
    return res.status(400).json({ success:false, message: "Provide email or username" });
  }
  // For demo: if username provided, try to find email
  const findEmail = new Promise((resolve, reject) => {
    if (email) return resolve(email);
    db.get("SELECT email FROM users WHERE username = ?", [username], (err, row) => {
      if (err) return reject(err);
      if (!row) return reject(new Error("User not found"));
      resolve(row.email);
    });
  });

  findEmail.then((finalEmail) => {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = Date.now() + 5*60*1000; // 5 minutes
    db.run("INSERT INTO otps (email, otp, expiry) VALUES (?, ?, ?)", [finalEmail, otp, expiry], (err) => {
      if (err) return res.status(500).json({ success:false, error: err.message });
      console.log(`*** OTP for ${finalEmail}: ${otp} (valid 5 minutes) ***`);
      cleanupOtps();
      res.json({ success:true, message: "OTP generated and logged on server console (demo)." });
    });
  }).catch(err=>{
    res.status(400).json({ success:false, message: err.message });
  });
});

// Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ success:false, message: "Provide email and otp" });
  db.get("SELECT * FROM otps WHERE email = ? AND otp = ?", [email, otp], (err, row) => {
    if (err) return res.status(500).json({ success:false, error: err.message });
    if (!row) return res.status(400).json({ success:false, message: "Invalid OTP" });
    if (row.expiry < Date.now()) return res.status(400).json({ success:false, message: "OTP expired" });
    // Optionally delete OTP after use
    db.run("DELETE FROM otps WHERE id = ?", [row.id]);
    res.json({ success:true, message: "OTP verified" });
  });
});

// Reset password
app.post("/api/reset-password", (req, res) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) return res.status(400).json({ success:false, message: "Provide email and newPassword" });
  db.run("UPDATE users SET password = ? WHERE email = ?", [newPassword, email], function(err) {
    if (err) return res.status(500).json({ success:false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ success:false, message: "User not found" });
    res.json({ success:true, message: "Password updated" });
  });
});

// Reset username
app.post("/api/reset-username", (req, res) => {
  const { email, newUsername } = req.body;
  if (!email || !newUsername) return res.status(400).json({ success:false, message: "Provide email and newUsername" });
  db.run("UPDATE users SET username = ? WHERE email = ?", [newUsername, email], function(err) {
    if (err) return res.status(500).json({ success:false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ success:false, message: "User not found" });
    res.json({ success:true, message: "Username updated" });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`Server running on http://localhost:${PORT}`));
