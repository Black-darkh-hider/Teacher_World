
require('dotenv').config();
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const validator = require("validator");

// Import services
const emailService = require('./services/emailService');
const authService = require('./services/authService');
const logger = require('./services/logger');

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// OTP specific rate limiting
const otpLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // limit each IP to 3 OTP requests per 5 minutes
  message: 'Too many OTP requests, please try again later.'
});

app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true }));

// Serve frontend static files (optional)
app.use('/', express.static(path.join(__dirname, '..', 'frontend')));

// DB Setup
const dbFile = path.join(__dirname, "database.db");
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    logger.error('Database connection failed', { error: err.message });
  } else {
    logger.info('Connected to SQLite database');
  }
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      email TEXT UNIQUE,
      password TEXT,
      is_verified BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS otps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      otp TEXT,
      type TEXT DEFAULT 'password_reset',
      expiry INTEGER,
      used BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT,
      phone TEXT,
      subject TEXT,
      message TEXT,
      status TEXT DEFAULT 'unread',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT,
      ip_address TEXT,
      success BOOLEAN,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Helper functions
function cleanupOtps() {
  const now = Date.now();
  db.run("DELETE FROM otps WHERE expiry < ? OR used = 1", [now], (err) => {
    if (err) logger.error('OTP cleanup failed', { error: err.message });
  });
}

function logLoginAttempt(email, ipAddress, success) {
  db.run(
    "INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)",
    [email, ipAddress, success],
    (err) => {
      if (err) logger.error('Failed to log login attempt', { error: err.message });
    }
  );
}

// Middleware to validate input
function validateInput(req, res, next) {
  const { email, password, username } = req.body;
  
  if (email && !validator.isEmail(email)) {
    return res.status(400).json({ success: false, message: "Invalid email format" });
  }
  
  if (password && !authService.isValidPassword(password)) {
    return res.status(400).json({ 
      success: false, 
      message: "Password must be at least 8 characters with uppercase, lowercase, and number" 
    });
  }
  
  if (username && (username.length < 3 || username.length > 20)) {
    return res.status(400).json({ 
      success: false, 
      message: "Username must be between 3 and 20 characters" 
    });
  }
  
  next();
}

// Clean up expired OTPs every 5 minutes
setInterval(cleanupOtps, 5 * 60 * 1000);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Teacher World API is running',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Contact endpoint
app.post("/api/contact", validateInput, (req, res) => {
  const { name, email, phone, subject, message } = req.body;
  
  // Sanitize inputs
  const sanitizedData = {
    name: authService.sanitizeInput(name),
    email: authService.sanitizeInput(email),
    phone: authService.sanitizeInput(phone || ''),
    subject: authService.sanitizeInput(subject),
    message: authService.sanitizeInput(message)
  };

  if (!sanitizedData.name || !sanitizedData.email || !sanitizedData.subject || !sanitizedData.message) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  db.run(
    "INSERT INTO messages (name, email, phone, subject, message) VALUES (?, ?, ?, ?, ?)",
    [sanitizedData.name, sanitizedData.email, sanitizedData.phone, sanitizedData.subject, sanitizedData.message],
    function (err) {
      if (err) {
        logger.error('Failed to save contact message', { error: err.message, email: sanitizedData.email });
        return res.status(500).json({ success: false, message: "Failed to save message" });
      }
      
      logger.info('Contact message saved', { messageId: this.lastID, email: sanitizedData.email });
      res.json({ success: true, message: "Message saved successfully!", id: this.lastID });
    }
  );
});

// User registration
app.post("/api/register", validateInput, async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    const sanitizedData = {
      username: authService.sanitizeInput(username),
      email: authService.sanitizeInput(email).toLowerCase()
    };

    // Check if user already exists
    db.get("SELECT id FROM users WHERE email = ? OR username = ?", [sanitizedData.email, sanitizedData.username], async (err, row) => {
      if (err) {
        logger.error('Database error during registration', { error: err.message });
        return res.status(500).json({ success: false, message: "Registration failed" });
      }
      
      if (row) {
        return res.status(400).json({ success: false, message: "User already exists" });
      }

      try {
        const hashedPassword = await authService.hashPassword(password);
        
        db.run(
          "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
          [sanitizedData.username, sanitizedData.email, hashedPassword],
          function (err) {
            if (err) {
              logger.error('Failed to create user', { error: err.message, email: sanitizedData.email });
              return res.status(500).json({ success: false, message: "Registration failed" });
            }
            
            logger.info('User registered successfully', { userId: this.lastID, email: sanitizedData.email });
            res.json({ success: true, message: "User registered successfully", userId: this.lastID });
          }
        );
      } catch (error) {
        logger.error('Password hashing failed', { error: error.message });
        res.status(500).json({ success: false, message: "Registration failed" });
      }
    });
  } catch (error) {
    logger.error('Registration error', { error: error.message });
    res.status(500).json({ success: false, message: "Registration failed" });
  }
});

// User login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "Email and password required" });
    }

    const sanitizedEmail = authService.sanitizeInput(email).toLowerCase();

    db.get("SELECT * FROM users WHERE email = ?", [sanitizedEmail], async (err, user) => {
      if (err) {
        logger.error('Database error during login', { error: err.message });
        logLoginAttempt(sanitizedEmail, clientIP, false);
        return res.status(500).json({ success: false, message: "Login failed" });
      }
      
      if (!user) {
        logLoginAttempt(sanitizedEmail, clientIP, false);
        return res.status(401).json({ success: false, message: "Invalid credentials" });
      }

      try {
        const isValidPassword = await authService.verifyPassword(password, user.password);
        
        if (!isValidPassword) {
          logLoginAttempt(sanitizedEmail, clientIP, false);
          return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const token = authService.generateToken({ 
          userId: user.id, 
          email: user.email, 
          username: user.username 
        });
        
        logLoginAttempt(sanitizedEmail, clientIP, true);
        logger.info('User logged in successfully', { userId: user.id, email: user.email });
        
        res.json({ 
          success: true, 
          message: "Login successful", 
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            isVerified: user.is_verified
          }
        });
      } catch (error) {
        logger.error('Password verification failed', { error: error.message });
        logLoginAttempt(sanitizedEmail, clientIP, false);
        res.status(500).json({ success: false, message: "Login failed" });
      }
    });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// Request OTP
app.post("/api/request-otp", otpLimiter, validateInput, async (req, res) => {
  try {
    const { email, username, type = 'password_reset' } = req.body;
    
    if (!email && !username) {
      return res.status(400).json({ success: false, message: "Provide email or username" });
    }

    const validTypes = ['password_reset', 'username_reset', 'account_verification', 'login_verification'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ success: false, message: "Invalid OTP type" });
    }

    const findEmail = new Promise((resolve, reject) => {
      if (email) {
        const sanitizedEmail = authService.sanitizeInput(email).toLowerCase();
        return resolve(sanitizedEmail);
      }
      
      const sanitizedUsername = authService.sanitizeInput(username);
      db.get("SELECT email FROM users WHERE username = ?", [sanitizedUsername], (err, row) => {
        if (err) return reject(err);
        if (!row) return reject(new Error("User not found"));
        resolve(row.email);
      });
    });

    const finalEmail = await findEmail;
    
    // Check for recent OTP requests
    db.get(
      "SELECT COUNT(*) as count FROM otps WHERE email = ? AND created_at > datetime('now', '-2 minutes')",
      [finalEmail],
      async (err, row) => {
        if (err) {
          logger.error('Database error checking recent OTPs', { error: err.message });
          return res.status(500).json({ success: false, message: "OTP request failed" });
        }
        
        if (row.count > 0) {
          return res.status(429).json({ 
            success: false, 
            message: "Please wait 2 minutes before requesting another OTP" 
          });
        }

        try {
          const otp = authService.generateSecureOTP();
          const expiry = Date.now() + 5 * 60 * 1000; // 5 minutes
          
          db.run(
            "INSERT INTO otps (email, otp, type, expiry) VALUES (?, ?, ?, ?)",
            [finalEmail, otp, type, expiry],
            async (err) => {
              if (err) {
                logger.error('Failed to save OTP', { error: err.message, email: finalEmail });
                return res.status(500).json({ success: false, message: "OTP generation failed" });
              }
              
              try {
                const emailResult = await emailService.sendOTP(finalEmail, otp, type);
                cleanupOtps();
                
                logger.info('OTP generated and sent', { 
                  email: finalEmail, 
                  type, 
                  demo: emailResult.demo || false 
                });
                
                res.json({ 
                  success: true, 
                  message: emailResult.demo 
                    ? "OTP generated and logged on server console (demo mode)" 
                    : "OTP sent to your email address",
                  demo: emailResult.demo || false
                });
              } catch (emailError) {
                logger.error('Failed to send OTP email', { error: emailError.message, email: finalEmail });
                res.status(500).json({ success: false, message: "Failed to send OTP email" });
              }
            }
          );
        } catch (error) {
          logger.error('OTP generation error', { error: error.message });
          res.status(500).json({ success: false, message: "OTP generation failed" });
        }
      }
    );
  } catch (error) {
    logger.error('Request OTP error', { error: error.message });
    res.status(500).json({ success: false, message: "OTP request failed" });
  }
});

// Verify OTP
app.post("/api/verify-otp", (req, res) => {
  const { email, otp, type = 'password_reset' } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ success: false, message: "Provide email and OTP" });
  }

  const sanitizedEmail = authService.sanitizeInput(email).toLowerCase();
  const sanitizedOTP = authService.sanitizeInput(otp);

  db.get(
    "SELECT * FROM otps WHERE email = ? AND otp = ? AND type = ? AND used = 0",
    [sanitizedEmail, sanitizedOTP, type],
    (err, row) => {
      if (err) {
        logger.error('Database error during OTP verification', { error: err.message });
        return res.status(500).json({ success: false, message: "OTP verification failed" });
      }
      
      if (!row) {
        logger.warn('Invalid OTP attempt', { email: sanitizedEmail, otp: sanitizedOTP });
        return res.status(400).json({ success: false, message: "Invalid OTP" });
      }
      
      if (row.expiry < Date.now()) {
        return res.status(400).json({ success: false, message: "OTP expired" });
      }
      
      // Mark OTP as used
      db.run("UPDATE otps SET used = 1 WHERE id = ?", [row.id], (err) => {
        if (err) {
          logger.error('Failed to mark OTP as used', { error: err.message });
        }
      });
      
      logger.info('OTP verified successfully', { email: sanitizedEmail, type });
      res.json({ success: true, message: "OTP verified successfully" });
    }
  );
});

// Reset password
app.post("/api/reset-password", validateInput, async (req, res) => {
  try {
    const { email, newPassword, otp } = req.body;
    
    if (!email || !newPassword) {
      return res.status(400).json({ success: false, message: "Provide email and new password" });
    }

    const sanitizedEmail = authService.sanitizeInput(email).toLowerCase();

    // Verify OTP if provided
    if (otp) {
      const sanitizedOTP = authService.sanitizeInput(otp);
      const otpRow = await new Promise((resolve, reject) => {
        db.get(
          "SELECT * FROM otps WHERE email = ? AND otp = ? AND type = 'password_reset' AND used = 0 AND expiry > ?",
          [sanitizedEmail, sanitizedOTP, Date.now()],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          }
        );
      });

      if (!otpRow) {
        return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
      }

      // Mark OTP as used
      db.run("UPDATE otps SET used = 1 WHERE id = ?", [otpRow.id]);
    }

    const hashedPassword = await authService.hashPassword(newPassword);
    
    db.run(
      "UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?",
      [hashedPassword, sanitizedEmail],
      function(err) {
        if (err) {
          logger.error('Failed to update password', { error: err.message, email: sanitizedEmail });
          return res.status(500).json({ success: false, message: "Password update failed" });
        }
        
        if (this.changes === 0) {
          return res.status(404).json({ success: false, message: "User not found" });
        }
        
        logger.info('Password updated successfully', { email: sanitizedEmail });
        res.json({ success: true, message: "Password updated successfully" });
      }
    );
  } catch (error) {
    logger.error('Reset password error', { error: error.message });
    res.status(500).json({ success: false, message: "Password reset failed" });
  }
});

// Reset username
app.post("/api/reset-username", validateInput, async (req, res) => {
  try {
    const { email, newUsername, otp } = req.body;
    
    if (!email || !newUsername) {
      return res.status(400).json({ success: false, message: "Provide email and new username" });
    }

    const sanitizedEmail = authService.sanitizeInput(email).toLowerCase();
    const sanitizedUsername = authService.sanitizeInput(newUsername);

    // Verify OTP if provided
    if (otp) {
      const sanitizedOTP = authService.sanitizeInput(otp);
      const otpRow = await new Promise((resolve, reject) => {
        db.get(
          "SELECT * FROM otps WHERE email = ? AND otp = ? AND type = 'username_reset' AND used = 0 AND expiry > ?",
          [sanitizedEmail, sanitizedOTP, Date.now()],
          (err, row) => {
            if (err) reject(err);
            else resolve(row);
          }
        );
      });

      if (!otpRow) {
        return res.status(400).json({ success: false, message: "Invalid or expired OTP" });
      }

      // Mark OTP as used
      db.run("UPDATE otps SET used = 1 WHERE id = ?", [otpRow.id]);
    }

    // Check if username is already taken
    db.get("SELECT id FROM users WHERE username = ? AND email != ?", [sanitizedUsername, sanitizedEmail], (err, row) => {
      if (err) {
        logger.error('Database error checking username availability', { error: err.message });
        return res.status(500).json({ success: false, message: "Username update failed" });
      }
      
      if (row) {
        return res.status(400).json({ success: false, message: "Username already taken" });
      }

      db.run(
        "UPDATE users SET username = ?, updated_at = CURRENT_TIMESTAMP WHERE email = ?",
        [sanitizedUsername, sanitizedEmail],
        function(err) {
          if (err) {
            logger.error('Failed to update username', { error: err.message, email: sanitizedEmail });
            return res.status(500).json({ success: false, message: "Username update failed" });
          }
          
          if (this.changes === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
          }
          
          logger.info('Username updated successfully', { email: sanitizedEmail, newUsername: sanitizedUsername });
          res.json({ success: true, message: "Username updated successfully" });
        }
      );
    });
  } catch (error) {
    logger.error('Reset username error', { error: error.message });
    res.status(500).json({ success: false, message: "Username reset failed" });
  }
});

// Get user profile
app.get("/api/profile", (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" });
  }

  try {
    const decoded = authService.verifyToken(token);
    
    db.get("SELECT id, username, email, is_verified, created_at FROM users WHERE id = ?", [decoded.userId], (err, user) => {
      if (err) {
        logger.error('Database error fetching user profile', { error: err.message });
        return res.status(500).json({ success: false, message: "Failed to fetch profile" });
      }
      
      if (!user) {
        return res.status(404).json({ success: false, message: "User not found" });
      }
      
      res.json({ success: true, user });
    });
  } catch (error) {
    logger.error('Token verification failed', { error: error.message });
    res.status(401).json({ success: false, message: "Invalid token" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`Server running on http://localhost:${PORT}`));
