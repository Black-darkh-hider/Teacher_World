const authService = require('../services/authService');
const logger = require('../services/logger');

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  try {
    const decoded = authService.verifyToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error('Token verification failed', { error: error.message });
    return res.status(403).json({ success: false, message: 'Invalid or expired token' });
  }
};

// Middleware to check if user is admin (optional for future use)
const requireAdmin = (req, res, next) => {
  if (!req.user || !req.user.isAdmin) {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// Middleware to validate user ownership (user can only access their own data)
const requireOwnership = (req, res, next) => {
  const userId = req.params.userId || req.body.userId;
  
  if (!userId) {
    return res.status(400).json({ success: false, message: 'User ID required' });
  }

  if (req.user.userId !== parseInt(userId) && !req.user.isAdmin) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }

  next();
};

module.exports = {
  authenticateToken,
  requireAdmin,
  requireOwnership
};