const request = require('supertest');
const path = require('path');

// Mock the database and services before requiring the server
jest.mock('../services/emailService', () => ({
  sendOTP: jest.fn().mockResolvedValue({ success: true, demo: true, otp: '123456' }),
  verifyConnection: jest.fn().mockResolvedValue(true)
}));

jest.mock('../services/logger', () => ({
  info: jest.fn(),
  error: jest.fn(),
  warn: jest.fn(),
  debug: jest.fn()
}));

// Set test environment
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-secret';

const app = require('../server');

describe('Teacher World API', () => {
  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Teacher World API is running');
    });
  });

  describe('POST /api/contact', () => {
    it('should save contact message with valid data', async () => {
      const contactData = {
        name: 'John Doe',
        email: 'john@example.com',
        subject: 'Test Subject',
        message: 'Test message content'
      };

      const response = await request(app)
        .post('/api/contact')
        .send(contactData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('Message saved successfully!');
    });

    it('should reject contact message with missing fields', async () => {
      const contactData = {
        name: 'John Doe',
        email: 'john@example.com'
        // missing subject and message
      };

      const response = await request(app)
        .post('/api/contact')
        .send(contactData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Missing required fields');
    });

    it('should reject contact message with invalid email', async () => {
      const contactData = {
        name: 'John Doe',
        email: 'invalid-email',
        subject: 'Test Subject',
        message: 'Test message content'
      };

      const response = await request(app)
        .post('/api/contact')
        .send(contactData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Invalid email format');
    });
  });

  describe('POST /api/register', () => {
    it('should register user with valid data', async () => {
      const userData = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPass123'
      };

      const response = await request(app)
        .post('/api/register')
        .send(userData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('User registered successfully');
    });

    it('should reject registration with weak password', async () => {
      const userData = {
        username: 'testuser2',
        email: 'test2@example.com',
        password: 'weak'
      };

      const response = await request(app)
        .post('/api/register')
        .send(userData)
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toContain('Password must be at least 8 characters');
    });
  });

  describe('POST /api/request-otp', () => {
    it('should generate OTP for valid email', async () => {
      const otpData = {
        email: 'test@example.com',
        type: 'password_reset'
      };

      const response = await request(app)
        .post('/api/request-otp')
        .send(otpData)
        .expect(200);

      expect(response.body.success).toBe(true);
      expect(response.body.message).toContain('OTP');
    });

    it('should reject OTP request without email or username', async () => {
      const response = await request(app)
        .post('/api/request-otp')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Provide email or username');
    });
  });

  describe('POST /api/verify-otp', () => {
    it('should reject verification without email and OTP', async () => {
      const response = await request(app)
        .post('/api/verify-otp')
        .send({})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('Provide email and OTP');
    });
  });
});

// Clean up after tests
afterAll((done) => {
  // Close any open database connections or servers
  done();
});