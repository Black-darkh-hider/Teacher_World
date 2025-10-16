
# Teacher World - Full Stack Application

A comprehensive web application for teachers with user authentication, OTP-based security, and contact management.

## 🚀 Quick Start

### Backend Setup
1. Open a terminal and navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   npm start
   # or for development with auto-reload:
   npm run dev
   ```

4. The API will be available at: http://localhost:5000

### Frontend Access
- Open your browser to: http://localhost:5000/contact.html
- Or open any HTML file from the frontend folder directly

## 📋 Features

### Backend Features
- **User Authentication** - Registration, login with JWT tokens
- **OTP System** - Email-based OTP for password/username reset
- **Contact Management** - Save and manage contact form submissions
- **Security** - Rate limiting, input validation, password hashing
- **Email Service** - Professional email templates for OTP delivery
- **Logging** - Comprehensive logging with Winston
- **Testing** - Jest test suite with coverage reports

### Frontend Features
- User registration and login forms
- Password and username reset with OTP verification
- Contact form with validation
- Responsive design
- Modern UI components

## 🗄️ Database

The application uses SQLite database (backend/database.db - auto-created) with tables for:
- Users (with authentication)
- OTPs (with expiry and type tracking)
- Contact messages
- Login attempts (for security monitoring)

## 🔧 Development

### Backend Development
```bash
cd backend
npm run dev      # Start with nodemon for auto-reload
npm test         # Run test suite
npm run lint     # Run ESLint
```

### Environment Configuration
Copy `.env.example` to `.env` and configure:
- JWT secret key
- Email service credentials (for production)
- Logging levels
- Rate limiting settings

## 📧 Email Configuration

### Development Mode
- OTPs are logged to console for testing
- No actual emails are sent

### Production Mode
Configure one of these email services in `.env`:
- **Gmail** - Use app-specific passwords
- **SendGrid** - Use API key
- **AWS SES** - Use AWS credentials

## 🔒 Security Features

- Password hashing with bcrypt
- JWT token authentication
- Rate limiting (API and OTP requests)
- Input validation and sanitization
- Security headers with Helmet.js
- Login attempt tracking

## 📊 Monitoring

- Health check endpoint: `/api/health`
- Logs stored in `backend/logs/`
- Error tracking and monitoring
- Performance metrics

## 🧪 Testing

Run the complete test suite:
```bash
cd backend
npm test
```

## 🚀 GitHub Automation

This repository includes comprehensive GitHub automation:
- **CI/CD Pipeline** - Automated testing and building
- **Dependabot** - Automatic dependency updates
- **Security Scanning** - CodeQL and vulnerability checks
- **Auto-merge** - Safe auto-merge for dependency updates
- **Issue Management** - Automated labeling and stale issue management

## 📝 API Documentation

See `backend/README.md` for complete API documentation including:
- Authentication endpoints
- OTP management
- Contact form handling
- User profile management

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `npm test`
5. Submit a pull request

The GitHub automation will automatically:
- Run CI/CD tests
- Check for security issues
- Label your PR appropriately
- Provide feedback on the changes

## 📄 Notes

- **Development**: OTPs are logged to server console for easy testing
- **Production**: Configure email service for actual OTP delivery
- **Database**: SQLite file is created automatically on first run
- **Security**: Change JWT_SECRET in production environment
