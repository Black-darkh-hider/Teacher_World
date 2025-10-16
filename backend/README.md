# Teacher World Backend API

A robust Node.js/Express backend for the Teacher World application with comprehensive OTP functionality, user authentication, and security features.

## 🚀 Features

### Core Functionality
- **User Registration & Authentication** - Secure user registration and login with JWT tokens
- **OTP System** - Email-based OTP for password reset, username reset, and account verification
- **Contact Management** - Save and manage contact form submissions
- **Profile Management** - User profile retrieval and updates

### Security Features
- **Password Hashing** - bcrypt with configurable salt rounds
- **JWT Authentication** - Secure token-based authentication
- **Rate Limiting** - Prevent abuse with configurable rate limits
- **Input Validation** - Comprehensive input sanitization and validation
- **Security Headers** - Helmet.js for security headers
- **Login Attempt Logging** - Track and log login attempts

### Email System
- **Professional Email Templates** - HTML and text email templates
- **Multiple Email Providers** - Support for Gmail, SendGrid, AWS SES
- **Development Mode** - Console logging for development/testing
- **OTP Types** - Support for different OTP purposes

### Monitoring & Logging
- **Winston Logging** - Comprehensive logging with file and console outputs
- **Health Check Endpoint** - Monitor API status
- **Error Tracking** - Detailed error logging and tracking

## 📋 Prerequisites

- Node.js 16.0.0 or higher
- npm or yarn package manager

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the server**
   ```bash
   # Development mode
   npm run dev

   # Production mode
   npm start
   ```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NODE_ENV` | Environment (development/production) | development |
| `PORT` | Server port | 5000 |
| `JWT_SECRET` | JWT signing secret | (required) |
| `EMAIL_SERVICE` | Email service provider | gmail |
| `EMAIL_USER` | Email username | (required for production) |
| `EMAIL_PASS` | Email password/API key | (required for production) |
| `LOG_LEVEL` | Logging level | info |

### Email Providers

#### Gmail
```env
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
```

#### SendGrid
```env
EMAIL_SERVICE=sendgrid
SENDGRID_API_KEY=your-sendgrid-api-key
```

#### AWS SES
```env
EMAIL_SERVICE=ses
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
```

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /api/register
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

#### Login User
```http
POST /api/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "SecurePass123"
}
```

#### Get User Profile
```http
GET /api/profile
Authorization: Bearer <jwt-token>
```

### OTP Endpoints

#### Request OTP
```http
POST /api/request-otp
Content-Type: application/json

{
  "email": "john@example.com",
  "type": "password_reset"
}
```

**OTP Types:**
- `password_reset` - For password reset
- `username_reset` - For username reset
- `account_verification` - For account verification
- `login_verification` - For login verification

#### Verify OTP
```http
POST /api/verify-otp
Content-Type: application/json

{
  "email": "john@example.com",
  "otp": "123456",
  "type": "password_reset"
}
```

### Password & Username Management

#### Reset Password
```http
POST /api/reset-password
Content-Type: application/json

{
  "email": "john@example.com",
  "newPassword": "NewSecurePass123",
  "otp": "123456"
}
```

#### Reset Username
```http
POST /api/reset-username
Content-Type: application/json

{
  "email": "john@example.com",
  "newUsername": "newusername",
  "otp": "123456"
}
```

### Contact Management

#### Submit Contact Form
```http
POST /api/contact
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "phone": "+1234567890",
  "subject": "Inquiry",
  "message": "Hello, I have a question..."
}
```

### Utility Endpoints

#### Health Check
```http
GET /api/health
```

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    is_verified BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### OTPs Table
```sql
CREATE TABLE otps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    otp TEXT,
    type TEXT DEFAULT 'password_reset',
    expiry INTEGER,
    used BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Messages Table
```sql
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    phone TEXT,
    subject TEXT,
    message TEXT,
    status TEXT DEFAULT 'unread',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Login Attempts Table
```sql
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    ip_address TEXT,
    success BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🧪 Testing

Run the test suite:
```bash
npm test
```

Run tests with coverage:
```bash
npm run test:coverage
```

## 📝 Logging

Logs are stored in the `logs/` directory:
- `combined.log` - All logs
- `error.log` - Error logs only

Log levels: `error`, `warn`, `info`, `debug`

## 🔒 Security Features

### Password Requirements
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number

### Rate Limiting
- General API: 100 requests per 15 minutes
- OTP requests: 3 requests per 5 minutes
- Configurable per environment

### Input Validation
- Email format validation
- Password strength validation
- Username length validation (3-20 characters)
- Input sanitization to prevent XSS

### Security Headers
- Helmet.js for security headers
- CORS configuration
- Content Security Policy

## 🚀 Deployment

### Production Checklist
1. Set `NODE_ENV=production`
2. Use strong `JWT_SECRET`
3. Configure production email service
4. Set up proper logging
5. Configure rate limits
6. Set up HTTPS
7. Configure database backups

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 5000
CMD ["npm", "start"]
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support and questions:
- Check the logs in `logs/` directory
- Review the API documentation above
- Check environment configuration
- Verify email service setup

## 🔄 Changelog

### Version 1.0.0
- Initial release with full OTP functionality
- User authentication and registration
- Contact form management
- Comprehensive security features
- Email service integration
- Logging and monitoring