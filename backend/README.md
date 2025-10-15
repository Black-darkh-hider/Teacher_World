TeacherWorld Backend

Quick start

- Copy `.env.example` to `.env` and set SMTP creds for real emails.
- Dev without SMTP: OTPs are logged to console.
- Run:

```bash
cd backend
npm install
npm start
```

API overview

- POST /api/auth/register {email,password,role}
- POST /api/auth/resend-otp {email, purpose}
- POST /api/auth/verify-otp {email, otp, purpose}
- POST /api/auth/login {email,password}  # direct login after verified
- POST /api/auth/login/init {email,password}  # optional OTP login step 1
- POST /api/auth/login/verify {email, otp}    # optional OTP login step 2
- POST /api/auth/refresh {refreshToken}
- POST /api/auth/logout {refreshToken}

- GET /api/users/me (Bearer)
- PUT /api/users/me (Bearer)
- POST /api/users/me/resume (Bearer, multipart form field `resume`)
- POST /api/users/me/certificates (Bearer, multipart `certificate`, body: title)
- GET /api/users/me/certificates (Bearer)
- DELETE /api/users/me/certificates/:id (Bearer)

- POST /api/jobs (Bearer employer)
- GET /api/jobs/search?q=&city=&tags=&lat=&lng=&radiusKm=
- POST /api/jobs/apply {jobId, coverLetter} (Bearer)

- POST /api/materials (Bearer, multipart `file` if type=file)
- GET /api/materials?subject=&grade=&q=

- POST /api/sessions {title, startsAt} (Bearer)
- GET /api/sessions (Bearer)

Notes

- Dev DB: SQLite file `backend/database.db`.
- Uploads served under `/uploads`.
- Replace storage with S3 in production.
