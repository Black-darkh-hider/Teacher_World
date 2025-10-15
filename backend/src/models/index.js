import { DataTypes, Model } from 'sequelize';
import { sequelize } from '../config/database.js';

class User extends Model {}
User.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    email: { type: DataTypes.STRING, allowNull: false, unique: true },
    passwordHash: { type: DataTypes.STRING, allowNull: false },
    isVerified: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    name: { type: DataTypes.STRING },
    contact: { type: DataTypes.STRING },
    address: { type: DataTypes.STRING },
    city: { type: DataTypes.STRING },
    qualifications: { type: DataTypes.TEXT },
    role: { type: DataTypes.ENUM('teacher', 'employer', 'admin'), defaultValue: 'teacher' },
    resumeUrl: { type: DataTypes.STRING },
  },
  { sequelize, modelName: 'user' }
);

class OtpToken extends Model {}
OtpToken.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    purpose: { type: DataTypes.ENUM('register', 'login'), allowNull: false },
    otpHash: { type: DataTypes.STRING, allowNull: false },
    expiresAt: { type: DataTypes.DATE, allowNull: false },
    used: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
    attempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
  },
  { sequelize, modelName: 'otp_token', indexes: [{ fields: ['userId', 'purpose'] }] }
);

class Certificate extends Model {}
Certificate.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    title: { type: DataTypes.STRING },
    fileUrl: { type: DataTypes.STRING, allowNull: false },
  },
  { sequelize, modelName: 'certificate' }
);

class Job extends Model {}
Job.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    employerId: { type: DataTypes.UUID, allowNull: false },
    title: { type: DataTypes.STRING, allowNull: false },
    description: { type: DataTypes.TEXT, allowNull: false },
    requiredQualifications: { type: DataTypes.TEXT },
    city: { type: DataTypes.STRING },
    salary: { type: DataTypes.STRING },
    tags: { type: DataTypes.STRING }, // comma-separated
    latitude: { type: DataTypes.FLOAT },
    longitude: { type: DataTypes.FLOAT },
  },
  { sequelize, modelName: 'job', indexes: [{ fields: ['city'] }] }
);

class JobApplication extends Model {}
JobApplication.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    jobId: { type: DataTypes.UUID, allowNull: false },
    teacherId: { type: DataTypes.UUID, allowNull: false },
    coverLetter: { type: DataTypes.TEXT },
    status: { type: DataTypes.ENUM('applied', 'reviewed', 'accepted', 'rejected'), defaultValue: 'applied' },
  },
  { sequelize, modelName: 'job_application' }
);

class Material extends Model {}
Material.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    uploaderId: { type: DataTypes.UUID, allowNull: false },
    subject: { type: DataTypes.STRING, allowNull: false },
    grade: { type: DataTypes.STRING },
    title: { type: DataTypes.STRING, allowNull: false },
    type: { type: DataTypes.ENUM('file', 'link'), allowNull: false },
    fileUrl: { type: DataTypes.STRING },
    linkUrl: { type: DataTypes.STRING },
  },
  { sequelize, modelName: 'material' }
);

class Session extends Model {}
Session.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    hostId: { type: DataTypes.UUID, allowNull: false },
    title: { type: DataTypes.STRING, allowNull: false },
    startsAt: { type: DataTypes.DATE },
    meetingId: { type: DataTypes.STRING, allowNull: false },
    provider: { type: DataTypes.ENUM('jitsi', 'zoom'), defaultValue: 'jitsi' },
  },
  { sequelize, modelName: 'session' }
);

class RefreshSession extends Model {}
RefreshSession.init(
  {
    id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
    userId: { type: DataTypes.UUID, allowNull: false },
    jti: { type: DataTypes.STRING, allowNull: false, unique: true },
    expiresAt: { type: DataTypes.DATE, allowNull: false },
    revoked: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
  },
  { sequelize, modelName: 'refresh_session', indexes: [{ fields: ['userId'] }, { unique: true, fields: ['jti'] }] }
);

// Associations
User.hasMany(Certificate, { foreignKey: 'userId' });
Certificate.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(Job, { foreignKey: 'employerId' });
Job.belongsTo(User, { foreignKey: 'employerId' });

Job.hasMany(JobApplication, { foreignKey: 'jobId' });
JobApplication.belongsTo(Job, { foreignKey: 'jobId' });

User.hasMany(JobApplication, { foreignKey: 'teacherId' });
JobApplication.belongsTo(User, { foreignKey: 'teacherId' });

User.hasMany(Material, { foreignKey: 'uploaderId' });
Material.belongsTo(User, { foreignKey: 'uploaderId' });

User.hasMany(Session, { foreignKey: 'hostId' });
Session.belongsTo(User, { foreignKey: 'hostId' });

User.hasMany(OtpToken, { foreignKey: 'userId' });
OtpToken.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(RefreshSession, { foreignKey: 'userId' });
RefreshSession.belongsTo(User, { foreignKey: 'userId' });

export { sequelize };
export { User, OtpToken, Certificate, Job, JobApplication, Material, Session, RefreshSession };
