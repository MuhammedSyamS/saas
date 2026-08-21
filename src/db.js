const mongoose = require('mongoose');
const crypto = require('crypto');

// Password Hashing & Verification Utilities
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `pbkdf2:sha512:100000:${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!password || !storedHash) return false;
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 5 || parts[0] !== 'pbkdf2' || parts[1] !== 'sha512') return false;
    const iterations = parseInt(parts[2], 10);
    const salt = parts[3];
    const originalHash = parts[4];
    const verifyHash = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(originalHash, 'hex'), Buffer.from(verifyHash, 'hex'));
  } catch (e) {
    return false;
  }
}

// Mongoose Schemas & Models
const EmployeeSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  role: { type: String, default: 'employee' },
  status: { type: String, default: 'active' },
  needs_review: { type: Number, default: 0 }
}, { timestamps: true });

const SessionSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  expires_at: { type: String, required: true },
  created_at: { type: String, required: true }
});

const WebAuthnCredentialSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  credential_id: { type: String, required: true, unique: true },
  public_key: { type: String, required: true },
  counter: { type: Number, default: 0 },
  transports: String,
  created_at: { type: String, required: true },
  last_used_at: String,
  status: { type: String, default: 'active' }
});

const ShiftSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  shift_name: { type: String, required: true },
  start_time: { type: String, required: true },
  end_time: { type: String, required: true },
  is_night_shift: { type: Number, default: 0 },
  allowed_early_in_mins: { type: Number, default: 60 },
  allowed_late_in_mins: { type: Number, default: 720 },
  allowed_early_out_mins: { type: Number, default: 60 },
  allowed_late_out_mins: { type: Number, default: 720 },
  active_days: { type: String, default: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' }
});

const ShiftInstanceSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  shift_id: { type: String, required: true },
  scheduled_date: { type: String, required: true },
  scheduled_start: { type: String, required: true },
  scheduled_end: { type: String, required: true },
  attendance_state: { type: String, default: 'NOT_STARTED' },
  created_at: { type: String, required: true }
});

const ChallengeSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  action: { type: String, required: true },
  challenge: { type: String, required: true },
  created_at: { type: String, required: true },
  expires_at: { type: Number, required: true },
  used: { type: Number, default: 0 }
});

const SystemSettingsSchema = new mongoose.Schema({
  id: { type: Number, default: 1 },
  hospital_name: { type: String, default: 'VAIDHYAR MANDHIRAM, Kallara' },
  geofence_lat: { type: Number, default: 8.752625 },
  geofence_lng: { type: Number, default: 76.938625 },
  geofence_radius_meters: { type: Number, default: 500 },
  max_allowed_accuracy_meters: { type: Number, default: 300 },
  hospital_wifi_ips: { type: String, default: '["103.170.54.239", "103.170.54.0/24", "103.15.22.4", "103.15.22.5", "127.0.0.1", "::1"]' },
  network_enforcement_mode: { type: String, default: 'enforce' },
  enforcement_strict_geofence: { type: Number, default: 1 },
  enforcement_strict_accuracy: { type: Number, default: 1 },
  enforcement_strict_shift: { type: Number, default: 1 }
});

const AttendanceRecordSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  shift_instance_id: { type: String, required: true },
  punch_type: { type: String, required: true },
  server_timestamp: { type: String, required: true },
  credential_id: String,
  webauthn_verified: { type: Number, default: 1 },
  source_ip: String,
  network_verified: { type: Number, default: 1 },
  latitude: Number,
  longitude: Number,
  accuracy_meters: Number,
  calculated_distance_meters: Number,
  geofence_verified: { type: Number, default: 1 },
  challenge_id: String,
  status: { type: String, default: 'SUCCESS' },
  notes: String
});

const AttendanceAttemptSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: String,
  shift_instance_id: String,
  action: { type: String, required: true },
  server_timestamp: { type: String, required: true },
  source_ip: String,
  network_verified: { type: Number, default: 0 },
  lat: Number,
  lng: Number,
  accuracy: Number,
  distance: Number,
  authentication_verified: { type: Number, default: 0 },
  reason_code: { type: String, required: true },
  result: { type: String, required: true }
});

const AuditLogSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, default: 'UNKNOWN' },
  employee_name: { type: String, default: 'Anonymous' },
  event_type: { type: String, required: true },
  severity: { type: String, default: 'INFO' },
  reason_code: String,
  reason: String,
  metadata: String,
  timestamp: { type: String, required: true }
});

const CorrectionRequestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  requested_date: { type: String, required: true },
  requested_punch_type: { type: String, required: true },
  requested_time: { type: String, required: true },
  reason: { type: String, required: true },
  status: { type: String, default: 'PENDING' },
  admin_notes: String,
  reviewed_at: String,
  reviewed_by: String,
  created_at: { type: String, required: true }
});

const models = {
  Employee: mongoose.models.Employee || mongoose.model('Employee', EmployeeSchema),
  Session: mongoose.models.Session || mongoose.model('Session', SessionSchema),
  WebAuthnCredential: mongoose.models.WebAuthnCredential || mongoose.model('WebAuthnCredential', WebAuthnCredentialSchema),
  Shift: mongoose.models.Shift || mongoose.model('Shift', ShiftSchema),
  ShiftInstance: mongoose.models.ShiftInstance || mongoose.model('ShiftInstance', ShiftInstanceSchema),
  Challenge: mongoose.models.Challenge || mongoose.model('Challenge', ChallengeSchema),
  SystemSettings: mongoose.models.SystemSettings || mongoose.model('SystemSettings', SystemSettingsSchema),
  AttendanceRecord: mongoose.models.AttendanceRecord || mongoose.model('AttendanceRecord', AttendanceRecordSchema),
  AttendanceAttempt: mongoose.models.AttendanceAttempt || mongoose.model('AttendanceAttempt', AttendanceAttemptSchema),
  AuditLog: mongoose.models.AuditLog || mongoose.model('AuditLog', AuditLogSchema),
  CorrectionRequest: mongoose.models.CorrectionRequest || mongoose.model('CorrectionRequest', CorrectionRequestSchema)
};

const memoryDb = {
  employees: [],
  sessions: [],
  webauthn_credentials: [],
  shifts: [],
  shift_instances: [],
  challenges: [],
  system_settings: [],
  attendance_records: [],
  attendance_attempts: [],
  audit_logs: [],
  correction_requests: []
};

let useRealMongo = false;
let dbInitializationError = null;

async function initDb() {
  dbInitializationError = null;

  if (process.env.MONGODB_URI && process.env.MONGODB_URI.trim() !== '') {
    try {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI.trim());
        useRealMongo = true;
        console.log('Successfully connected to MongoDB.');
      } else {
        useRealMongo = true;
      }
    } catch (err) {
      dbInitializationError = err;
      console.warn('MongoDB connection failed:', err.message);
      useRealMongo = false;

      // In production mode, MongoDB is mandatory. Fail fast!
      if (process.env.NODE_ENV === 'production') {
        throw new Error(`DATABASE_UNAVAILABLE: MongoDB connection required in production mode (${err.message})`);
      }
    }
  } else {
    useRealMongo = false;
    if (process.env.NODE_ENV === 'production') {
      dbInitializationError = new Error('DATABASE_UNAVAILABLE: MONGODB_URI is required in production.');
      throw dbInitializationError;
    }
    console.log('Using memory database fallback for local dev/testing.');
  }

  if (useRealMongo) {
    const existingSettings = await models.SystemSettings.findOne({ id: 1 });
    if (!existingSettings) {
      await models.SystemSettings.create({
        id: 1,
        hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
        geofence_lat: parseFloat(process.env.HOSPITAL_LAT) || 8.752625,
        geofence_lng: parseFloat(process.env.HOSPITAL_LNG) || 76.938625,
        geofence_radius_meters: parseFloat(process.env.GEOFENCE_RADIUS_METERS) || 500,
        max_allowed_accuracy_meters: parseFloat(process.env.MAX_LOCATION_ACCURACY_METERS) || 300,
        hospital_wifi_ips: '["103.170.54.239", "103.170.54.0/24", "103.15.22.4", "103.15.22.5", "127.0.0.1", "::1"]',
        network_enforcement_mode: 'enforce'
      });
    }

    const empCount = await models.Employee.countDocuments({});
    if (empCount === 0) {
      await models.Employee.create([
        { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active' },
        { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active' },
        { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', password_hash: hashPassword('AdminPassword123!'), role: 'admin', status: 'active' }
      ]);

      await models.Shift.create([
        { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 },
        { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 }
      ]);
    }
  }

  // Always seed memory DB if empty to guarantee instant fallback operation in dev/test
  if (memoryDb.system_settings.length === 0) {
    memoryDb.system_settings.push({
      id: 1,
      hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
      geofence_lat: parseFloat(process.env.HOSPITAL_LAT) || 8.752625,
      geofence_lng: parseFloat(process.env.HOSPITAL_LNG) || 76.938625,
      geofence_radius_meters: parseFloat(process.env.GEOFENCE_RADIUS_METERS) || 500,
      max_allowed_accuracy_meters: parseFloat(process.env.MAX_LOCATION_ACCURACY_METERS) || 300,
      hospital_wifi_ips: '["103.170.54.239", "103.170.54.0/24", "103.15.22.4", "103.15.22.5", "127.0.0.1", "::1"]',
      network_enforcement_mode: 'enforce',
      enforcement_strict_geofence: 1,
      enforcement_strict_accuracy: 1,
      enforcement_strict_shift: 1
    });

    memoryDb.employees.push(
      { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
      { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
      { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', password_hash: hashPassword('AdminPassword123!'), role: 'admin', status: 'active', needs_review: 0 }
    );

    memoryDb.shifts.push(
      { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' },
      { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' }
    );
  }
}

function checkDatabaseAvailability() {
  if (process.env.NODE_ENV === 'production' && !useRealMongo) {
    throw new Error('DATABASE_UNAVAILABLE: MongoDB connection required in production mode.');
  }
}

function getCollectionName(sqlQuery) {
  const q = sqlQuery.trim().toUpperCase();
  if (q.includes('FROM EMPLOYEES') || q.includes('INTO EMPLOYEES') || q.includes('UPDATE EMPLOYEES')) return 'employees';
  if (q.includes('FROM SESSIONS') || q.includes('INTO SESSIONS') || q.includes('DELETE FROM SESSIONS')) return 'sessions';
  if (q.includes('FROM WEBAUTHN_CREDENTIALS') || q.includes('INTO WEBAUTHN_CREDENTIALS') || q.includes('UPDATE WEBAUTHN_CREDENTIALS') || q.includes('DELETE FROM WEBAUTHN_CREDENTIALS')) return 'webauthn_credentials';
  if (q.includes('FROM SHIFTS') || q.includes('INTO SHIFTS')) return 'shifts';
  if (q.includes('FROM SHIFT_INSTANCES') || q.includes('INTO SHIFT_INSTANCES') || q.includes('UPDATE SHIFT_INSTANCES')) return 'shift_instances';
  if (q.includes('FROM CHALLENGES') || q.includes('INTO CHALLENGES') || q.includes('UPDATE CHALLENGES')) return 'challenges';
  if (q.includes('FROM SYSTEM_SETTINGS') || q.includes('UPDATE SYSTEM_SETTINGS')) return 'system_settings';
  if (q.includes('FROM ATTENDANCE_RECORDS') || q.includes('INTO ATTENDANCE_RECORDS')) return 'attendance_records';
  if (q.includes('FROM ATTENDANCE_ATTEMPTS') || q.includes('INTO ATTENDANCE_ATTEMPTS')) return 'attendance_attempts';
  if (q.includes('FROM AUDIT_LOGS') || q.includes('INTO AUDIT_LOGS')) return 'audit_logs';
  if (q.includes('FROM CORRECTION_REQUESTS') || q.includes('INTO CORRECTION_REQUESTS') || q.includes('UPDATE CORRECTION_REQUESTS')) return 'correction_requests';
  return null;
}

function modelForCollection(colName) {
  switch (colName) {
    case 'employees': return models.Employee;
    case 'sessions': return models.Session;
    case 'webauthn_credentials': return models.WebAuthnCredential;
    case 'shifts': return models.Shift;
    case 'shift_instances': return models.ShiftInstance;
    case 'challenges': return models.Challenge;
    case 'system_settings': return models.SystemSettings;
    case 'attendance_records': return models.AttendanceRecord;
    case 'attendance_attempts': return models.AttendanceAttempt;
    case 'audit_logs': return models.AuditLog;
    case 'correction_requests': return models.CorrectionRequest;
    default: return null;
  }
}

async function queryAll(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const colName = getCollectionName(sqlQuery);

  if (useRealMongo && colName) {
    const Model = modelForCollection(colName);
    if (Model) {
      const filter = parseWhereFilter(sqlQuery, params);
      const docs = await Model.find(filter).lean();
      return docs;
    }
  }

  if (colName && memoryDb[colName]) {
    const filter = parseWhereFilter(sqlQuery, params);
    return memoryDb[colName].filter(item => matchFilter(item, filter));
  }
  return [];
}

async function queryGet(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const colName = getCollectionName(sqlQuery);

  if (useRealMongo && colName) {
    const Model = modelForCollection(colName);
    if (Model) {
      const filter = parseWhereFilter(sqlQuery, params);
      const doc = await Model.findOne(filter).lean();
      return doc || null;
    }
  }

  if (colName && memoryDb[colName]) {
    const filter = parseWhereFilter(sqlQuery, params);
    const item = memoryDb[colName].find(i => matchFilter(i, filter));
    return item || null;
  }
  return null;
}

async function queryRun(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const colName = getCollectionName(sqlQuery);
  const upper = sqlQuery.trim().toUpperCase();

  if (useRealMongo && colName) {
    const Model = modelForCollection(colName);
    if (Model) {
      if (upper.startsWith('INSERT INTO')) {
        const doc = parseInsertDoc(sqlQuery, params);
        if (doc) await Model.create(doc);
      } else if (upper.startsWith('UPDATE')) {
        const { filter, update } = parseUpdateDoc(sqlQuery, params);
        if (filter) await Model.updateMany(filter, { $set: update });
      } else if (upper.startsWith('DELETE FROM')) {
        const filter = parseWhereFilter(sqlQuery, params);
        await Model.deleteMany(filter);
      }
      return { success: true };
    }
  }

  if (colName && memoryDb[colName]) {
    if (upper.startsWith('INSERT INTO')) {
      const doc = parseInsertDoc(sqlQuery, params);
      if (doc) memoryDb[colName].push(doc);
    } else if (upper.startsWith('UPDATE')) {
      const { filter, update } = parseUpdateDoc(sqlQuery, params);
      memoryDb[colName].forEach(item => {
        if (matchFilter(item, filter)) {
          Object.assign(item, update);
        }
      });
    } else if (upper.startsWith('DELETE FROM')) {
      const filter = parseWhereFilter(sqlQuery, params);
      memoryDb[colName] = memoryDb[colName].filter(item => !matchFilter(item, filter));
    }
  }
  return { success: true };
}

function parseWhereFilter(sql, params) {
  const filter = {};
  const whereMatch = sql.match(/WHERE\s+(.+?)(?:ORDER|LIMIT|$)/i);
  if (!whereMatch) return filter;

  const clauses = whereMatch[1].split(/\s+AND\s+/i);
  let paramIdx = 0;

  for (const clause of clauses) {
    const parts = clause.trim().split(/\s*=\s*/);
    if (parts.length === 2) {
      const field = parts[0].trim().toLowerCase();
      let val = parts[1].trim();

      if (val === '?') {
        val = params[paramIdx++];
      } else {
        val = val.replace(/^['"]|['"]$/g, '');
      }
      filter[field] = val;
    }
  }
  return filter;
}

function parseInsertDoc(sql, params) {
  const colsMatch = sql.match(/\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i);
  if (!colsMatch) return null;

  const fields = colsMatch[1].split(',').map(s => s.trim().toLowerCase());
  const rawVals = colsMatch[2].split(',').map(s => s.trim());
  const doc = {};
  let paramIdx = 0;

  for (let i = 0; i < fields.length; i++) {
    const field = fields[i];
    const rawVal = rawVals[i];

    if (rawVal === '?') {
      doc[field] = params[paramIdx++];
    } else if (rawVal.toUpperCase() === 'NULL') {
      doc[field] = null;
    } else if (!isNaN(rawVal)) {
      doc[field] = Number(rawVal);
    } else {
      doc[field] = rawVal.replace(/^['"]|['"]$/g, '');
    }
  }
  return doc;
}

function parseUpdateDoc(sql, params) {
  const setMatch = sql.match(/SET\s+(.+?)\s+WHERE/i);
  const whereMatch = sql.match(/WHERE\s+(.+?)(?:ORDER|LIMIT|$)/i);

  const update = {};
  const filter = {};
  let paramIdx = 0;

  if (setMatch) {
    const assignments = setMatch[1].split(',');
    for (const assign of assignments) {
      const parts = assign.trim().split(/\s*=\s*/);
      if (parts.length === 2) {
        const field = parts[0].trim().toLowerCase();
        let val = parts[1].trim();

        if (val === '?') {
          val = params[paramIdx++];
        } else if (!isNaN(val)) {
          val = Number(val);
        } else {
          val = val.replace(/^['"]|['"]$/g, '');
        }
        update[field] = val;
      }
    }
  }

  if (whereMatch) {
    const clauses = whereMatch[1].split(/\s+AND\s+/i);
    for (const clause of clauses) {
      const parts = clause.trim().split(/\s*=\s*/);
      if (parts.length === 2) {
        const field = parts[0].trim().toLowerCase();
        let val = parts[1].trim();

        if (val === '?') {
          val = params[paramIdx++];
        } else {
          val = val.replace(/^['"]|['"]$/g, '');
        }
        filter[field] = val;
      }
    }
  }

  return { filter, update };
}

function matchFilter(item, filter) {
  for (const key in filter) {
    if (item[key] != filter[key]) return false;
  }
  return true;
}

module.exports = {
  initDb,
  queryAll,
  queryGet,
  queryRun,
  verifyPassword,
  hashPassword,
  checkDatabaseAvailability
};
