const mongoose = require('mongoose');
const crypto = require('crypto');

// Salting & Hashing Helper (PBKDF2)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  try {
    const [salt, originalHash] = storedHash.split(':');
    const verifyHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
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
  allowed_early_in_mins: { type: Number, default: 720 },
  allowed_late_in_mins: { type: Number, default: 1440 },
  allowed_early_out_mins: { type: Number, default: 720 },
  allowed_late_out_mins: { type: Number, default: 1440 },
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
  hospital_wifi_ips: { type: String, default: '["120.61.26.70"]' },
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

async function initDb() {
  if (process.env.MONGODB_URI && process.env.MONGODB_URI.trim() !== '') {
    try {
      if (mongoose.connection.readyState === 0) {
        await mongoose.connect(process.env.MONGODB_URI.trim(), {
          serverSelectionTimeoutMS: 4000,
          connectTimeoutMS: 4000
        });
        useRealMongo = true;
        console.log('Successfully connected to MongoDB.');
      } else {
        useRealMongo = true;
      }
    } catch (err) {
      console.warn('MongoDB connection failed. Falling back to memory database:', err.message);
      useRealMongo = false;
    }
  } else {
    useRealMongo = false;
    console.log('Using memory database fallback.');
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
        hospital_wifi_ips: '["120.61.26.70"]',
        network_enforcement_mode: 'enforce',
        enforcement_strict_geofence: 1,
        enforcement_strict_accuracy: 1,
        enforcement_strict_shift: 1
      });
    }

    const empCount = await models.Employee.countDocuments();
    if (empCount === 0) {
      await models.Employee.create([
        { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', password_hash: hashPassword('AdminPassword123!'), role: 'admin', status: 'active', needs_review: 0 }
      ]);

      await models.Shift.create([
        { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' },
        { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' }
      ]);
    }
  } else {
    if (memoryDb.system_settings.length === 0) {
      memoryDb.system_settings.push({
        id: 1,
        hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
        geofence_lat: parseFloat(process.env.HOSPITAL_LAT) || 8.752625,
        geofence_lng: parseFloat(process.env.HOSPITAL_LNG) || 76.938625,
        geofence_radius_meters: parseFloat(process.env.GEOFENCE_RADIUS_METERS) || 500,
        max_allowed_accuracy_meters: parseFloat(process.env.MAX_LOCATION_ACCURACY_METERS) || 300,
        hospital_wifi_ips: '["120.61.26.70"]',
        network_enforcement_mode: 'enforce',
        enforcement_strict_geofence: 1,
        enforcement_strict_accuracy: 1,
        enforcement_strict_shift: 1
      });
    }

    if (memoryDb.employees.length === 0) {
      memoryDb.employees.push(
        { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', password_hash: hashPassword('Password123!'), role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', password_hash: hashPassword('AdminPassword123!'), role: 'admin', status: 'active', needs_review: 0 }
      );
    }

    if (memoryDb.shifts.length === 0) {
      memoryDb.shifts.push(
        { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' },
        { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440, active_days: 'Mon,Tue,Wed,Thu,Fri,Sat,Sun' }
      );
    }
  }
}

function checkDatabaseAvailability() {
  // Graceful memoryDb fallback
}

function getCollectionName(sqlQuery) {
  const q = sqlQuery.trim().toUpperCase();
  if (q.includes('FROM EMPLOYEES') || q.includes('INTO EMPLOYEES') || q.includes('UPDATE EMPLOYEES')) return 'employees';
  if (q.includes('FROM SESSIONS') || q.includes('INTO SESSIONS') || q.includes('DELETE FROM SESSIONS')) return 'sessions';
  if (q.includes('FROM WEBAUTHN_CREDENTIALS') || q.includes('INTO WEBAUTHN_CREDENTIALS') || q.includes('UPDATE WEBAUTHN_CREDENTIALS') || q.includes('DELETE FROM WEBAUTHN_CREDENTIALS')) return 'webauthn_credentials';
  if (q.includes('FROM SHIFTS') || q.includes('INTO SHIFTS')) return 'shifts';
  if (q.includes('FROM SHIFT_INSTANCES') || q.includes('INTO SHIFT_INSTANCES') || q.includes('UPDATE SHIFT_INSTANCES') || q.includes('DELETE FROM SHIFT_INSTANCES')) return 'shift_instances';
  if (q.includes('FROM CHALLENGES') || q.includes('INTO CHALLENGES') || q.includes('UPDATE CHALLENGES') || q.includes('DELETE FROM CHALLENGES')) return 'challenges';
  if (q.includes('FROM SYSTEM_SETTINGS') || q.includes('UPDATE SYSTEM_SETTINGS')) return 'system_settings';
  if (q.includes('FROM ATTENDANCE_RECORDS') || q.includes('INTO ATTENDANCE_RECORDS')) return 'attendance_records';
  if (q.includes('FROM ATTENDANCE_ATTEMPTS') || q.includes('INTO ATTENDANCE_ATTEMPTS')) return 'attendance_attempts';
  if (q.includes('FROM AUDIT_LOGS') || q.includes('INTO AUDIT_LOGS')) return 'audit_logs';
  if (q.includes('FROM CORRECTION_REQUESTS') || q.includes('INTO CORRECTION_REQUESTS') || q.includes('UPDATE CORRECTION_REQUESTS')) return 'correction_requests';
  return 'employees';
}

function getModelForTable(tableName) {
  switch (tableName) {
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
    default: return models.Employee;
  }
}

async function queryAll(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const table = getCollectionName(sqlQuery);

  if (useRealMongo) {
    const Model = getModelForTable(table);
    const filter = parseWhereParams(sqlQuery, params);
    const docs = await Model.find(filter).lean();
    return docs.map(d => normalizeDoc(d));
  } else {
    let list = memoryDb[table] || [];
    const filter = parseWhereParams(sqlQuery, params);
    if (Object.keys(filter).length > 0) {
      list = list.filter(item => matchFilter(item, filter));
    }
    return list;
  }
}

async function queryGet(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const table = getCollectionName(sqlQuery);

  if (useRealMongo) {
    const Model = getModelForTable(table);
    const filter = parseWhereParams(sqlQuery, params);
    const doc = await Model.findOne(filter).lean();
    return doc ? normalizeDoc(doc) : null;
  } else {
    const list = memoryDb[table] || [];
    const filter = parseWhereParams(sqlQuery, params);
    const item = list.find(it => matchFilter(it, filter));
    return item || null;
  }
}

async function queryRun(sqlQuery, params = []) {
  checkDatabaseAvailability();
  const table = getCollectionName(sqlQuery);
  const q = sqlQuery.trim().toUpperCase();

  if (q.startsWith('INSERT INTO')) {
    const doc = parseInsertDoc(sqlQuery, params);
    if (useRealMongo) {
      const Model = getModelForTable(table);
      await Model.create(doc);
    } else {
      if (!memoryDb[table]) memoryDb[table] = [];
      memoryDb[table].push(doc);
    }
    return { lastID: doc.id, changes: 1 };
  }

  if (q.startsWith('UPDATE')) {
    const { updateDoc, whereFilter } = parseUpdateDoc(sqlQuery, params);
    if (useRealMongo) {
      const Model = getModelForTable(table);
      const res = await Model.updateMany(whereFilter, { $set: updateDoc });
      return { changes: res.modifiedCount };
    } else {
      let count = 0;
      if (memoryDb[table]) {
        memoryDb[table].forEach(item => {
          if (matchFilter(item, whereFilter)) {
            Object.assign(item, updateDoc);
            count++;
          }
        });
      }
      return { changes: count };
    }
  }

  if (q.startsWith('DELETE FROM')) {
    const filter = parseWhereParams(sqlQuery, params);
    if (useRealMongo) {
      const Model = getModelForTable(table);
      const res = await Model.deleteMany(filter);
      return { changes: res.deletedCount };
    } else {
      if (memoryDb[table]) {
        const origLen = memoryDb[table].length;
        memoryDb[table] = memoryDb[table].filter(item => !matchFilter(item, filter));
        return { changes: origLen - memoryDb[table].length };
      }
      return { changes: 0 };
    }
  }

  return { changes: 0 };
}

function normalizeDoc(doc) {
  if (!doc) return null;
  const copy = { ...doc };
  delete copy._id;
  delete copy.__v;
  return copy;
}

function parseWhereParams(sql, params) {
  const filter = {};
  if (!sql.toUpperCase().includes('WHERE')) return filter;

  const whereClause = sql.substring(sql.toUpperCase().indexOf('WHERE') + 5);
  const parts = whereClause.split(/AND/i);

  let paramIndex = 0;
  for (const p of parts) {
    const clean = p.trim().replace(/[()]/g, '').replace(/ORDER BY.*/i, '').replace(/LIMIT.*/i, '').trim();
    if (clean.includes('=')) {
      const [col, valPart] = clean.split('=').map(s => s.trim().toLowerCase());
      if (valPart === '?' && paramIndex < params.length) {
        filter[col] = params[paramIndex++];
      }
    }
  }
  return filter;
}

function matchFilter(item, filter) {
  for (const key of Object.keys(filter)) {
    const filterVal = filter[key];
    const itemVal = item[key];
    if (filterVal !== undefined && filterVal !== null) {
      if (String(itemVal) !== String(filterVal)) return false;
    }
  }
  return true;
}

function parseInsertDoc(sql, params) {
  const colMatch = sql.match(/INSERT\s+INTO\s+\w+\s*\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i);
  if (!colMatch) return {};

  const cols = colMatch[1].split(',').map(s => s.trim().toLowerCase());
  const valTokens = colMatch[2].split(',').map(s => s.trim());

  const doc = {};
  let paramIndex = 0;

  cols.forEach((col, idx) => {
    const valToken = valTokens[idx];
    if (valToken === '?') {
      if (paramIndex < params.length) {
        doc[col] = params[paramIndex++];
      }
    } else if (valToken) {
      doc[col] = valToken.replace(/^['"]|['"]$/g, '');
    }
  });
  return doc;
}

function parseUpdateDoc(sql, params) {
  const setIndex = sql.toUpperCase().indexOf('SET');
  const whereIndex = sql.toUpperCase().indexOf('WHERE');

  const setStr = whereIndex !== -1 ? sql.substring(setIndex + 3, whereIndex) : sql.substring(setIndex + 3);
  const setCols = setStr.split(',').map(s => s.split('=')[0].trim().toLowerCase());
  const setVals = setStr.split(',').map(s => s.split('=')[1].trim());

  const updateDoc = {};
  let paramIdx = 0;

  setCols.forEach((col, idx) => {
    const valToken = setVals[idx];
    if (valToken === '?') {
      if (paramIdx < params.length) {
        updateDoc[col] = params[paramIdx++];
      }
    } else if (valToken !== undefined) {
      const parsedNum = Number(valToken);
      updateDoc[col] = !isNaN(parsedNum) ? parsedNum : valToken.replace(/^['"]|['"]$/g, '');
    }
  });

  const whereParams = params.slice(paramIdx);
  const whereFilter = whereIndex !== -1 ? parseWhereParams(sql.substring(whereIndex), whereParams) : {};

  return { updateDoc, whereFilter };
}

module.exports = {
  initDb,
  queryAll,
  queryGet,
  queryRun,
  hashPassword,
  verifyPassword
};
