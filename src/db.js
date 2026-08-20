const mongoose = require('mongoose');

// Mongoose Schemas & Models
const EmployeeSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password_hash: String,
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
  hospital_wifi_ips: { type: String, default: '["127.0.0.1", "::1", "::ffff:127.0.0.1"]' },
  network_enforcement_mode: { type: String, default: 'enforce' },
  enforcement_strict_geofence: { type: Number, default: 1 },
  enforcement_strict_accuracy: { type: Number, default: 1 },
  enforcement_strict_shift: { type: Number, default: 1 }
});

const AttendanceRecordSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  shift_instance_id: String,
  punch_type: { type: String, required: true },
  server_timestamp: { type: String, required: true },
  credential_id: String,
  webauthn_verified: { type: Number, default: 0 },
  source_ip: { type: String, default: '' },
  network_verified: { type: Number, default: 0 },
  latitude: Number,
  longitude: Number,
  accuracy_meters: Number,
  calculated_distance_meters: Number,
  geofence_verified: { type: Number, default: 0 },
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
  source_ip: { type: String, required: true },
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
  employee_id: String,
  employee_name: String,
  event_type: { type: String, required: true },
  severity: { type: String, required: true },
  reason_code: { type: String, required: true },
  reason: { type: String, required: true },
  metadata: String,
  timestamp: { type: String, required: true }
});

const CorrectionRequestSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  employee_id: { type: String, required: true },
  original_record_id: String,
  requested_date: { type: String, required: true },
  requested_punch_type: { type: String, required: true },
  requested_time: { type: String, required: true },
  reason: { type: String, required: true },
  status: { type: String, default: 'PENDING' },
  admin_notes: String,
  created_at: { type: String, required: true },
  reviewed_at: String,
  reviewed_by: String
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

// In-Memory Collections Store (Fast local fallback when MONGODB_URI is not connected)
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
    if (mongoose.connection.readyState === 0) {
      await mongoose.connect(process.env.MONGODB_URI.trim());
      useRealMongo = true;
    }
  }

  if (useRealMongo) {
    const existingSettings = await models.SystemSettings.findOne({ id: 1 });
    if (!existingSettings) {
      await models.SystemSettings.create({
        id: 1,
        hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
        geofence_lat: 8.752625,
        geofence_lng: 76.938625,
        geofence_radius_meters: 500,
        max_allowed_accuracy_meters: 300,
        hospital_wifi_ips: '["127.0.0.1", "::1", "::ffff:127.0.0.1"]',
        network_enforcement_mode: 'enforce'
      });
    }

    const empCount = await models.Employee.countDocuments({});
    if (empCount === 0) {
      await models.Employee.create([
        { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', role: 'employee', status: 'active' },
        { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', role: 'employee', status: 'active' },
        { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', role: 'admin', status: 'active' }
      ]);

      await models.Shift.create([
        { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 },
        { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 }
      ]);
    }
  } else {
    // Seed Memory DB if empty
    if (memoryDb.system_settings.length === 0) {
      memoryDb.system_settings.push({
        id: 1,
        hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
        geofence_lat: 8.752625,
        geofence_lng: 76.938625,
        geofence_radius_meters: 500,
        max_allowed_accuracy_meters: 300,
        hospital_wifi_ips: '["127.0.0.1", "::1", "::ffff:127.0.0.1"]',
        network_enforcement_mode: 'enforce',
        enforcement_strict_geofence: 1,
        enforcement_strict_accuracy: 1,
        enforcement_strict_shift: 1
      });
    }

    if (memoryDb.employees.length === 0) {
      memoryDb.employees.push(
        { id: 'emp_1', name: 'Rahul Sharma', email: 'rahul.sharma@vaidhyar.org', role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_2', name: 'Dr. Ananya Iyer', email: 'ananya.iyer@vaidhyar.org', role: 'employee', status: 'active', needs_review: 0 },
        { id: 'emp_admin', name: 'Dr. Marcus Vance (Chief Admin)', email: 'admin@vaidhyar.org', role: 'admin', status: 'active', needs_review: 0 }
      );

      memoryDb.shifts.push(
        { id: 'shift_1', employee_id: 'emp_1', shift_name: 'Emergency Night Shift', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 },
        { id: 'shift_2', employee_id: 'emp_2', shift_name: 'Emergency Night Duty', start_time: '20:00', end_time: '06:00', is_night_shift: 1, allowed_early_in_mins: 720, allowed_late_in_mins: 1440, allowed_early_out_mins: 720, allowed_late_out_mins: 1440 }
      );
    }
  }

  return true;
}

function getCollectionName(sql) {
  const lower = sql.toLowerCase();
  if (lower.includes('correction_requests')) return 'correction_requests';
  if (lower.includes('attendance_records')) return 'attendance_records';
  if (lower.includes('attendance_attempts')) return 'attendance_attempts';
  if (lower.includes('webauthn_credentials')) return 'webauthn_credentials';
  if (lower.includes('shift_instances')) return 'shift_instances';
  if (lower.includes('challenges')) return 'challenges';
  if (lower.includes('system_settings')) return 'system_settings';
  if (lower.includes('audit_logs')) return 'audit_logs';
  if (lower.includes('shifts')) return 'shifts';
  if (lower.includes('sessions')) return 'sessions';
  if (lower.includes('employees')) return 'employees';
  return null;
}

function parseWhereFilter(sql, params) {
  const filter = {};
  let paramIndex = 0;

  if (sql.includes('WHERE')) {
    const whereClause = sql.split(/WHERE/i)[1].split(/ORDER|LIMIT/i)[0].trim();
    const parts = whereClause.split(/\s+AND\s+/i);

    for (const part of parts) {
      const matchParam = part.match(/([a-zA-Z0-9_.]+)\s*=\s*\?/);
      const matchLiteral = part.match(/([a-zA-Z0-9_.]+)\s*=\s*'([^']+)'/);
      const matchNumber = part.match(/([a-zA-Z0-9_.]+)\s*=\s*([0-9.]+)/);
      const matchGte = part.match(/([a-zA-Z0-9_.]+)\s*>=\s*\?/);

      const cleanKey = (key) => key.includes('.') ? key.split('.').pop().trim() : key.trim();

      if (matchGte && paramIndex < params.length) {
        filter[cleanKey(matchGte[1])] = { $gte: params[paramIndex++] };
      } else if (matchParam && paramIndex < params.length) {
        filter[cleanKey(matchParam[1])] = params[paramIndex++];
      } else if (matchLiteral) {
        filter[cleanKey(matchLiteral[1])] = matchLiteral[2];
      } else if (matchNumber) {
        filter[cleanKey(matchNumber[1])] = Number(matchNumber[2]);
      }
    }
  }

  return filter;
}

async function queryAll(sql, params = []) {
  const collectionName = getCollectionName(sql);
  if (!collectionName) return [];

  const lower = sql.toLowerCase();
  const filter = parseWhereFilter(sql, params);

  let list = memoryDb[collectionName].filter(item => {
    for (const key in filter) {
      if (typeof filter[key] === 'object' && filter[key].$gte) {
        if (!(item[key] >= filter[key].$gte)) return false;
      } else if (item[key] !== filter[key]) {
        return false;
      }
    }
    return true;
  });

  if (lower.includes('join employees')) {
    list = list.map(item => {
      const emp = memoryDb.employees.find(e => e.id === item.employee_id);
      return {
        ...item,
        employee_name: emp ? emp.name : 'Unknown',
        employee_email: emp ? emp.email : ''
      };
    });
  }

  if (lower.includes('order by timestamp desc')) {
    list.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  } else if (lower.includes('order by server_timestamp desc')) {
    list.sort((a, b) => new Date(b.server_timestamp) - new Date(a.server_timestamp));
  } else if (lower.includes('order by created_at desc')) {
    list.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  } else if (lower.includes('order by id asc')) {
    list.sort((a, b) => (a.id > b.id ? 1 : -1));
  }

  const limitMatch = lower.match(/limit\s+(\d+)/);
  if (limitMatch) {
    list = list.slice(0, parseInt(limitMatch[1]));
  }

  return list;
}

async function queryGet(sql, params = []) {
  const collectionName = getCollectionName(sql);
  if (!collectionName) return null;

  const lower = sql.toLowerCase();
  if (lower.includes('count(*)')) {
    const filter = parseWhereFilter(sql, params);
    const count = memoryDb[collectionName].filter(item => {
      for (const key in filter) {
        if (typeof filter[key] === 'object' && filter[key].$gte) {
          if (!(item[key] >= filter[key].$gte)) return false;
        } else if (item[key] !== filter[key]) return false;
      }
      return true;
    }).length;
    return { count };
  }

  const list = await queryAll(sql, params);
  return list[0] || null;
}

async function queryRun(sql, params = []) {
  const collectionName = getCollectionName(sql);
  const lower = sql.toLowerCase();

  if (!collectionName) return { changes: 0 };

  if (lower.includes('insert into')) {
    const colsMatch = sql.match(/\(([^)]+)\)\s*VALUES\s*\(([^)]+)\)/i);
    if (colsMatch) {
      const cols = colsMatch[1].split(',').map(c => c.trim());
      const valTokens = colsMatch[2].split(',').map(v => v.trim());
      const doc = {};
      let paramIdx = 0;

      cols.forEach((col, idx) => {
        const valToken = valTokens[idx];
        if (valToken === '?') {
          doc[col] = params[paramIdx++];
        } else if (valToken && valToken.startsWith("'") && valToken.endsWith("'")) {
          doc[col] = valToken.slice(1, -1);
        } else if (valToken && !isNaN(Number(valToken))) {
          doc[col] = Number(valToken);
        }
      });

      memoryDb[collectionName].push(doc);
      return { lastID: doc.id, changes: 1 };
    }
  } else if (lower.includes('update')) {
    const setMatch = sql.match(/SET\s+([\s\S]+)\s+WHERE/i);
    if (setMatch) {
      const setClause = setMatch[1];
      const setFields = setClause.split(',');
      const updateDoc = {};
      let paramIdx = 0;

      for (const field of setFields) {
        const parts = field.split('=').map(s => s.trim());
        const col = parts[0].trim();
        const val = parts[1].trim();

        if (val === '?') {
          updateDoc[col] = params[paramIdx++];
        } else if (val.startsWith("'") && val.endsWith("'")) {
          updateDoc[col] = val.slice(1, -1);
        } else if (!isNaN(Number(val))) {
          updateDoc[col] = Number(val);
        }
      }

      const whereParams = params.slice(paramIdx);
      const whereFilter = parseWhereFilter(sql, whereParams);

      let updatedCount = 0;
      memoryDb[collectionName].forEach(item => {
        let match = true;
        for (const key in whereFilter) {
          if (item[key] !== whereFilter[key]) match = false;
        }
        if (match) {
          Object.assign(item, updateDoc);
          updatedCount++;
        }
      });
      return { changes: updatedCount };
    }
  } else if (lower.includes('delete from')) {
    const filter = parseWhereFilter(sql, params);
    const beforeCount = memoryDb[collectionName].length;
    memoryDb[collectionName] = memoryDb[collectionName].filter(item => {
      for (const key in filter) {
        if (item[key] !== filter[key]) return true;
      }
      return false;
    });
    return { changes: beforeCount - memoryDb[collectionName].length };
  }

  return { changes: 0 };
}

module.exports = {
  isPg: false,
  isMongo: true,
  mongoose,
  models,
  initDb,
  queryAll,
  queryGet,
  queryRun
};
