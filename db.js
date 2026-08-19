const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const dbPath = path.join(__dirname, 'attendance.db');

// Reset DB schema if older version is detected
if (fs.existsSync(dbPath)) {
  try {
    fs.unlinkSync(dbPath);
  } catch (err) {}
}

const db = new sqlite3.Database(dbPath);

function initDb() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      // Employees Table
      db.run(`
        CREATE TABLE IF NOT EXISTS employees (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT UNIQUE NOT NULL,
          role TEXT NOT NULL DEFAULT 'employee',
          status TEXT NOT NULL DEFAULT 'active',
          current_punch_status TEXT NOT NULL DEFAULT 'NOT_STARTED',
          last_punch_time TEXT,
          last_punch_id TEXT,
          needs_review INTEGER DEFAULT 0
        )
      `);

      // WebAuthn Credentials Table
      db.run(`
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
          id TEXT PRIMARY KEY,
          employee_id TEXT NOT NULL,
          credential_id TEXT UNIQUE NOT NULL,
          public_key TEXT NOT NULL,
          counter INTEGER NOT NULL DEFAULT 0,
          transports TEXT,
          created_at TEXT NOT NULL,
          FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
      `);

      // Shifts Table
      db.run(`
        CREATE TABLE IF NOT EXISTS shifts (
          id TEXT PRIMARY KEY,
          employee_id TEXT NOT NULL,
          shift_name TEXT NOT NULL,
          start_time TEXT NOT NULL,
          end_time TEXT NOT NULL,
          is_night_shift INTEGER DEFAULT 0,
          allowed_early_in_mins INTEGER DEFAULT 60,
          allowed_late_in_mins INTEGER DEFAULT 720,
          allowed_early_out_mins INTEGER DEFAULT 60,
          allowed_late_out_mins INTEGER DEFAULT 720,
          active_days TEXT DEFAULT 'Mon,Tue,Wed,Thu,Fri,Sat,Sun',
          FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
      `);

      // System Settings Table (Default Hospital Location: QW3Q+2CG, Kallara, Kerala 695608)
      db.run(`
        CREATE TABLE IF NOT EXISTS system_settings (
          id INTEGER PRIMARY KEY DEFAULT 1,
          hospital_name TEXT DEFAULT 'VAIDHYAR MANDHIRAM, Kallara',
          geofence_lat REAL DEFAULT 8.750104,
          geofence_lng REAL DEFAULT 76.938646,
          geofence_radius_meters REAL DEFAULT 30,
          max_allowed_accuracy_meters REAL DEFAULT 50,
          hospital_wifi_ips TEXT DEFAULT '["127.0.0.1", "::1", "::ffff:127.0.0.1", "192.168.86.2", "192.168.86.", "192.168.1.100", "10.0.0.1", "fe80::ca95:8930:cc23:6872"]',
          enforcement_strict_wifi INTEGER DEFAULT 1,
          enforcement_strict_geofence INTEGER DEFAULT 1,
          enforcement_strict_accuracy INTEGER DEFAULT 1,
          enforcement_strict_shift INTEGER DEFAULT 1
        )
      `);

      // Attendance Records (Audit Evidence)
      db.run(`
        CREATE TABLE IF NOT EXISTS attendance_records (
          id TEXT PRIMARY KEY,
          employee_id TEXT NOT NULL,
          shift_id TEXT,
          punch_type TEXT NOT NULL,
          server_timestamp TEXT NOT NULL,
          ip_address TEXT NOT NULL,
          lat REAL,
          lng REAL,
          accuracy REAL,
          calculated_distance_meters REAL,
          verification_method TEXT NOT NULL,
          challenge_id TEXT,
          credential_ref TEXT,
          status TEXT NOT NULL DEFAULT 'SUCCESS',
          notes TEXT,
          FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
      `);

      // Audit Logs Table
      db.run(`
        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          employee_id TEXT,
          employee_name TEXT,
          event_type TEXT NOT NULL,
          severity TEXT NOT NULL,
          reason_code TEXT NOT NULL,
          reason TEXT NOT NULL,
          metadata TEXT,
          timestamp TEXT NOT NULL
        )
      `);

      // Correction Requests Table
      db.run(`
        CREATE TABLE IF NOT EXISTS correction_requests (
          id TEXT PRIMARY KEY,
          employee_id TEXT NOT NULL,
          original_record_id TEXT,
          requested_date TEXT NOT NULL,
          requested_punch_type TEXT NOT NULL,
          requested_time TEXT NOT NULL,
          reason TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'PENDING',
          admin_notes TEXT,
          created_at TEXT NOT NULL,
          reviewed_at TEXT,
          reviewed_by TEXT,
          FOREIGN KEY(employee_id) REFERENCES employees(id)
        )
      `);

      // Seed Initial Settings & Sample Data if empty or update existing settings
      db.get("SELECT COUNT(*) AS count FROM system_settings", (err, row) => {
        if (!err && row.count === 0) {
          db.run(`
            INSERT INTO system_settings (id, hospital_name, geofence_lat, geofence_lng, geofence_radius_meters, max_allowed_accuracy_meters, hospital_wifi_ips)
            VALUES (1, 'VAIDHYAR MANDHIRAM, Kallara', 8.750104, 76.938646, 500, 200, '["127.0.0.1", "::1", "::ffff:", "192.168.", "10.", "172.", "fe80:"]')
          `);
        } else {
          db.run(`UPDATE system_settings SET hospital_name = 'VAIDHYAR MANDHIRAM, Kallara', geofence_lat = 8.750104, geofence_lng = 76.938646, geofence_radius_meters = 500, max_allowed_accuracy_meters = 200, hospital_wifi_ips = '["127.0.0.1", "::1", "::ffff:", "192.168.", "10.", "172.", "fe80:"]' WHERE id = 1`);
        }
      });

      db.get("SELECT COUNT(*) AS count FROM employees", (err, row) => {
        if (!err && row.count === 0) {
          // Seed Sample Staff & Admin
          db.run(`INSERT INTO employees (id, name, email, role, status, current_punch_status) VALUES 
            ('emp_1', 'Rahul Sharma', 'rahul.sharma@vaidhyar.org', 'employee', 'active', 'NOT_STARTED'),
            ('emp_2', 'Dr. Ananya Iyer', 'ananya.iyer@vaidhyar.org', 'employee', 'active', 'NOT_STARTED'),
            ('emp_admin', 'Dr. Marcus Vance (Chief Admin)', 'admin@vaidhyar.org', 'admin', 'active', 'NOT_STARTED')
          `);

          // Seed Shifts (Emergency Night Shift: 20:00 - 06:00 crossing midnight)
          db.run(`INSERT INTO shifts (id, employee_id, shift_name, start_time, end_time, is_night_shift, allowed_early_in_mins, allowed_late_in_mins, allowed_early_out_mins, allowed_late_out_mins) VALUES 
            ('shift_1', 'emp_1', 'Emergency Night Shift', '20:00', '06:00', 1, 720, 1440, 720, 1440),
            ('shift_2', 'emp_2', 'Emergency Night Duty', '20:00', '06:00', 1, 720, 1440, 720, 1440)
          `);
        } else {
          db.run(`UPDATE shifts SET shift_name = 'Emergency Night Shift', start_time = '20:00', end_time = '06:00', is_night_shift = 1, allowed_early_in_mins = 720, allowed_late_in_mins = 1440, allowed_early_out_mins = 720, allowed_late_out_mins = 1440 WHERE id = 'shift_1'`);
        }
        // Log initialization
        db.run(`INSERT INTO audit_logs (id, employee_id, employee_name, event_type, severity, reason_code, reason, metadata, timestamp) VALUES
          ('log_init', 'system', 'System', 'SYSTEM_INITIALIZED', 'INFO', 'SYSTEM_INIT', 'VAIDHYAR MANDHIRAM High-Trust Attendance Module initialized', '{}', '${new Date().toISOString()}')
        `);
        resolve(true);
      });
    });
  });
}

function queryAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
}

function queryGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function queryRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

module.exports = {
  db,
  initDb,
  queryAll,
  queryGet,
  queryRun
};
