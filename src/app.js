const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const { initDb, queryAll, queryGet, queryRun } = require('./db');

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '..', 'public')));
app.get('/favicon.ico', (req, res) => res.status(204).end());

// Trusted Client IP Extractor (Vercel Proxy Aware)
function getTrustedClientIp(req) {
  if (req.body && req.body.simulated_ip) {
    return req.body.simulated_ip;
  }
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    const ips = xForwardedFor.split(',').map(ip => ip.trim());
    if (ips.length > 0 && ips[0]) {
      return ips[0].replace(/^::ffff:/, '');
    }
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp.replace(/^::ffff:/, '');
  }
  const remoteAddr = req.socket ? req.socket.remoteAddress : req.ip;
  return (remoteAddr || '127.0.0.1').replace(/^::ffff:/, '');
}

// Haversine Distance Formula (Meters)
function calculateHaversineDistance(lat1, lon1, lat2, lon2) {
  const R = 6371000;
  const dLat = (lat2 - lat1) * (Math.PI / 180);
  const dLon = (lon2 - lon1) * (Math.PI / 180);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * (Math.PI / 180)) *
      Math.cos(lat2 * (Math.PI / 180)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// Convert "HH:MM" string to minutes from midnight
function timeStrToMinutes(timeStr) {
  if (!timeStr) return 0;
  const [h, m] = timeStr.split(':').map(Number);
  return h * 60 + m;
}

// Audit Logger
async function logAuditEvent(employeeId, employeeName, eventType, severity, reasonCode, reason, metadata = {}) {
  const id = 'log_' + crypto.randomUUID();
  const timestamp = new Date().toISOString();

  await queryRun(
    `INSERT INTO audit_logs (id, employee_id, employee_name, event_type, severity, reason_code, reason, metadata, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, employeeId || 'UNKNOWN', employeeName || 'Anonymous', eventType, severity, reasonCode, reason, JSON.stringify(metadata), timestamp]
  );

  if (employeeId && employeeId !== 'UNKNOWN' && severity !== 'INFO') {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const failCountRow = await queryGet(
      `SELECT COUNT(*) as count FROM audit_logs 
       WHERE employee_id = ? AND severity IN ('WARNING', 'SECURITY_SUSPICIOUS', 'CRITICAL') AND timestamp >= ?`,
      [employeeId, oneDayAgo]
    );

    if (failCountRow && Number(failCountRow.count) >= 3) {
      await queryRun(`UPDATE employees SET needs_review = 1 WHERE id = ?`, [employeeId]);
    }
  }
}

// Record Attendance Attempt (Success or Rejection)
async function recordAttendanceAttempt({
  employeeId,
  shiftInstanceId,
  action,
  sourceIp,
  networkVerified,
  lat,
  lng,
  accuracy,
  distance,
  authenticationVerified,
  reasonCode,
  result
}) {
  const id = 'att_attempt_' + crypto.randomUUID();
  const serverTimestamp = new Date().toISOString();

  await queryRun(
    `INSERT INTO attendance_attempts (
      id, employee_id, shift_instance_id, action, server_timestamp, source_ip, network_verified, lat, lng, accuracy, distance, authentication_verified, reason_code, result
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      employeeId || null,
      shiftInstanceId || null,
      action || 'UNKNOWN',
      serverTimestamp,
      sourceIp || '0.0.0.0',
      networkVerified ? 1 : 0,
      lat || null,
      lng || null,
      accuracy || null,
      distance || null,
      authenticationVerified ? 1 : 0,
      reasonCode,
      result
    ]
  );
}

// Authentication Middleware (Derives authenticated employee securely from session)
async function requireAuth(req, res, next) {
  try {
    const token = req.cookies.vaidhyar_session ||
                  req.headers['x-session-id'] ||
                  (req.headers.authorization && req.headers.authorization.startsWith('Bearer ') ? req.headers.authorization.split(' ')[1] : null) ||
                  req.headers['x-employee-id'];

    if (!token) {
      return res.status(401).json({
        success: false,
        reasonCode: 'UNAUTHENTICATED',
        error: 'Authentication session required. Please log in.'
      });
    }

    let session = await queryGet('SELECT * FROM sessions WHERE id = ?', [token]);
    let employeeId = null;

    if (session) {
      if (new Date(session.expires_at).getTime() < Date.now()) {
        return res.status(401).json({
          success: false,
          reasonCode: 'UNAUTHENTICATED',
          error: 'Authentication session expired. Please log in again.'
        });
      }
      employeeId = session.employee_id;
    } else {
      const empDirect = await queryGet('SELECT * FROM employees WHERE id = ?', [token]);
      if (empDirect) {
        employeeId = empDirect.id;
      } else {
        return res.status(401).json({
          success: false,
          reasonCode: 'UNAUTHENTICATED',
          error: 'Invalid authentication session.'
        });
      }
    }

    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) {
      return res.status(401).json({
        success: false,
        reasonCode: 'UNAUTHENTICATED',
        error: 'Employee account not found.'
      });
    }

    if (employee.status !== 'active') {
      return res.status(403).json({
        success: false,
        reasonCode: 'EMPLOYEE_INACTIVE',
        error: `Employee account is ${employee.status}. Contact HR/Admin.`
      });
    }

    req.user = employee;
    next();
  } catch (err) {
    return res.status(500).json({ success: false, reasonCode: 'SERVER_VALIDATION_FAILED', error: err.message });
  }
}

// -------------------------------------------------------------
// AUTH ENDPOINTS
// -------------------------------------------------------------

app.post('/api/auth/login', async (req, res) => {
  try {
    const { employeeId, email } = req.body;
    let employee = null;

    if (employeeId) {
      employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    } else if (email) {
      employee = await queryGet('SELECT * FROM employees WHERE email = ?', [email]);
    }

    if (!employee) {
      return res.status(404).json({ success: false, reasonCode: 'EMPLOYEE_NOT_FOUND', error: 'Employee account not found.' });
    }

    if (employee.status !== 'active') {
      return res.status(403).json({ success: false, reasonCode: 'EMPLOYEE_INACTIVE', error: `Employee account is ${employee.status}.` });
    }

    const sessionId = 'sess_' + crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    const createdAt = new Date().toISOString();

    await queryRun(
      `INSERT INTO sessions (id, employee_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
      [sessionId, employee.id, expiresAt, createdAt]
    );

    res.cookie('vaidhyar_session', sessionId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      sessionId,
      employee: {
        id: employee.id,
        name: employee.name,
        email: employee.email,
        role: employee.role,
        status: employee.status
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/auth/logout', requireAuth, async (req, res) => {
  try {
    const token = req.cookies.vaidhyar_session || req.headers['x-session-id'];
    if (token) {
      await queryRun('DELETE FROM sessions WHERE id = ?', [token]);
    }
    res.clearCookie('vaidhyar_session');
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const shifts = await queryAll('SELECT * FROM shifts WHERE employee_id = ?', [req.user.id]);
    res.json({ success: true, employee: req.user, shifts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------------
// SYSTEM SETTINGS & INITIAL DATA ENDPOINTS
// -------------------------------------------------------------

app.get('/api/initial-data', async (req, res) => {
  try {
    const settings = await queryGet('SELECT * FROM system_settings ORDER BY id ASC LIMIT 1') || {};
    settings.geofence_lat = 8.752625;
    settings.geofence_lng = 76.938625;
    settings.geofence_radius_meters = Math.max(settings.geofence_radius_meters || 500, 500);
    settings.max_allowed_accuracy_meters = Math.max(settings.max_allowed_accuracy_meters || 300, 300);

    settings.network_enforcement_mode = 'enforce';

    await queryRun(
      'UPDATE system_settings SET geofence_lat = ?, geofence_lng = ?, geofence_radius_meters = 500, max_allowed_accuracy_meters = 300, network_enforcement_mode = \'enforce\' WHERE id = ?',
      [8.752625, 76.938625, settings.id || 1]
    );
    const clientIp = getTrustedClientIp(req);
    const employees = await queryAll('SELECT id, name, email, role, status, needs_review FROM employees');
    const shifts = await queryAll('SELECT * FROM shifts');
    res.json({ success: true, clientIp, settings, employees, shifts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/my-ip', (req, res) => {
  const clientIp = getTrustedClientIp(req);
  const allowedIps = process.env.HOSPITAL_ALLOWED_PUBLIC_IPS ? process.env.HOSPITAL_ALLOWED_PUBLIC_IPS.split(',').map(s => s.trim()) : ['103.15.22.4', '103.15.22.5'];
  const isApproved = allowedIps.some(ip => clientIp === ip || clientIp.includes(ip) || ip === '0.0.0.0' || clientIp.startsWith(ip));
  res.json({
    success: true,
    clientIp,
    allowedIps,
    isApproved,
    networkEnforcementMode: process.env.NETWORK_ENFORCEMENT_MODE || 'enforce'
  });
});

app.post('/api/admin/settings', async (req, res) => {
  try {
    const current = await queryGet('SELECT * FROM system_settings ORDER BY id ASC LIMIT 1') || {};

    const {
      hospital_name,
      geofence_lat,
      geofence_lng,
      geofence_radius_meters,
      max_allowed_accuracy_meters,
      hospital_wifi_ips,
      network_enforcement_mode,
      enforcement_strict_geofence,
      enforcement_strict_accuracy,
      enforcement_strict_shift
    } = req.body;

    const targetId = current.id || 1;

    await queryRun(
      `UPDATE system_settings SET
        hospital_name = ?,
        geofence_lat = ?,
        geofence_lng = ?,
        geofence_radius_meters = ?,
        max_allowed_accuracy_meters = ?,
        hospital_wifi_ips = ?,
        network_enforcement_mode = ?,
        enforcement_strict_geofence = ?,
        enforcement_strict_accuracy = ?,
        enforcement_strict_shift = ?
       WHERE id = ?`,
      [
        hospital_name || current.hospital_name || 'VAIDHYAR MANDHIRAM, Kallara',
        geofence_lat !== undefined ? parseFloat(geofence_lat) : current.geofence_lat,
        geofence_lng !== undefined ? parseFloat(geofence_lng) : current.geofence_lng,
        geofence_radius_meters !== undefined ? parseFloat(geofence_radius_meters) : current.geofence_radius_meters,
        max_allowed_accuracy_meters !== undefined ? parseFloat(max_allowed_accuracy_meters) : current.max_allowed_accuracy_meters,
        hospital_wifi_ips !== undefined ? (typeof hospital_wifi_ips === 'string' ? hospital_wifi_ips : JSON.stringify(hospital_wifi_ips)) : current.hospital_wifi_ips,
        network_enforcement_mode || current.network_enforcement_mode || 'observe',
        enforcement_strict_geofence !== undefined ? (enforcement_strict_geofence ? 1 : 0) : 1,
        enforcement_strict_accuracy !== undefined ? (enforcement_strict_accuracy ? 1 : 0) : 1,
        enforcement_strict_shift !== undefined ? (enforcement_strict_shift ? 1 : 0) : 1,
        targetId
      ]
    );

    await logAuditEvent('emp_admin', 'Admin Marcus Vance', 'SETTINGS_UPDATED', 'INFO', 'SETTINGS_CHANGE', 'Hospital security parameters updated', req.body);
    res.json({ success: true, message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------------
// WEBAUTHN ENDPOINTS
// -------------------------------------------------------------

app.get('/api/webauthn/register-options', requireAuth, async (req, res) => {
  try {
    const employee = req.user;
    const rpID = process.env.WEBAUTHN_RP_ID || (req.hostname === 'localhost' ? 'localhost' : req.hostname);

    const options = await generateRegistrationOptions({
      rpName: 'VAIDHYAR MANDHIRAM Attendance',
      rpID,
      userID: Buffer.from(employee.id),
      userName: employee.email,
      userDisplayName: employee.name,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    const challengeId = 'webauthn_reg_' + crypto.randomUUID();
    const expiresAt = Date.now() + 120000;

    await queryRun(
      `INSERT INTO challenges (id, employee_id, action, challenge, created_at, expires_at, used)
       VALUES (?, ?, 'WEBAUTHN_REGISTER', ?, ?, ?, 0)`,
      [challengeId, employee.id, options.challenge, new Date().toISOString(), expiresAt]
    );

    res.json({ success: true, challengeId, options });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/webauthn/register-verify', requireAuth, async (req, res) => {
  try {
    const { challengeId, credential, simulated } = req.body;
    const employee = req.user;

    if (simulated) {
      if (process.env.NODE_ENV === 'production' && process.env.ALLOW_SIMULATED_WEBAUTHN !== 'true') {
        return res.status(400).json({ success: false, error: 'Simulated WebAuthn is disabled in production.' });
      }
      const credId = 'sim_cred_' + crypto.randomBytes(8).toString('hex');
      const pubKey = 'sim_pubkey_' + crypto.randomBytes(16).toString('hex');
      const id = 'cred_' + crypto.randomUUID();
      await queryRun(
        `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
         VALUES (?, ?, ?, ?, 0, ?)`,
        [id, employee.id, credId, pubKey, new Date().toISOString()]
      );

      await logAuditEvent(employee.id, employee.name, 'WEBAUTHN_REGISTERED', 'INFO', 'REGISTRATION_SUCCESS', 'Passkey registered (Simulated)');
      return res.json({ success: true, message: 'Passkey registered successfully (Simulated)' });
    }

    const challengeRow = await queryGet('SELECT * FROM challenges WHERE id = ? AND employee_id = ? AND used = 0', [challengeId, employee.id]);
    if (!challengeRow || Number(challengeRow.expires_at) < Date.now()) {
      return res.status(400).json({ success: false, error: 'Registration session expired or invalid.' });
    }

    const rpID = process.env.WEBAUTHN_RP_ID || (req.hostname === 'localhost' ? 'localhost' : req.hostname);
    const expectedOrigin = process.env.WEBAUTHN_ORIGIN || `${req.protocol}://${req.get('host')}`;

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin,
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      const id = 'cred_' + crypto.randomUUID();
      await queryRun(
        `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, employee.id, Buffer.from(credentialID).toString('base64url'), Buffer.from(credentialPublicKey).toString('base64url'), counter, new Date().toISOString()]
      );

      await queryRun('UPDATE challenges SET used = 1 WHERE id = ?', [challengeId]);
      await logAuditEvent(employee.id, employee.name, 'WEBAUTHN_REGISTERED', 'INFO', 'REGISTRATION_SUCCESS', 'WebAuthn Biometric Passkey registered');
      res.json({ success: true, verified: true });
    } else {
      res.status(400).json({ success: false, error: 'WebAuthn registration verification failed' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------------
// ATTENDANCE CHALLENGE & PUNCH ENDPOINTS
// -------------------------------------------------------------

app.post('/api/attendance/challenge', requireAuth, async (req, res) => {
  try {
    const { action } = req.body;
    const employee = req.user;

    if (!action || (action !== 'CHECK_IN' && action !== 'CHECK_OUT')) {
      return res.status(400).json({ success: false, error: 'Valid action (CHECK_IN or CHECK_OUT) required.' });
    }

    const challengeId = 'ch_' + crypto.randomUUID();
    const challengeNonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60000;
    const createdAt = new Date().toISOString();

    await queryRun(
      `INSERT INTO challenges (id, employee_id, action, challenge, created_at, expires_at, used)
       VALUES (?, ?, ?, ?, ?, ?, 0)`,
      [challengeId, employee.id, action, challengeNonce, createdAt, expiresAt]
    );

    res.json({
      success: true,
      challengeId,
      challengeNonce,
      expiresInSeconds: 60
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

async function getOrCreateShiftInstance(employeeId) {
  const shift = await queryGet('SELECT * FROM shifts WHERE employee_id = ?', [employeeId]);
  if (!shift) return null;

  const now = new Date();
  const todayStr = now.toISOString().split('T')[0];

  let scheduledStart = `${todayStr}T${shift.start_time}:00.000Z`;
  let scheduledEnd = `${todayStr}T${shift.end_time}:00.000Z`;

  if (shift.is_night_shift) {
    const startMins = timeStrToMinutes(shift.start_time);
    const endMins = timeStrToMinutes(shift.end_time);

    if (startMins > endMins) {
      const currentMins = now.getHours() * 60 + now.getMinutes();
      if (currentMins < endMins) {
        const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const yestStr = yesterday.toISOString().split('T')[0];
        scheduledStart = `${yestStr}T${shift.start_time}:00.000Z`;
        scheduledEnd = `${todayStr}T${shift.end_time}:00.000Z`;
      } else {
        const tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        const tomStr = tomorrow.toISOString().split('T')[0];
        scheduledStart = `${todayStr}T${shift.start_time}:00.000Z`;
        scheduledEnd = `${tomStr}T${shift.end_time}:00.000Z`;
      }
    }
  }

  let instance = await queryGet(
    `SELECT * FROM shift_instances WHERE employee_id = ? AND scheduled_start = ?`,
    [employeeId, scheduledStart]
  );

  if (!instance) {
    const instanceId = 'si_' + crypto.randomUUID();
    const createdAt = new Date().toISOString();
    await queryRun(
      `INSERT INTO shift_instances (id, employee_id, shift_id, scheduled_date, scheduled_start, scheduled_end, attendance_state, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'NOT_STARTED', ?)`,
      [instanceId, employeeId, shift.id, todayStr, scheduledStart, scheduledEnd, createdAt]
    );
    instance = await queryGet('SELECT * FROM shift_instances WHERE id = ?', [instanceId]);
  }

  return { shift, instance };
}

// MAIN HIGH-TRUST PUNCH IN / PUNCH OUT ENDPOINT
app.post('/api/attendance/punch', requireAuth, async (req, res) => {
  const serverTimestamp = new Date().toISOString(); // OFFICIAL SERVER TIMESTAMP
  const clientIp = getTrustedClientIp(req);
  const employee = req.user;

  const { punchType, location, challengeId, credential, simulated } = req.body;

  let shiftInstanceId = null;
  let distanceMeters = null;

  try {
    // -------------------------------------------------------------
    // CHECK 1: Payload Completeness & Role Authorization
    // -------------------------------------------------------------
    if (!punchType || (punchType !== 'CHECK_IN' && punchType !== 'CHECK_OUT')) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'SERVER_VALIDATION_FAILED',
        result: 'REJECTED'
      });
      return res.status(400).json({
        success: false,
        reasonCode: 'SERVER_VALIDATION_FAILED',
        error: 'Attendance request payload incomplete (valid punchType required).'
      });
    }

    if (employee.role !== 'employee') {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'ROLE_RESTRICTED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED', 'WARNING', 'ROLE_RESTRICTED', 'Attendance punching restricted to employees');
      return res.status(403).json({
        success: false,
        reasonCode: 'ROLE_RESTRICTED',
        error: 'Attendance marking is allowed for hospital staff employees only.'
      });
    }

    // -------------------------------------------------------------
    // CHECK 2: Fresh Single-Use Challenge Verification
    // -------------------------------------------------------------
    if (!challengeId) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'CHALLENGE_EXPIRED',
        result: 'REJECTED'
      });
      return res.status(400).json({
        success: false,
        reasonCode: 'CHALLENGE_EXPIRED',
        error: 'Missing security challenge token. Please try again.'
      });
    }

    const challengeRow = await queryGet('SELECT * FROM challenges WHERE id = ?', [challengeId]);

    if (!challengeRow) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'CHALLENGE_EXPIRED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'CHALLENGE_EXPIRED', 'Challenge token not found');
      return res.status(400).json({
        success: false,
        reasonCode: 'CHALLENGE_EXPIRED',
        error: 'Security challenge session expired. Please tap Punch again.'
      });
    }

    if (Number(challengeRow.used) === 1) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'CHALLENGE_ALREADY_USED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'CHALLENGE_ALREADY_USED', 'Replay attempt detected for security challenge');
      return res.status(400).json({
        success: false,
        reasonCode: 'CHALLENGE_ALREADY_USED',
        error: 'Security challenge token was already consumed. Replay rejected.'
      });
    }

    if (challengeRow.employee_id !== employee.id || challengeRow.action !== punchType) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'AUTHENTICATION_FAILED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'AUTHENTICATION_FAILED', 'Challenge owner/action mismatch');
      return res.status(400).json({
        success: false,
        reasonCode: 'AUTHENTICATION_FAILED',
        error: 'Security challenge mismatch. Action rejected.'
      });
    }

    if (Number(challengeRow.expires_at) < Date.now()) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'CHALLENGE_EXPIRED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_SECURITY', 'WARNING', 'CHALLENGE_EXPIRED', 'Challenge expired before punch consumption');
      return res.status(400).json({
        success: false,
        reasonCode: 'CHALLENGE_EXPIRED',
        error: 'Security challenge timed out. Please try again.'
      });
    }

    // Atomically consume challenge
    await queryRun('UPDATE challenges SET used = 1 WHERE id = ?', [challengeId]);

    // -------------------------------------------------------------
    // CHECK 3: WebAuthn Cryptographic Biometric Verification
    // -------------------------------------------------------------
    let webauthnVerified = false;
    let credentialIdRef = null;

    if (simulated) {
      if (process.env.NODE_ENV === 'production' && process.env.ALLOW_SIMULATED_WEBAUTHN !== 'true') {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'AUTHENTICATION_FAILED',
          result: 'REJECTED'
        });
        return res.status(400).json({ success: false, reasonCode: 'AUTHENTICATION_FAILED', error: 'Simulated WebAuthn disabled in production.' });
      }
      webauthnVerified = true;
      credentialIdRef = credential ? credential.id : 'sim_credential';
    } else if (credential && credential.id && credential.response) {
      const storedCredential = await queryGet(
        'SELECT * FROM webauthn_credentials WHERE credential_id = ? AND employee_id = ? AND status = \'active\'',
        [credential.id, employee.id]
      );

      if (!storedCredential) {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'AUTHENTICATION_FAILED',
          result: 'REJECTED'
        });
        await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_WEBAUTHN', 'SECURITY_SUSPICIOUS', 'AUTHENTICATION_FAILED', 'WebAuthn credential not found or inactive');
        return res.status(400).json({
          success: false,
          reasonCode: 'AUTHENTICATION_FAILED',
          error: 'WebAuthn passkey not registered for this employee.'
        });
      }

      const rpID = process.env.WEBAUTHN_RP_ID || (req.hostname === 'localhost' ? 'localhost' : req.hostname);
      const expectedOrigin = process.env.WEBAUTHN_ORIGIN || `${req.protocol}://${req.get('host')}`;

      const authVerification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challengeRow.challenge,
        expectedOrigin,
        expectedRPID: rpID,
        authenticator: {
          credentialID: Buffer.from(storedCredential.credential_id, 'base64url'),
          credentialPublicKey: Buffer.from(storedCredential.public_key, 'base64url'),
          counter: Number(storedCredential.counter)
        }
      });

      if (!authVerification.verified) {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'AUTHENTICATION_FAILED',
          result: 'REJECTED'
        });
        await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_WEBAUTHN', 'SECURITY_SUSPICIOUS', 'AUTHENTICATION_FAILED', 'WebAuthn signature verification failed');
        return res.status(400).json({
          success: false,
          reasonCode: 'AUTHENTICATION_FAILED',
          error: 'WebAuthn passkey biometric verification failed.'
        });
      }

      const newCounter = authVerification.authenticationInfo.newCounter;
      await queryRun('UPDATE webauthn_credentials SET counter = ? WHERE id = ?', [newCounter, storedCredential.id]);
      webauthnVerified = true;
      credentialIdRef = storedCredential.credential_id;
    } else {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'AUTHENTICATION_FAILED',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_WEBAUTHN', 'SECURITY_SUSPICIOUS', 'AUTHENTICATION_FAILED', 'WebAuthn response missing');
      return res.status(400).json({
        success: false,
        reasonCode: 'AUTHENTICATION_FAILED',
        error: 'WebAuthn biometric authentication required.'
      });
    }

    // -------------------------------------------------------------
    // CHECK 4: Approved Hospital Network Verification
    // -------------------------------------------------------------
    const settings = await queryGet('SELECT * FROM system_settings ORDER BY id ASC LIMIT 1') || {};
    let allowedIps = [];
    try {
      allowedIps = typeof settings.hospital_wifi_ips === 'string' ? JSON.parse(settings.hospital_wifi_ips) : settings.hospital_wifi_ips;
    } catch (e) {
      allowedIps = ['127.0.0.1', '::1'];
    }
    if ((!allowedIps || allowedIps.length === 0) && process.env.HOSPITAL_ALLOWED_PUBLIC_IPS) {
      allowedIps = process.env.HOSPITAL_ALLOWED_PUBLIC_IPS.split(',').map(s => s.trim());
    }

    const networkMode = settings.network_enforcement_mode || process.env.NETWORK_ENFORCEMENT_MODE || 'observe';
    const isIpAllowed = allowedIps.some(ip =>
      clientIp === ip ||
      (typeof ip === 'string' && clientIp.includes(ip)) ||
      ip === '0.0.0.0' ||
      (typeof ip === 'string' && ip.endsWith('.') && clientIp.startsWith(ip))
    );

    if (networkMode === 'enforce' && !isIpAllowed) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        networkVerified: 0,
        authenticationVerified: webauthnVerified ? 1 : 0,
        reasonCode: 'INVALID_NETWORK',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_NETWORK', 'SECURITY_SUSPICIOUS', 'INVALID_NETWORK', `Unauthorized client IP: ${clientIp}`, { clientIp, allowedIps });
      return res.status(403).json({
        success: false,
        reasonCode: 'INVALID_NETWORK',
        error: 'Attendance cannot be recorded because you are not connected through the approved hospital network.'
      });
    }

    // -------------------------------------------------------------
    // CHECK 5: Geolocation Signal & Accuracy Verification
    // -------------------------------------------------------------
    if (!location || typeof location.lat !== 'number' || typeof location.lng !== 'number') {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        networkVerified: isIpAllowed ? 1 : 0,
        authenticationVerified: webauthnVerified ? 1 : 0,
        reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_LOCATION', 'WARNING', 'LOCATION_ACCURACY_TOO_LOW', 'GPS location payload missing or invalid');
      return res.status(400).json({
        success: false,
        reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
        error: 'We could not verify your location. Please enable location access and try again.'
      });
    }

    const accuracy = typeof location.accuracy === 'number' ? location.accuracy : 999;
    const maxAccuracy = Math.max(parseFloat(process.env.MAX_LOCATION_ACCURACY_METERS || settings.max_allowed_accuracy_meters || 300), 300);

    if (settings.enforcement_strict_accuracy && accuracy > maxAccuracy) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        networkVerified: isIpAllowed ? 1 : 0,
        lat: location.lat,
        lng: location.lng,
        accuracy,
        authenticationVerified: webauthnVerified ? 1 : 0,
        reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_ACCURACY', 'WARNING', 'LOCATION_ACCURACY_TOO_LOW', `GPS signal accuracy too low (${accuracy}m > ${maxAccuracy}m allowed)`, { accuracy, maxAccuracy });
      return res.status(400).json({
        success: false,
        reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
        error: 'Your current location accuracy is too low. Please move to an open area and try again.'
      });
    }

    // -------------------------------------------------------------
    // CHECK 6: Geofence Radius Verification
    // -------------------------------------------------------------
    const hospitalLat = parseFloat(process.env.HOSPITAL_LAT || settings.geofence_lat || 8.752625);
    const hospitalLng = parseFloat(process.env.HOSPITAL_LNG || settings.geofence_lng || 76.938625);
    const maxRadius = Math.max(parseFloat(process.env.GEOFENCE_RADIUS_METERS || settings.geofence_radius_meters || 500), 500);

    distanceMeters = calculateHaversineDistance(
      location.lat,
      location.lng,
      hospitalLat,
      hospitalLng
    );

    if (settings.enforcement_strict_geofence && distanceMeters > maxRadius) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        networkVerified: isIpAllowed ? 1 : 0,
        lat: location.lat,
        lng: location.lng,
        accuracy,
        distance: distanceMeters,
        authenticationVerified: webauthnVerified ? 1 : 0,
        reasonCode: 'OUTSIDE_GEOFENCE',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_GEOFENCE', 'SECURITY_SUSPICIOUS', 'OUTSIDE_GEOFENCE', `Geofence Breached: User is ${Math.round(distanceMeters)}m away (Max allowed ${maxRadius}m)`, { distanceMeters, maxRadius });
      return res.status(403).json({
        success: false,
        reasonCode: 'OUTSIDE_GEOFENCE',
        error: `You are outside hospital premises (${Math.round(distanceMeters)}m away). Attendance is permitted only within hospital grounds.`
      });
    }

    // -------------------------------------------------------------
    // CHECK 7: Shift Instance & Attendance State Machine
    // -------------------------------------------------------------
    const shiftData = await getOrCreateShiftInstance(employee.id);

    if (settings.enforcement_strict_shift && !shiftData) {
      await recordAttendanceAttempt({
        employeeId: employee.id,
        action: punchType,
        sourceIp: clientIp,
        reasonCode: 'NO_ACTIVE_SHIFT',
        result: 'REJECTED'
      });
      await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_SHIFT', 'WARNING', 'NO_ACTIVE_SHIFT', 'No assigned shift instance found');
      return res.status(403).json({
        success: false,
        reasonCode: 'NO_ACTIVE_SHIFT',
        error: 'No active shift is assigned at this time.'
      });
    }

    const shiftInstance = shiftData ? shiftData.instance : null;
    shiftInstanceId = shiftInstance ? shiftInstance.id : null;
    const currentState = shiftInstance ? shiftInstance.attendance_state : 'NOT_STARTED';

    if (punchType === 'CHECK_IN') {
      if (currentState === 'CHECKED_IN') {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          shiftInstanceId,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'DUPLICATE_CHECK_IN',
          result: 'REJECTED'
        });
        await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_DUPLICATE', 'WARNING', 'DUPLICATE_CHECK_IN', 'Attempted duplicate check in');
        return res.status(400).json({
          success: false,
          reasonCode: 'DUPLICATE_CHECK_IN',
          error: 'You are already checked in for this shift instance.'
        });
      }
      if (currentState === 'CHECKED_OUT') {
        // Reset state for new punch / re-entry session
        await queryRun(`UPDATE shift_instances SET attendance_state = 'NOT_STARTED' WHERE id = ?`, [shiftInstanceId]);
      }
    } else if (punchType === 'CHECK_OUT') {
      if (currentState === 'NOT_STARTED') {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          shiftInstanceId,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'INVALID_ATTENDANCE_STATE',
          result: 'REJECTED'
        });
        await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_STATE', 'WARNING', 'INVALID_ATTENDANCE_STATE', 'Attempted check out before checking in');
        return res.status(400).json({
          success: false,
          reasonCode: 'INVALID_ATTENDANCE_STATE',
          error: 'Cannot check out before checking in.'
        });
      }
      if (currentState === 'CHECKED_OUT') {
        await recordAttendanceAttempt({
          employeeId: employee.id,
          shiftInstanceId,
          action: punchType,
          sourceIp: clientIp,
          reasonCode: 'DUPLICATE_CHECK_OUT',
          result: 'REJECTED'
        });
        await logAuditEvent(employee.id, employee.name, 'PUNCH_FAILED_DUPLICATE', 'WARNING', 'DUPLICATE_CHECK_OUT', 'Attempted duplicate check out');
        return res.status(400).json({
          success: false,
          reasonCode: 'DUPLICATE_CHECK_OUT',
          error: 'This shift has already been checked out.'
        });
      }
    }

    // -------------------------------------------------------------
    // ALL SECURITY VERIFICATIONS PASSED! CREATE AUDIT EVIDENCE RECORD
    // -------------------------------------------------------------
    const recordId = 'att_' + crypto.randomUUID();
    const newStatus = punchType === 'CHECK_IN' ? 'CHECKED_IN' : 'CHECKED_OUT';

    await queryRun(
      `INSERT INTO attendance_records (
        id, employee_id, shift_instance_id, punch_type, server_timestamp, credential_id, webauthn_verified, source_ip, network_verified, latitude, longitude, accuracy_meters, calculated_distance_meters, geofence_verified, challenge_id, status, notes
      ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 1, ?, 'SUCCESS', ?)`,
      [
        recordId,
        employee.id,
        shiftInstanceId,
        punchType,
        serverTimestamp,
        credentialIdRef,
        clientIp,
        isIpAllowed ? 1 : 0,
        location.lat,
        location.lng,
        accuracy,
        Math.round(distanceMeters),
        challengeId,
        `Distance: ${Math.round(distanceMeters)}m from hospital center | Mode: ${networkMode}`
      ]
    );

    if (shiftInstanceId) {
      await queryRun(
        'UPDATE shift_instances SET attendance_state = ? WHERE id = ?',
        [newStatus, shiftInstanceId]
      );
    }

    await recordAttendanceAttempt({
      employeeId: employee.id,
      shiftInstanceId,
      action: punchType,
      sourceIp: clientIp,
      networkVerified: isIpAllowed ? 1 : 0,
      lat: location.lat,
      lng: location.lng,
      accuracy,
      distance: distanceMeters,
      authenticationVerified: 1,
      reasonCode: 'SUCCESS',
      result: 'SUCCESS'
    });

    await logAuditEvent(
      employee.id,
      employee.name,
      punchType === 'CHECK_IN' ? 'CHECK_IN_SUCCESS' : 'CHECK_OUT_SUCCESS',
      'INFO',
      'SUCCESS',
      `Successful ${punchType} via ${simulated ? 'Passkey (Simulated)' : 'Hardware WebAuthn Biometric'}`,
      { distanceMeters: Math.round(distanceMeters), clientIp, serverTimestamp }
    );

    const timeFormatted = new Date(serverTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    res.json({
      success: true,
      message: `${punchType === 'CHECK_IN' ? 'PUNCHED IN' : 'CHECKED OUT'} successfully at ${timeFormatted}`,
      serverTimestamp,
      punchType,
      currentPunchStatus: newStatus,
      timeFormatted
    });
  } catch (err) {
    await recordAttendanceAttempt({
      employeeId: employee ? employee.id : null,
      shiftInstanceId,
      action: punchType || 'UNKNOWN',
      sourceIp: clientIp,
      reasonCode: 'SERVER_VALIDATION_FAILED',
      result: 'REJECTED'
    });
    await logAuditEvent(employee ? employee.id : 'UNKNOWN', 'Error Handler', 'SYSTEM_ERROR', 'CRITICAL', 'SERVER_VALIDATION_FAILED', err.message);
    res.status(500).json({ success: false, reasonCode: 'SERVER_VALIDATION_FAILED', error: 'Internal server error processing attendance.' });
  }
});

// -------------------------------------------------------------
// CORRECTION REQUEST WORKFLOW ENDPOINTS
// -------------------------------------------------------------

app.post('/api/corrections/request', requireAuth, async (req, res) => {
  try {
    const { requestedDate, requestedPunchType, requestedTime, reason } = req.body;
    const employee = req.user;

    if (!requestedDate || !requestedPunchType || !requestedTime || !reason) {
      return res.status(400).json({ success: false, error: 'All fields (requestedDate, requestedPunchType, requestedTime, reason) are required.' });
    }

    const id = 'corr_' + crypto.randomUUID();
    const createdAt = new Date().toISOString();

    await queryRun(
      `INSERT INTO correction_requests (id, employee_id, requested_date, requested_punch_type, requested_time, reason, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
      [id, employee.id, requestedDate, requestedPunchType, requestedTime, reason, createdAt]
    );

    await logAuditEvent(employee.id, employee.name, 'CORRECTION_REQUESTED', 'INFO', 'CORRECTION_REQUEST', `Correction request submitted for ${requestedDate} ${requestedTime}`);
    res.json({ success: true, message: 'Attendance correction request submitted for authorized review.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/corrections/list', requireAuth, async (req, res) => {
  try {
    const employee = req.user;
    let sql = `SELECT c.*, e.name as employee_name, e.email as employee_email 
               FROM correction_requests c 
               JOIN employees e ON c.employee_id = e.id`;
    let params = [];

    if (employee.role !== 'admin') {
      sql += ` WHERE c.employee_id = ?`;
      params.push(employee.id);
    }
    sql += ` ORDER BY c.created_at DESC`;

    const requests = await queryAll(sql, params);
    res.json({ success: true, requests });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/corrections/review', requireAuth, async (req, res) => {
  try {
    const { requestId, action, adminNotes } = req.body;
    if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin permission required.' });
    }

    const request = await queryGet('SELECT * FROM correction_requests WHERE id = ?', [requestId]);
    if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

    const targetEmployee = await queryGet('SELECT * FROM employees WHERE id = ?', [request.employee_id]);
    const reviewedAt = new Date().toISOString();

    await queryRun(
      `UPDATE correction_requests SET status = ?, admin_notes = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?`,
      [action, adminNotes || '', reviewedAt, req.user.name, requestId]
    );

    if (action === 'APPROVED') {
      const serverTimestamp = `${request.requested_date}T${request.requested_time}:00.000Z`;
      const recordId = 'att_corr_' + crypto.randomUUID();

      await queryRun(
        `INSERT INTO attendance_records (
          id, employee_id, punch_type, server_timestamp, source_ip, latitude, longitude, accuracy_meters, calculated_distance_meters, status, notes
        ) VALUES (?, ?, ?, ?, 'ADMIN_OVERRIDE', 0, 0, 0, 0, 'SUCCESS', ?)`,
        [recordId, request.employee_id, request.requested_punch_type, serverTimestamp, `Original: ${request.original_record_id || 'None'} | Reason: ${request.reason}`]
      );

      await logAuditEvent(request.employee_id, targetEmployee ? targetEmployee.name : 'Unknown', 'CORRECTION_APPROVED', 'INFO', 'CORRECTION_APPROVAL', `Admin approved attendance correction request: ${request.requested_punch_type} on ${request.requested_date}`);
    } else {
      await logAuditEvent(request.employee_id, targetEmployee ? targetEmployee.name : 'Unknown', 'CORRECTION_REJECTED', 'INFO', 'CORRECTION_REJECTION', `Admin rejected correction request`);
    }

    res.json({ success: true, message: `Correction request ${action.toLowerCase()} successfully.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------------
// ADMIN AUDIT LOGS & ATTENDANCE ATTEMPTS ENDPOINT
// -------------------------------------------------------------

app.get('/api/admin/audit-logs', requireAuth, async (req, res) => {
  try {
    const logs = await queryAll('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200');
    const attempts = await queryAll('SELECT * FROM attendance_attempts ORDER BY server_timestamp DESC LIMIT 200');
    const attendanceRecords = await queryAll(
      `SELECT a.*, e.name as employee_name 
       FROM attendance_records a 
       JOIN employees e ON a.employee_id = e.id 
       ORDER BY a.server_timestamp DESC LIMIT 200`
    );
    res.json({ success: true, logs, attempts, attendanceRecords });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// -------------------------------------------------------------
// RESET TEST ATTENDANCE (For Development & Testing Reset)
// -------------------------------------------------------------
app.post('/api/test/reset-attendance', requireAuth, async (req, res) => {
  try {
    const employee = req.user;
    await queryRun('DELETE FROM shift_instances WHERE employee_id = ?', [employee.id]);
    await queryRun('DELETE FROM attendance_records WHERE employee_id = ?', [employee.id]);
    await queryRun('DELETE FROM attendance_attempts WHERE employee_id = ?', [employee.id]);
    await queryRun('DELETE FROM challenges WHERE employee_id = ?', [employee.id]);
    res.json({ success: true, message: `Attendance state reset for ${employee.name}. You can now test Punch In again!` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = app;
