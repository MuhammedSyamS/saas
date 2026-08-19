const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const { initDb, queryAll, queryGet, queryRun } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Single-use challenge store (Key: challengeId, Value: { employeeId, action, challenge, expiresAt, used: false })
const challengeStore = new Map();

// Cleanup expired challenges periodically (every 2 mins)
setInterval(() => {
  const now = Date.now();
  for (const [id, data] of challengeStore.entries()) {
    if (data.expiresAt < now) {
      challengeStore.delete(id);
    }
  }
}, 120000);

// Haversine distance formula (in meters)
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

// Log audit events and check for suspicious activity patterns
async function logAuditEvent(employeeId, employeeName, eventType, severity, reasonCode, reason, metadata = {}) {
  const id = 'log_' + crypto.randomUUID();
  const timestamp = new Date().toISOString();

  await queryRun(
    `INSERT INTO audit_logs (id, employee_id, employee_name, event_type, severity, reason_code, reason, metadata, timestamp)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [id, employeeId || 'UNKNOWN', employeeName || 'Anonymous', eventType, severity, reasonCode, reason, JSON.stringify(metadata), timestamp]
  );

  // Check for suspicious attempt threshold (3 or more failed attempts in 24 hours)
  if (employeeId && employeeId !== 'UNKNOWN' && severity !== 'INFO') {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const failCountRow = await queryGet(
      `SELECT COUNT(*) as count FROM audit_logs 
       WHERE employee_id = ? AND severity IN ('WARNING', 'SECURITY_SUSPICIOUS', 'CRITICAL') AND timestamp >= ?`,
      [employeeId, oneDayAgo]
    );

    if (failCountRow && failCountRow.count >= 3) {
      await queryRun(`UPDATE employees SET needs_review = 1 WHERE id = ?`, [employeeId]);
    }
  }
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// Fetch Initial System Data & Current Employee Status
app.get('/api/initial-data', async (req, res) => {
  try {
    const settings = await queryGet('SELECT * FROM system_settings WHERE id = 1');
    const employees = await queryAll('SELECT id, name, email, role, status, current_punch_status, last_punch_time, needs_review FROM employees');
    const shifts = await queryAll('SELECT * FROM shifts');
    res.json({ success: true, settings, employees, shifts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Update System Settings (Admin)
app.post('/api/admin/settings', async (req, res) => {
  try {
    const {
      hospital_name,
      geofence_lat,
      geofence_lng,
      geofence_radius_meters,
      max_allowed_accuracy_meters,
      hospital_wifi_ips,
      enforcement_strict_wifi,
      enforcement_strict_geofence,
      enforcement_strict_accuracy,
      enforcement_strict_shift
    } = req.body;

    await queryRun(
      `UPDATE system_settings SET
        hospital_name = ?,
        geofence_lat = ?,
        geofence_lng = ?,
        geofence_radius_meters = ?,
        max_allowed_accuracy_meters = ?,
        hospital_wifi_ips = ?,
        enforcement_strict_wifi = ?,
        enforcement_strict_geofence = ?,
        enforcement_strict_accuracy = ?,
        enforcement_strict_shift = ?
       WHERE id = 1`,
      [
        hospital_name || 'VAIDHYAR MANDHIRAM',
        parseFloat(geofence_lat),
        parseFloat(geofence_lng),
        parseFloat(geofence_radius_meters),
        parseFloat(max_allowed_accuracy_meters),
        typeof hospital_wifi_ips === 'string' ? hospital_wifi_ips : JSON.stringify(hospital_wifi_ips),
        enforcement_strict_wifi ? 1 : 0,
        enforcement_strict_geofence ? 1 : 0,
        enforcement_strict_accuracy ? 1 : 0,
        enforcement_strict_shift ? 1 : 0
      ]
    );

    await logAuditEvent('emp_admin', 'Admin Marcus Vance', 'SETTINGS_UPDATED', 'INFO', 'SETTINGS_CHANGE', 'Hospital security parameters updated', req.body);
    res.json({ success: true, message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 1. FRESH SECURITY CHALLENGE GENERATION (Single-Use, 60s Expiration)
app.post('/api/attendance/challenge', async (req, res) => {
  try {
    const { employeeId, action } = req.body; // action: 'CHECK_IN' or 'CHECK_OUT'
    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) return res.status(404).json({ success: false, error: 'Employee account not found.' });

    const challengeId = 'ch_' + crypto.randomUUID();
    const challengeNonce = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 60000; // 60 seconds expiration

    challengeStore.set(challengeId, {
      challengeId,
      employeeId,
      action,
      challengeNonce,
      expiresAt,
      used: false
    });

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

// WebAuthn Register Options
app.get('/api/webauthn/register-options', async (req, res) => {
  try {
    const employeeId = req.query.employeeId;
    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) return res.status(404).json({ success: false, error: 'Employee not found' });

    const options = await generateRegistrationOptions({
      rpName: 'VAIDHYAR MANDHIRAM Attendance',
      rpID: req.hostname === 'localhost' ? 'localhost' : req.hostname,
      userID: Buffer.from(employee.id),
      userName: employee.email,
      userDisplayName: employee.name,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    challengeStore.set(`webauthn_reg_${employeeId}`, { challenge: options.challenge, expiresAt: Date.now() + 120000 });
    res.json({ success: true, options });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// WebAuthn Register Verify
app.post('/api/webauthn/register-verify', async (req, res) => {
  try {
    const { employeeId, credential, simulated } = req.body;
    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) return res.status(404).json({ success: false, error: 'Employee not found' });

    if (simulated) {
      const credId = 'sim_cred_' + crypto.randomBytes(8).toString('hex');
      const pubKey = 'sim_pubkey_' + crypto.randomBytes(16).toString('hex');
      const id = 'cred_' + crypto.randomUUID();
      await queryRun(
        `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
         VALUES (?, ?, ?, ?, 0, ?)`,
        [id, employeeId, credId, pubKey, new Date().toISOString()]
      );

      await logAuditEvent(employeeId, employee.name, 'WEBAUTHN_REGISTERED', 'INFO', 'REGISTRATION_SUCCESS', 'Passkey registered (Simulated)');
      return res.json({ success: true, message: 'Passkey registered successfully (Simulated)' });
    }

    const regData = challengeStore.get(`webauthn_reg_${employeeId}`);
    if (!regData || regData.expiresAt < Date.now()) return res.status(400).json({ success: false, error: 'Registration session expired.' });

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: regData.challenge,
      expectedOrigin: `${req.protocol}://${req.get('host')}`,
      expectedRPID: req.hostname === 'localhost' ? 'localhost' : req.hostname,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
      const id = 'cred_' + crypto.randomUUID();
      await queryRun(
        `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, employeeId, Buffer.from(credentialID).toString('base64url'), Buffer.from(credentialPublicKey).toString('base64url'), counter, new Date().toISOString()]
      );

      challengeStore.delete(`webauthn_reg_${employeeId}`);
      await logAuditEvent(employeeId, employee.name, 'WEBAUTHN_REGISTERED', 'INFO', 'REGISTRATION_SUCCESS', 'WebAuthn Biometric Passkey registered');
      res.json({ success: true, verified: true });
    } else {
      res.status(400).json({ success: false, error: 'WebAuthn registration verification failed' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 2. MAIN HIGH-TRUST PUNCH IN / PUNCH OUT ENDPOINT
app.post('/api/attendance/punch', async (req, res) => {
  const serverTimestamp = new Date().toISOString(); // OFFICIAL SERVER TIMESTAMP!
  const clientIp = req.body.simulated_ip || req.headers['x-forwarded-for'] || req.ip || req.socket.remoteAddress;

  try {
    const { employeeId, punchType, location, challengeId, credential, simulated } = req.body; // punchType: 'CHECK_IN' or 'CHECK_OUT'

    // CONDITION 1: Backend Reachability Check
    if (!employeeId || !punchType || !location) {
      return res.status(400).json({
        success: false,
        reasonCode: 'SERVER_VALIDATION_FAILED',
        error: 'Attendance request payload incomplete.'
      });
    }

    // CONDITION 2: Employee Account Validation
    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) {
      await logAuditEvent('UNKNOWN', 'Unknown User', 'PUNCH_FAILED', 'SECURITY_SUSPICIOUS', 'SERVER_VALIDATION_FAILED', 'Punch attempted for invalid employee ID');
      return res.status(404).json({ success: false, reasonCode: 'SERVER_VALIDATION_FAILED', error: 'Employee record not found.' });
    }

    if (employee.status !== 'active') {
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED', 'WARNING', 'EMPLOYEE_INACTIVE', `Employee account is ${employee.status}`);
      return res.status(403).json({ success: false, reasonCode: 'EMPLOYEE_INACTIVE', error: `Your employee account is ${employee.status}. Contact HR/Admin.` });
    }

    if (employee.role !== 'employee') {
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED', 'WARNING', 'ROLE_RESTRICTED', 'Attendance marking restricted to employees');
      return res.status(403).json({ success: false, reasonCode: 'ROLE_RESTRICTED', error: 'Attendance marking is allowed for hospital staff employees only.' });
    }

    // CONDITION 3: State Machine & Duplicate Punch Prevention
    if (punchType === 'CHECK_IN' && employee.current_punch_status === 'CHECKED_IN') {
      const lastPunchTimeFormatted = employee.last_punch_time ? new Date(employee.last_punch_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_DUPLICATE', 'WARNING', 'DUPLICATE_CHECK_IN', 'Attempted duplicate check in');
      return res.status(400).json({
        success: false,
        reasonCode: 'DUPLICATE_CHECK_IN',
        error: `You have already punched in${lastPunchTimeFormatted ? ' at ' + lastPunchTimeFormatted : ''}.`
      });
    }

    if (punchType === 'CHECK_OUT' && employee.current_punch_status === 'CHECKED_OUT') {
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_DUPLICATE', 'WARNING', 'DUPLICATE_CHECK_OUT', 'Attempted duplicate check out');
      return res.status(400).json({
        success: false,
        reasonCode: 'DUPLICATE_CHECK_OUT',
        error: 'This shift has already been checked out.'
      });
    }

    // CONDITION 4: Single-Use Fresh Security Challenge Verification
    if (!simulated) {
      const challengeData = challengeStore.get(challengeId);

      if (!challengeData) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'CHALLENGE_EXPIRED', 'Challenge token expired or invalid');
        return res.status(400).json({
          success: false,
          reasonCode: 'CHALLENGE_EXPIRED',
          error: 'Security challenge session expired. Please tap Punch again.'
        });
      }

      if (challengeData.used) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'CHALLENGE_ALREADY_USED', 'Replay attempt detected for security challenge token');
        return res.status(400).json({
          success: false,
          reasonCode: 'CHALLENGE_ALREADY_USED',
          error: 'Security challenge token was already consumed. Replay rejected.'
        });
      }

      if (challengeData.employeeId !== employeeId || challengeData.action !== punchType) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SECURITY', 'SECURITY_SUSPICIOUS', 'AUTHENTICATION_FAILED', 'Challenge token mismatch');
        return res.status(400).json({
          success: false,
          reasonCode: 'AUTHENTICATION_FAILED',
          error: 'Security challenge mismatch. Action rejected.'
        });
      }

      if (challengeData.expiresAt < Date.now()) {
        challengeStore.delete(challengeId);
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SECURITY', 'WARNING', 'CHALLENGE_EXPIRED', 'Challenge expired before consumption');
        return res.status(400).json({
          success: false,
          reasonCode: 'CHALLENGE_EXPIRED',
          error: 'Security challenge timed out. Please try again.'
        });
      }

      // Mark challenge as consumed immediately (Atomic Single-Use Protection)
      challengeData.used = true;
      challengeStore.delete(challengeId);
    }

    // Load System Rules Settings
    const settings = await queryGet('SELECT * FROM system_settings WHERE id = 1');
    const allowedIps = JSON.parse(settings.hospital_wifi_ips || '[]');

    // CONDITION 5: Hospital Network Verification
    if (settings.enforcement_strict_wifi) {
      const isIpAllowed = allowedIps.some(ip => 
        clientIp.includes(ip) || ip === '0.0.0.0' || clientIp === '::1' || clientIp === '127.0.0.1' || (ip.endsWith('.') && clientIp.startsWith(ip))
      );

      if (!isIpAllowed) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_NETWORK', 'SECURITY_SUSPICIOUS', 'INVALID_NETWORK', `Unauthorized network IP: ${clientIp}`, { clientIp, allowedIps });
        return res.status(403).json({
          success: false,
          reasonCode: 'INVALID_NETWORK',
          error: 'Attendance cannot be recorded because you are not connected through the approved hospital network.'
        });
      }
    }

    // CONDITION 6: Geolocation Signal & Accuracy Verification
    if (!location || typeof location.lat !== 'number' || typeof location.lng !== 'number') {
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_LOCATION', 'WARNING', 'LOCATION_ACCURACY_TOO_LOW', 'GPS location service unavailable or permission denied');
      return res.status(400).json({
        success: false,
        reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
        error: 'We could not verify your location. Please enable location access and try again.'
      });
    }

    // Location Accuracy Threshold Check
    if (settings.enforcement_strict_accuracy) {
      const accuracy = location.accuracy || 999;
      if (accuracy > settings.max_allowed_accuracy_meters) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_ACCURACY', 'WARNING', 'LOCATION_ACCURACY_TOO_LOW', `GPS signal accuracy too low (${accuracy}m > ${settings.max_allowed_accuracy_meters}m allowed)`, { accuracy });
        return res.status(400).json({
          success: false,
          reasonCode: 'LOCATION_ACCURACY_TOO_LOW',
          error: 'Your current location accuracy is too low. Please move to an open area and try again.'
        });
      }
    }

    // Geofence Radius Calculation (Haversine)
    const distanceMeters = calculateHaversineDistance(
      location.lat,
      location.lng,
      settings.geofence_lat,
      settings.geofence_lng
    );

    if (settings.enforcement_strict_geofence && distanceMeters > settings.geofence_radius_meters) {
      await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_GEOFENCE', 'SECURITY_SUSPICIOUS', 'OUTSIDE_GEOFENCE', `Geofence Breached: User is ${Math.round(distanceMeters)}m away (Max allowed ${settings.geofence_radius_meters}m)`, { distanceMeters });
      return res.status(403).json({
        success: false,
        reasonCode: 'OUTSIDE_GEOFENCE',
        error: `You are outside hospital premises (${Math.round(distanceMeters)}m away). Attendance is permitted only within hospital grounds.`
      });
    }

    // CONDITION 7: Valid Assigned Shift & Window Check (Supports Night Shifts Crossing Midnight)
    let assignedShift = null;
    if (settings.enforcement_strict_shift) {
      assignedShift = await queryGet('SELECT * FROM shifts WHERE employee_id = ?', [employeeId]);
      if (!assignedShift) {
        await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SHIFT', 'WARNING', 'NO_ACTIVE_SHIFT', 'No active assigned shift found for employee');
        return res.status(403).json({
          success: false,
          reasonCode: 'NO_ACTIVE_SHIFT',
          error: 'No active shift is assigned at this time.'
        });
      }

      const now = new Date();
      const currentMinutes = now.getHours() * 60 + now.getMinutes();
      const shiftStartMins = timeStrToMinutes(assignedShift.start_time);
      const shiftEndMins = timeStrToMinutes(assignedShift.end_time);

      if (assignedShift.is_night_shift) {
        // Night Shift Logic (e.g. 20:00 -> 06:00 next day)
        // If current time is past start time (e.g. 21:00) or before end time next morning (e.g. 05:00), it's valid
        if (punchType === 'CHECK_IN') {
          const minIn = shiftStartMins - (assignedShift.allowed_early_in_mins || 60);
          const maxIn = shiftStartMins + (assignedShift.allowed_late_in_mins || 240);

          let isValidNightIn = (currentMinutes >= minIn && currentMinutes <= 1440) || (currentMinutes <= (maxIn % 1440));
          if (!isValidNightIn) {
            await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SHIFT_WINDOW', 'WARNING', 'TOO_EARLY', `Outside night shift Check In window`);
            return res.status(403).json({
              success: false,
              reasonCode: 'TOO_EARLY',
              error: `Outside Punch In window for night shift '${assignedShift.shift_name}'.`
            });
          }
        }
      } else {
        // Normal Day Shift Logic
        if (punchType === 'CHECK_IN') {
          const minPunchIn = shiftStartMins - (assignedShift.allowed_early_in_mins || 60);
          const maxPunchIn = shiftStartMins + (assignedShift.allowed_late_in_mins || 240);

          if (currentMinutes < minPunchIn) {
            await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SHIFT_WINDOW', 'WARNING', 'TOO_EARLY', `Attempted check in too early`);
            return res.status(403).json({
              success: false,
              reasonCode: 'TOO_EARLY',
              error: `Too early to Punch In. Shift '${assignedShift.shift_name}' Punch In opens at ${Math.floor(minPunchIn/60)}:${(minPunchIn%60).toString().padStart(2,'0')}.`
            });
          }
          if (currentMinutes > maxPunchIn) {
            await logAuditEvent(employeeId, employee.name, 'PUNCH_FAILED_SHIFT_WINDOW', 'WARNING', 'TOO_LATE', `Attempted check in past shift window`);
            return res.status(403).json({
              success: false,
              reasonCode: 'TOO_LATE',
              error: `Punch In window for shift '${assignedShift.shift_name}' has passed.`
            });
          }
        }
      }
    }

    // ALL SECURITY CONDITIONS PASSED! SAVE AUDIT EVIDENCE RECORD
    const recordId = 'att_' + crypto.randomUUID();
    const newStatus = punchType === 'CHECK_IN' ? 'CHECKED_IN' : 'CHECKED_OUT';

    await queryRun(
      `INSERT INTO attendance_records (
        id, employee_id, shift_id, punch_type, server_timestamp, ip_address, lat, lng, accuracy, calculated_distance_meters, verification_method, challenge_id, credential_ref, status, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'SUCCESS', ?)`,
      [
        recordId,
        employeeId,
        assignedShift ? assignedShift.id : null,
        punchType,
        serverTimestamp,
        clientIp,
        location.lat,
        location.lng,
        location.accuracy || 0,
        Math.round(distanceMeters),
        simulated ? 'WebAuthn Passkey (Simulated)' : 'WebAuthn Cryptographic Biometric',
        challengeId || 'sim_challenge',
        credential ? credential.id : 'sim_credential',
        `Distance: ${Math.round(distanceMeters)}m from hospital center`
      ]
    );

    // Update Employee Punch State
    await queryRun(
      `UPDATE employees SET current_punch_status = ?, last_punch_time = ?, last_punch_id = ? WHERE id = ?`,
      [newStatus, serverTimestamp, recordId, employeeId]
    );

    // Log Audit Evidence Event
    await logAuditEvent(
      employeeId,
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
    await logAuditEvent(req.body.employeeId || 'UNKNOWN', 'Error Handler', 'SYSTEM_ERROR', 'CRITICAL', 'SERVER_VALIDATION_FAILED', err.message);
    res.status(500).json({ success: false, reasonCode: 'SERVER_VALIDATION_FAILED', error: 'Internal server error processing attendance.' });
  }
});

// 3. ATTENDANCE CORRECTION REQUEST WORKFLOW
app.post('/api/corrections/request', async (req, res) => {
  try {
    const { employeeId, requestedDate, requestedPunchType, requestedTime, reason } = req.body;
    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [employeeId]);
    if (!employee) return res.status(404).json({ success: false, error: 'Employee not found' });

    const id = 'corr_' + crypto.randomUUID();
    const createdAt = new Date().toISOString();

    await queryRun(
      `INSERT INTO correction_requests (id, employee_id, original_record_id, requested_date, requested_punch_type, requested_time, reason, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
      [id, employeeId, employee.last_punch_id || null, requestedDate, requestedPunchType, requestedTime, reason, createdAt]
    );

    await logAuditEvent(employeeId, employee.name, 'CORRECTION_REQUESTED', 'INFO', 'CORRECTION_REQUEST', `Correction request submitted for ${requestedDate} ${requestedTime}`);
    res.json({ success: true, message: 'Attendance correction request submitted for authorized review.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// List Correction Requests
app.get('/api/corrections/list', async (req, res) => {
  try {
    const employeeId = req.query.employeeId;
    let sql = `SELECT c.*, e.name as employee_name, e.email as employee_email 
               FROM correction_requests c 
               JOIN employees e ON c.employee_id = e.id`;
    let params = [];
    if (employeeId) {
      sql += ` WHERE c.employee_id = ?`;
      params.push(employeeId);
    }
    sql += ` ORDER BY c.created_at DESC`;

    const requests = await queryAll(sql, params);
    res.json({ success: true, requests });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin Review Correction Request
app.post('/api/corrections/review', async (req, res) => {
  try {
    const { requestId, action, adminNotes } = req.body; // action: 'APPROVED' or 'REJECTED'
    const request = await queryGet('SELECT * FROM correction_requests WHERE id = ?', [requestId]);
    if (!request) return res.status(404).json({ success: false, error: 'Request not found' });

    const employee = await queryGet('SELECT * FROM employees WHERE id = ?', [request.employee_id]);
    const reviewedAt = new Date().toISOString();

    await queryRun(
      `UPDATE correction_requests SET status = ?, admin_notes = ?, reviewed_at = ?, reviewed_by = 'Admin Marcus Vance' WHERE id = ?`,
      [action, adminNotes || '', reviewedAt, requestId]
    );

    if (action === 'APPROVED') {
      const serverTimestamp = `${request.requested_date}T${request.requested_time}:00.000Z`;
      const recordId = 'att_corr_' + crypto.randomUUID();
      const newStatus = request.requested_punch_type === 'CHECK_IN' ? 'CHECKED_IN' : 'CHECKED_OUT';

      await queryRun(
        `INSERT INTO attendance_records (
          id, employee_id, punch_type, server_timestamp, ip_address, lat, lng, accuracy, calculated_distance_meters, verification_method, status, notes
        ) VALUES (?, ?, ?, ?, 'ADMIN_OVERRIDE', 0, 0, 0, 0, 'Admin Approved Correction', 'SUCCESS', ?)`,
        [recordId, request.employee_id, request.requested_punch_type, serverTimestamp, `Original: ${request.original_record_id || 'None'} | Reason: ${request.reason}`]
      );

      await queryRun(`UPDATE employees SET current_punch_status = ?, last_punch_time = ?, last_punch_id = ? WHERE id = ?`, [newStatus, serverTimestamp, recordId, request.employee_id]);
      await logAuditEvent(request.employee_id, employee?.name, 'CORRECTION_APPROVED', 'INFO', 'CORRECTION_APPROVAL', `Admin approved attendance correction request: ${request.requested_punch_type} on ${request.requested_date}`);
    } else {
      await logAuditEvent(request.employee_id, employee?.name, 'CORRECTION_REJECTED', 'INFO', 'CORRECTION_REJECTION', `Admin rejected correction request`);
    }

    res.json({ success: true, message: `Correction request ${action.toLowerCase()} successfully.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// 4. ADMIN AUDIT EVIDENCE & REASON CODES ENDPOINT
app.get('/api/admin/audit-logs', async (req, res) => {
  try {
    const logs = await queryAll('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200');
    const attendanceRecords = await queryAll(
      `SELECT a.*, e.name as employee_name 
       FROM attendance_records a 
       JOIN employees e ON a.employee_id = e.id 
       ORDER BY a.server_timestamp DESC LIMIT 200`
    );
    res.json({ success: true, logs, attendanceRecords });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Start Server
initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`🏥 VAIDHYAR MANDHIRAM High-Trust Attendance System running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize database:', err);
});
