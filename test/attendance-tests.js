const http = require('http');
const app = require('../src/app');
const { initDb, queryRun, hashPassword } = require('../src/db');

let server = null;
let BASE_URL = '';
let sessionCookie = '';

function makeRequest(path, method = 'GET', body = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE_URL + path);
    const headers = {
      'Content-Type': 'application/json',
      ...extraHeaders
    };
    if (sessionCookie) {
      headers['Cookie'] = sessionCookie;
    }

    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers
    };

    const req = http.request(options, (res) => {
      let data = '';
      if (res.headers['set-cookie']) {
        const cookieHeader = res.headers['set-cookie'][0];
        sessionCookie = cookieHeader.split(';')[0];
      }
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch (err) {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runEnterpriseTestSuite() {
  console.log('🧪 Starting Enterprise-Grade Hospital Attendance Validation Test Suite...\n');

  await initDb();
  await queryRun('DELETE FROM shift_instances');
  await queryRun('DELETE FROM challenges');
  await queryRun('DELETE FROM attendance_records');
  await queryRun('DELETE FROM attendance_attempts');
  await queryRun('DELETE FROM webauthn_credentials');
  await queryRun('DELETE FROM sessions');

  // Register mock WebAuthn credential for emp_1 & emp_2 for testing assertions
  const mockCredId = 'test_cred_id_rahul';
  const mockPubKey = 'test_pub_key_rahul';
  await queryRun(
    `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
     VALUES ('cred_1', 'emp_1', ?, ?, 0, ?)`,
    [mockCredId, mockPubKey, new Date().toISOString()]
  );

  const mockCredId2 = 'test_cred_id_ananya';
  const mockPubKey2 = 'test_pub_key_ananya';
  await queryRun(
    `INSERT INTO webauthn_credentials (id, employee_id, credential_id, public_key, counter, created_at)
     VALUES ('cred_2', 'emp_2', ?, ?, 0, ?)`,
    [mockCredId2, mockPubKey2, new Date().toISOString()]
  );

  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      BASE_URL = `http://localhost:${port}`;
      console.log(`Enterprise Test Server running on ${BASE_URL}\n`);
      resolve();
    });
  });

  let passed = 0;
  let failed = 0;

  async function testCase(name, fn) {
    try {
      await fn();
      console.log(`  ✅ PASSED: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ FAILED: ${name}\n     Error: ${err.message}`);
      failed++;
    }
  }

  // 1. Initial System Data Loading
  await testCase('1. Load initial server system settings & egress IP', async () => {
    const res = await makeRequest('/api/initial-data');
    if (res.status !== 200 || !res.body.success) throw new Error('Failed to load initial server settings');
  });

  // 2. Reject Unauthenticated Requests
  await testCase('2. Reject unauthenticated request without session token', async () => {
    sessionCookie = '';
    const res = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    if (res.status !== 401 || res.body.reasonCode !== 'UNAUTHENTICATED') {
      throw new Error(`Expected 401 UNAUTHENTICATED but got status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  });

  // 3. Reject Passwordless Employee ID Login Attempts
  await testCase('3. Reject passwordless employee ID login attempts', async () => {
    const res = await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_1' });
    if (res.status !== 400 || res.body.reasonCode !== 'AUTHENTICATION_FAILED') {
      throw new Error(`Expected 400 AUTHENTICATION_FAILED but got status ${res.status}`);
    }
  });

  // 4. Reject Wrong Password Login
  await testCase('4. Reject wrong password login', async () => {
    const res = await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'WrongPassword999!' });
    if (res.status !== 401 || res.body.reasonCode !== 'AUTHENTICATION_FAILED') {
      throw new Error(`Expected 401 AUTHENTICATION_FAILED but got status ${res.status}`);
    }
  });

  // 5. Valid Employee Password Login
  await testCase('5. Valid employee login with salted PBKDF2 password', async () => {
    const res = await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    if (res.status !== 200 || !res.body.sessionId) throw new Error('Employee password login failed');
  });

  // 6. Reject x-employee-id Header Impersonation
  await testCase('6. Reject x-employee-id header impersonation attack', async () => {
    sessionCookie = '';
    const res = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' }, { 'x-employee-id': 'emp_1' });
    if (res.status !== 401 || res.body.reasonCode !== 'UNAUTHENTICATED') {
      throw new Error(`Expected 401 UNAUTHENTICATED for x-employee-id header bypass attempt`);
    }
    // Re-authenticate
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
  });

  // 7. Generate Single-Use Security Challenge Token
  let challengeId = null;
  await testCase('7. Generate single-use security challenge token', async () => {
    const res = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    if (res.status !== 200 || !res.body.challengeId) throw new Error('Failed to generate challenge token');
    challengeId = res.body.challengeId;
  });

  // 8. Reject Punch Without WebAuthn Assertion
  await testCase('8. Reject punch attempt missing WebAuthn assertion', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: challengeId
    });
    if (res.body.reasonCode !== 'AUTHENTICATION_FAILED') {
      throw new Error(`Expected AUTHENTICATION_FAILED but got ${res.body.reasonCode}`);
    }
  });

  // 9. Reject Punch Without Fresh GPS Location
  await testCase('9. Reject punch attempt missing fresh GPS location evidence', async () => {
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'LOCATION_REQUIRED') {
      throw new Error(`Expected LOCATION_REQUIRED but got ${res.body.reasonCode}`);
    }
  });

  // 10. Reject Punch Outside Geofence
  await testCase('10. Reject punch outside hospital geofence (OUTSIDE_GEOFENCE)', async () => {
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.850000, lng: 76.990000, accuracy: 15 }, // ~12km away
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'OUTSIDE_GEOFENCE') {
      throw new Error(`Expected OUTSIDE_GEOFENCE but got ${res.body.reasonCode}`);
    }
  });

  // 11. Reject Low GPS Accuracy
  await testCase('11. Reject low location accuracy (LOCATION_ACCURACY_TOO_LOW)', async () => {
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 450 }, // ±450m (max 300m)
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'LOCATION_ACCURACY_TOO_LOW') {
      throw new Error(`Expected LOCATION_ACCURACY_TOO_LOW but got ${res.body.reasonCode}`);
    }
  });

  // 12. Reject Single-Use Challenge Replay Attack
  await testCase('12. Single-use challenge replay prevention (CHALLENGE_ALREADY_USED)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: challengeId, // Previously consumed in test case 8
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'CHALLENGE_ALREADY_USED') {
      throw new Error(`Expected CHALLENGE_ALREADY_USED but got: ${res.body.reasonCode}`);
    }
  });

  // 13. Unauthorized Network IP Rejection in Enforce Mode
  await testCase('13. Unauthorized network IP rejection in enforce mode (INVALID_NETWORK)', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'admin@vaidhyar.org', password: 'AdminPassword123!' });
    await makeRequest('/api/admin/settings', 'POST', {
      hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
      geofence_lat: 8.752625,
      geofence_lng: 76.938625,
      geofence_radius_meters: 500,
      max_allowed_accuracy_meters: 300,
      hospital_wifi_ips: '["103.15.22.4"]',
      network_enforcement_mode: 'enforce'
    });

    await makeRequest('/api/auth/login', 'POST', { email: 'ananya.iyer@vaidhyar.org', password: 'Password123!' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId2, response: { clientDataJSON: 'xyz' } }
    }, { 'x-forwarded-for': '198.51.100.99' }); // Unauthorized Public Egress IP

    if (res.body.reasonCode !== 'INVALID_NETWORK') {
      throw new Error(`Expected INVALID_NETWORK but got ${res.body.reasonCode}`);
    }

    // Revert network setting
    await makeRequest('/api/auth/login', 'POST', { email: 'admin@vaidhyar.org', password: 'AdminPassword123!' });
    await makeRequest('/api/admin/settings', 'POST', {
      hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
      geofence_lat: 8.752625,
      geofence_lng: 76.938625,
      geofence_radius_meters: 500,
      max_allowed_accuracy_meters: 300,
      hospital_wifi_ips: '["127.0.0.1", "::1"]',
      network_enforcement_mode: 'observe'
    });
  });

  // 14. Admin Privilege Escalation Protection
  await testCase('14. Prevent non-admin employee from accessing administrative audit logs', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    const res = await makeRequest('/api/admin/audit-logs');
    if (res.status !== 403 || res.body.reasonCode !== 'ROLE_RESTRICTED') {
      throw new Error(`Expected 403 ROLE_RESTRICTED but got status ${res.status}`);
    }
  });

  // 15. Server Timestamp Generation Verification
  await testCase('15. Official server timestamp verification (Client time ignored)', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const fakeClientTime = '1999-12-31T23:59:59.000Z';

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } },
      clientTimestamp: fakeClientTime
    });

    if (res.body.serverTimestamp && res.body.serverTimestamp.startsWith('1999')) {
      throw new Error('Server trusted client timestamp instead of authoritative server time!');
    }
  });

  // 16. Duplicate Punch In Prevention
  await testCase('16. Duplicate Punch In prevention (DUPLICATE_CHECK_IN)', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'DUPLICATE_CHECK_IN') {
      throw new Error(`Expected DUPLICATE_CHECK_IN but got ${res.body.reasonCode}`);
    }
  });

  // 17. Valid Punch Out
  await testCase('17. Valid Punch Out re-verification', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_OUT' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_OUT',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.status !== 200 || !res.body.success) {
      throw new Error(res.body.error || 'Valid Punch Out failed');
    }
  });

  // 18. Terminal State Machine Enforcement (Re-check in after checkout rejected)
  await testCase('18. Re-check in after completed shift terminal state rejection', async () => {
    await makeRequest('/api/auth/login', 'POST', { email: 'rahul.sharma@vaidhyar.org', password: 'Password123!' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      challengeId: chRes.body.challengeId,
      credential: { id: mockCredId, response: { clientDataJSON: 'xyz' } }
    });
    if (res.body.reasonCode !== 'SHIFT_ALREADY_COMPLETED') {
      throw new Error(`Expected SHIFT_ALREADY_COMPLETED but got ${res.body.reasonCode}`);
    }
  });

  server.close();

  console.log(`\n==================================================`);
  console.log(`🎉 ENTERPRISE TEST SUITE COMPLETE: ${passed} Passed, ${failed} Failed`);
  console.log(`==================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runEnterpriseTestSuite().catch(err => {
  console.error('Test suite runner crashed:', err);
  if (server) server.close();
  process.exit(1);
});
