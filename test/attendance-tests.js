const http = require('http');
const app = require('../src/app');
const { initDb, queryRun } = require('../src/db');

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

async function runTestSuite() {
  console.log('🧪 Starting High-Trust Attendance Security & Vercel Verification Suite...\n');

  await initDb();
  await queryRun('DELETE FROM shift_instances');
  await queryRun('DELETE FROM challenges');
  await queryRun('DELETE FROM attendance_records');
  await queryRun('DELETE FROM attendance_attempts');
  await queryRun('DELETE FROM sessions');
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const port = server.address().port;
      BASE_URL = `http://localhost:${port}`;
      console.log(`Test server running on ${BASE_URL}\n`);
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
  await testCase('1. Initial server system data & settings loading', async () => {
    const res = await makeRequest('/api/initial-data');
    if (res.status !== 200 || !res.body.success) throw new Error('Failed to load initial server settings');
  });

  // 2. Reject Unauthenticated Requests
  await testCase('2. Reject unauthenticated request without session token', async () => {
    const res = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    if (res.status !== 401 || res.body.reasonCode !== 'UNAUTHENTICATED') {
      throw new Error(`Expected 401 UNAUTHENTICATED but got status ${res.status}: ${JSON.stringify(res.body)}`);
    }
  });

  // 3. Employee Session Login
  await testCase('3. Authenticated employee session login', async () => {
    const res = await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_1' });
    if (res.status !== 200 || !res.body.sessionId) throw new Error('Employee login failed');
  });

  // 4. Generate Single-Use Challenge Token
  let challengeId = null;
  await testCase('4. Generate single-use security challenge token', async () => {
    const res = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    if (res.status !== 200 || !res.body.challengeId) throw new Error('Failed to generate challenge token');
    challengeId = res.body.challengeId;
  });

  // 5. Valid Punch In
  await testCase('5. Valid Punch In with full security compliance', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: challengeId,
      simulated: true
    });
    if (res.status !== 200 || !res.body.success) throw new Error(res.body.error || 'Valid Punch In failed');
  });

  // 6. Duplicate Punch In Prevention
  await testCase('6. Duplicate Punch In prevention (DUPLICATE_CHECK_IN)', async () => {
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.body.reasonCode !== 'DUPLICATE_CHECK_IN') throw new Error(`Expected DUPLICATE_CHECK_IN but got ${res.body.reasonCode}`);
  });

  // 7. Single-Use Challenge Replay Prevention
  await testCase('7. Single-use challenge replay prevention (CHALLENGE_ALREADY_USED)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_OUT',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: challengeId, // Reusing previously consumed challenge
      simulated: true
    });
    if (res.body.reasonCode !== 'CHALLENGE_ALREADY_USED') {
      throw new Error(`Expected CHALLENGE_ALREADY_USED but got: ${res.body.reasonCode}`);
    }
  });

  // 8. Expired Challenge Rejection
  await testCase('8. Expired challenge rejection (CHALLENGE_EXPIRED)', async () => {
    const expiredId = 'ch_expired_test';
    await queryRun('DELETE FROM challenges WHERE id = ?', [expiredId]);
    await queryRun(
      `INSERT INTO challenges (id, employee_id, action, challenge, created_at, expires_at, used)
       VALUES (?, 'emp_1', 'CHECK_OUT', 'nonce_expired', ?, ?, 0)`,
      [expiredId, new Date().toISOString(), Date.now() - 10000]
    );

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_OUT',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: expiredId,
      simulated: true
    });
    if (res.body.reasonCode !== 'CHALLENGE_EXPIRED') throw new Error(`Expected CHALLENGE_EXPIRED but got ${res.body.reasonCode}`);
  });

  // 9. Unauthorized Hospital Network Rejection (Enforce Mode)
  await testCase('9. Unauthorized hospital network IP rejection in enforce mode (INVALID_NETWORK)', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_admin' });
    await makeRequest('/api/admin/settings', 'POST', {
      hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
      geofence_lat: 8.752625,
      geofence_lng: 76.938625,
      geofence_radius_meters: 120,
      max_allowed_accuracy_meters: 60,
      hospital_wifi_ips: '["103.15.22.4"]',
      network_enforcement_mode: 'enforce'
    });

    const emp2Login = await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_2' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '198.51.100.99', // Unauthorized Public IP
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.body.reasonCode !== 'INVALID_NETWORK') {
      throw new Error(`Expected INVALID_NETWORK but got ${res.body.reasonCode}`);
    }

    // Revert network enforcement back to observe for remaining tests
    await makeRequest('/api/admin/settings', 'POST', {
      hospital_name: 'VAIDHYAR MANDHIRAM, Kallara',
      geofence_lat: 8.752625,
      geofence_lng: 76.938625,
      geofence_radius_meters: 120,
      max_allowed_accuracy_meters: 60,
      hospital_wifi_ips: '["127.0.0.1", "::1"]',
      network_enforcement_mode: 'observe'
    });
  });

  // 10. Outside Geofence Rejection
  await testCase('10. Outside hospital geofence rejection (OUTSIDE_GEOFENCE)', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_2' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.790000, lng: 76.980000, accuracy: 15 }, // ~5km away from Kallara
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.body.reasonCode !== 'OUTSIDE_GEOFENCE') throw new Error(`Expected OUTSIDE_GEOFENCE but got ${res.body.reasonCode}`);
  });

  // 11. Low Location Accuracy Rejection
  await testCase('11. Low location accuracy rejection (LOCATION_ACCURACY_TOO_LOW)', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_2' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 450 }, // ±450m (max allowed is 300m)
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.body.reasonCode !== 'LOCATION_ACCURACY_TOO_LOW') throw new Error(`Expected LOCATION_ACCURACY_TOO_LOW but got ${res.body.reasonCode}`);
  });

  // 12. Valid Punch Out
  await testCase('12. Valid Punch Out re-verification', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_1' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_OUT' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_OUT',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.status !== 200 || !res.body.success) throw new Error(res.body.error || 'Punch Out failed');
  });

  // 13. Duplicate Punch Out Prevention
  await testCase('13. Duplicate Punch Out prevention (DUPLICATE_CHECK_OUT)', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_1' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_OUT' });

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_OUT',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true
    });
    if (res.body.reasonCode !== 'DUPLICATE_CHECK_OUT') throw new Error(`Expected DUPLICATE_CHECK_OUT but got ${res.body.reasonCode}`);
  });

  // 14. Attendance Correction Request Submission
  await testCase('14. Attendance correction request submission', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_1' });
    const res = await makeRequest('/api/corrections/request', 'POST', {
      requestedDate: '2026-08-18',
      requestedPunchType: 'CHECK_IN',
      requestedTime: '07:05',
      reason: 'GPS connection loss inside basement radiology ward'
    });
    if (!res.body.success) throw new Error(res.body.error);
  });

  // 15. Admin Correction Review & Approval Workflow
  await testCase('15. Admin correction approval workflow & audit trail', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_admin' });
    const listRes = await makeRequest('/api/corrections/list');
    const reqItem = listRes.body.requests.find(r => r.employee_id === 'emp_1');
    if (!reqItem) throw new Error('Correction request item not found');

    const reviewRes = await makeRequest('/api/corrections/review', 'POST', {
      requestId: reqItem.id,
      action: 'APPROVED',
      adminNotes: 'Verified with department head shift supervisor'
    });
    if (!reviewRes.body.success) throw new Error(reviewRes.body.error);
  });

  // 16. Attendance Attempt Logs & Reason Codes Retrieval
  await testCase('16. Comprehensive Audit Evidence & Attendance Attempt logs retrieval', async () => {
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_admin' });
    const res = await makeRequest('/api/admin/audit-logs');
    if (!res.body.logs || res.body.logs.length === 0) throw new Error('No audit logs retrieved');
    if (!res.body.attempts || res.body.attempts.length === 0) throw new Error('No attendance attempts retrieved');
  });

  // 17. Server Timestamp Generation Verification
  await testCase('17. Server timestamp generation verification (Client time ignored)', async () => {
    await queryRun('DELETE FROM shift_instances WHERE employee_id = ?', ['emp_2']);
    await makeRequest('/api/auth/login', 'POST', { employeeId: 'emp_2' });
    const chRes = await makeRequest('/api/attendance/challenge', 'POST', { action: 'CHECK_IN' });
    const fakeClientTime = '2000-01-01T00:00:00.000Z';

    const res = await makeRequest('/api/attendance/punch', 'POST', {
      punchType: 'CHECK_IN',
      location: { lat: 8.752625, lng: 76.938625, accuracy: 15 },
      simulated_ip: '127.0.0.1',
      challengeId: chRes.body.challengeId,
      simulated: true,
      clientTimestamp: fakeClientTime // Attempted client time manipulation
    });
    if (!res.body.success) throw new Error('Punch failed');
    if (res.body.serverTimestamp.startsWith('2000-01-01')) {
      throw new Error('Server trusted client time instead of generating server time!');
    }
  });

  server.close();

  console.log(`\n==================================================`);
  console.log(`🎉 TEST SUITE COMPLETE: ${passed} Passed, ${failed} Failed`);
  console.log(`==================================================\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTestSuite().catch(err => {
  console.error('Test suite runner crashed:', err);
  if (server) server.close();
  process.exit(1);
});
