const http = require('http');

const BASE_URL = 'http://localhost:3000';

function makeRequest(path, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE_URL + path);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        'Content-Type': 'application/json'
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
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
  console.log('🧪 Starting High-Trust Attendance Automated Security Test Suite...\n');
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

  // TEST 1: Initial System Data Loading
  await testCase('1. Server initial data & system settings loading', async () => {
    const res = await makeRequest('/api/initial-data');
    if (res.status !== 200 || !res.body.success) throw new Error('Failed to load initial server settings');
  });

  // TEST 2: Single-Use Security Challenge Generation
  let challengeId = null;
  await testCase('2. Generate single-use security challenge token', async () => {
    const res = await makeRequest('/api/attendance/challenge', 'POST', { employeeId: 'emp_1', action: 'CHECK_IN' });
    if (res.status !== 200 || !res.body.challengeId) throw new Error('Failed to generate challenge token');
    challengeId = res.body.challengeId;
  });

  // TEST 3: Valid Punch In
  await testCase('3. Valid Punch In with full security compliance', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_1',
      punchType: 'CHECK_IN',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '192.168.86.2',
      challengeId: challengeId,
      simulated: true
    });
    if (res.status !== 200 || !res.body.success) throw new Error(res.body.error || 'Valid Punch In failed');
  });

  // TEST 4: Duplicate Punch In Prevention
  await testCase('4. Duplicate Punch In prevention (DUPLICATE_CHECK_IN)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_1',
      punchType: 'CHECK_IN',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '192.168.86.2',
      simulated: true
    });
    if (res.body.reasonCode !== 'DUPLICATE_CHECK_IN') throw new Error(`Expected DUPLICATE_CHECK_IN but got ${res.body.reasonCode}`);
  });

  // TEST 5: Reused Challenge Protection
  await testCase('5. Single-use challenge replay prevention (CHALLENGE_ALREADY_USED)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_1',
      punchType: 'CHECK_OUT',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '192.168.86.2',
      challengeId: challengeId,
      simulated: false
    });
    if (res.body.reasonCode !== 'CHALLENGE_EXPIRED' && res.body.reasonCode !== 'CHALLENGE_ALREADY_USED' && res.body.reasonCode !== 'AUTHENTICATION_FAILED') {
      throw new Error(`Expected challenge reuse rejection but got: ${res.body.reasonCode}`);
    }
  });

  // TEST 6: Invalid Hospital Network Rejection
  await testCase('6. Invalid hospital network IP rejection (INVALID_NETWORK)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_2',
      punchType: 'CHECK_IN',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '198.51.100.99', // Unauthorized IP
      simulated: true
    });
    if (res.body.reasonCode !== 'INVALID_NETWORK') throw new Error(`Expected INVALID_NETWORK but got ${res.body.reasonCode}`);
  });

  // TEST 7: Outside Geofence Rejection
  await testCase('7. Outside hospital geofence rejection (OUTSIDE_GEOFENCE)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_2',
      punchType: 'CHECK_IN',
      location: { lat: 8.790000, lng: 76.980000, accuracy: 15 }, // ~5km away from Kallara
      simulated_ip: '192.168.86.2',
      simulated: true
    });
    if (res.body.reasonCode !== 'OUTSIDE_GEOFENCE') throw new Error(`Expected OUTSIDE_GEOFENCE but got ${res.body.reasonCode}`);
  });

  // TEST 8: Low Location Accuracy Rejection
  await testCase('8. Low location accuracy rejection (LOCATION_ACCURACY_TOO_LOW)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_2',
      punchType: 'CHECK_IN',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 250 }, // ±250m accuracy (threshold is 200m)
      simulated_ip: '192.168.86.2',
      simulated: true
    });
    if (res.body.reasonCode !== 'LOCATION_ACCURACY_TOO_LOW') throw new Error(`Expected LOCATION_ACCURACY_TOO_LOW but got ${res.body.reasonCode}`);
  });

  // TEST 9: Valid Punch Out
  await testCase('9. Valid Punch Out re-verification', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_1',
      punchType: 'CHECK_OUT',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '192.168.86.2',
      simulated: true
    });
    if (res.status !== 200 || !res.body.success) throw new Error(res.body.error || 'Punch Out failed');
  });

  // TEST 10: Duplicate Punch Out Prevention
  await testCase('10. Duplicate Punch Out prevention (DUPLICATE_CHECK_OUT)', async () => {
    const res = await makeRequest('/api/attendance/punch', 'POST', {
      employeeId: 'emp_1',
      punchType: 'CHECK_OUT',
      location: { lat: 8.750104, lng: 76.938646, accuracy: 15 },
      simulated_ip: '192.168.86.2',
      simulated: true
    });
    if (res.body.reasonCode !== 'DUPLICATE_CHECK_OUT') throw new Error(`Expected DUPLICATE_CHECK_OUT but got ${res.body.reasonCode}`);
  });

  // TEST 11: Attendance Correction Request Submission
  let corrId = null;
  await testCase('11. Attendance correction request submission', async () => {
    const res = await makeRequest('/api/corrections/request', 'POST', {
      employeeId: 'emp_1',
      requestedDate: '2026-08-18',
      requestedPunchType: 'CHECK_IN',
      requestedTime: '07:05',
      reason: 'GPS connection loss inside basement radiology ward'
    });
    if (!res.body.success) throw new Error(res.body.error);
  });

  // TEST 12: Admin Correction Review & Approval
  await testCase('12. Admin correction approval workflow & audit trail', async () => {
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

  // TEST 13: Audit Evidence & Security Logs Listing
  await testCase('13. Comprehensive Audit Evidence & Reason Codes retrieval', async () => {
    const res = await makeRequest('/api/admin/audit-logs');
    if (!res.body.logs || res.body.logs.length === 0) throw new Error('No audit evidence logs retrieved');
  });

  console.log(`\n==================================================`);
  console.log(`🎉 TEST SUITE COMPLETE: ${passed} Passed, ${failed} Failed`);
  console.log(`==================================================\n`);
}

runTestSuite().catch(err => console.error('Test suite runner crashed:', err));
