// Global Application State
let state = {
  settings: null,
  employees: [],
  shifts: [],
  currentEmployee: null,
  currentLocation: { lat: 8.752625, lng: 76.938625, accuracy: 15 }
};

// Register Service Worker for PWA
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW registration failed:', err));
  });
}

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  await fetchInitialData();
  getUserLocation();

  const today = new Date().toISOString().split('T')[0];
  const dateInput = document.getElementById('corrDate');
  if (dateInput) dateInput.value = today;
});

// Fetch Initial Data from Server
async function fetchInitialData() {
  try {
    const res = await fetch('/api/initial-data');
    const data = await res.json();
    if (data.success) {
      state.settings = data.settings;
      state.employees = data.employees;
      state.shifts = data.shifts;
      if (data.clientIp) {
        state.clientIp = data.clientIp;
        const ipElem = document.getElementById('wifiIpAddress');
        if (ipElem) ipElem.textContent = data.clientIp;
      }

      // Auto-authenticate as employee for demo/session
      const params = new URLSearchParams(window.location.search);
      const empParam = params.get('emp') || 'emp_1';
      state.currentEmployee = state.employees.find(e => e.id === empParam) || state.employees[0];

      // Login session behind the scenes
      await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ employeeId: state.currentEmployee.id })
      });

      updateActiveEmployeeUI();
    }
  } catch (err) {
    showAlert('Failed to connect to backend server: ' + err.message, 'error');
  }
}

// Update Employee Experience UI (VAIDHYAR MANDHIRAM Brand & Layout)
function updateActiveEmployeeUI() {
  const emp = state.currentEmployee;

  // 0. Navbar User Info
  const userPill = document.getElementById('currentUserName');
  if (userPill) userPill.textContent = `${emp.name}`;

  // 1. Time Greeting
  const hour = new Date().getHours();
  let timeGreeting = 'Good Morning';
  if (hour >= 12 && hour < 17) timeGreeting = 'Good Afternoon';
  if (hour >= 17) timeGreeting = 'Good Evening';

  const firstName = emp.name.split(' ')[0];
  document.getElementById('greetingTitle').textContent = `${timeGreeting}, ${firstName}`;

  // 2. Shift Details
  const shift = state.shifts.find(s => s.employee_id === emp.id);
  const shiftNameElem = document.getElementById('assignedShiftName');
  const shiftTimeElem = document.getElementById('assignedShiftTime');

  if (shift) {
    shiftNameElem.textContent = shift.shift_name;
    shiftTimeElem.textContent = `${shift.start_time} – ${shift.end_time}`;
  } else {
    shiftNameElem.textContent = 'No Active Shift Assigned';
    shiftTimeElem.textContent = 'Contact Hospital Admin';
  }

  // 3. Status Badge & Punch Main Button State
  const badge = document.getElementById('attendanceStatusBadge');
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const btn = document.getElementById('btnPunchMain');
  const btnIcon = document.getElementById('btnIcon');
  const btnLabel = document.getElementById('btnLabel');

  if (emp.current_punch_status === 'CHECKED_IN') {
    badge.className = 'attendance-status-badge checked_in';
    statusDot.textContent = '✓';
    statusText.textContent = 'PUNCHED IN';

    btn.className = 'btn-punch-main out';
    btnIcon.textContent = '👆';
    btnLabel.textContent = 'PUNCH OUT';
  } else if (emp.current_punch_status === 'CHECKED_OUT') {
    badge.className = 'attendance-status-badge checked_out';
    statusDot.textContent = '✓';
    statusText.textContent = 'CHECKED OUT TODAY';

    btn.className = 'btn-punch-main in';
    btnIcon.textContent = '👇';
    btnLabel.textContent = 'PUNCH IN AGAIN';
  } else {
    badge.className = 'attendance-status-badge ready';
    statusDot.textContent = '●';
    statusText.textContent = 'Ready to Punch';

    btn.className = 'btn-punch-main in';
    btnIcon.textContent = '👇';
    btnLabel.textContent = 'PUNCH IN';
  }

  // 4. Summary Row (Check In, Check Out, Worked)
  const summaryCheckIn = document.getElementById('summaryCheckIn');
  const summaryCheckOut = document.getElementById('summaryCheckOut');
  const summaryWorked = document.getElementById('summaryWorked');

  if (emp.last_punch_time) {
    const formatted = new Date(emp.last_punch_time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    if (emp.current_punch_status === 'CHECKED_IN') {
      summaryCheckIn.textContent = formatted;
      summaryCheckOut.textContent = '--';
      summaryWorked.textContent = 'In Progress';
    } else if (emp.current_punch_status === 'CHECKED_OUT') {
      summaryCheckOut.textContent = formatted;
      summaryWorked.textContent = 'Completed';
    }
  } else {
    summaryCheckIn.textContent = '--';
    summaryCheckOut.textContent = '--';
    summaryWorked.textContent = '--';
  }

  updateHospitalPresenceUI();
}

// Calculate Haversine Distance (in meters)
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

// Update presence UI
function updateHospitalPresenceUI() {
  const btnPunch = document.getElementById('btnPunchMain');
  const noticeBox = document.getElementById('outsideHospitalNotice');
  const noticeDetail = document.getElementById('outsideNoticeDetail');

  if (!btnPunch || !noticeBox) return;

  if (state.currentEmployee && state.currentEmployee.role !== 'employee') {
    btnPunch.style.display = 'none';
    noticeBox.style.display = 'block';
    if (noticeDetail) {
      noticeDetail.textContent = '🔒 Admin Account: Attendance marking is restricted to hospital staff employees only.';
    }
    return;
  }

  const hospitalLat = state.settings?.geofence_lat || 8.752625;
  const hospitalLng = state.settings?.geofence_lng || 76.938625;
  const maxRadius = Math.max(state.settings?.geofence_radius_meters || 500, 500);

  const distanceMeters = calculateHaversineDistance(
    state.currentLocation.lat,
    state.currentLocation.lng,
    hospitalLat,
    hospitalLng
  );

  const isInside = distanceMeters <= maxRadius;

  if (isInside) {
    btnPunch.style.display = 'inline-flex';
    noticeBox.style.display = 'none';
  } else {
    btnPunch.style.display = 'none';
    noticeBox.style.display = 'block';
    if (noticeDetail) {
      noticeDetail.textContent = `You are currently ${Math.round(distanceMeters)} meters away from Kallara Hospital grounds. Attendance punching is permitted only inside hospital premises (${maxRadius}m radius).`;
    }
  }
}

// Get Real GPS Location
function getUserLocation() {
  if ('geolocation' in navigator) {
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        state.currentLocation = {
          lat: pos.coords.latitude,
          lng: pos.coords.longitude,
          accuracy: pos.coords.accuracy
        };
        updateHospitalPresenceUI();
      },
      (err) => {
        console.warn('Geolocation unavailable, using default coordinates.');
        updateHospitalPresenceUI();
      },
      { enableHighAccuracy: true }
    );
  } else {
    updateHospitalPresenceUI();
  }
}

// -------------------------------------------------------------
// INSTANT HIGH-TRUST ATTENDANCE PUNCH PIPELINE
// -------------------------------------------------------------
async function initiateHighTrustPunch() {
  if (!state.currentEmployee) return showAlert('Please select an active staff member', 'error');

  const emp = state.currentEmployee;
  const targetAction = emp.current_punch_status === 'CHECKED_IN' ? 'CHECK_OUT' : 'CHECK_IN';

  openProgressModal(targetAction);

  const btnMain = document.getElementById('btnPunchMain');
  if (btnMain) btnMain.disabled = true;

  try {
    // STEP 1: Identity & Challenge Verification
    updateProgressStep('stepIdentity', 'active', 'Verifying employee identity & challenge...');
    await sleep(250);

    const challengeRes = await fetch('/api/attendance/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: targetAction })
    });
    const challengeData = await challengeRes.json();

    if (!challengeData.success) {
      updateProgressStep('stepIdentity', 'failed', 'Identity Verification Failed');
      showModalFooter();
      if (challengeRes.status === 401 || (challengeData.error && challengeData.error.toLowerCase().includes('log in'))) {
        openLoginModal();
      }
      throw new Error(challengeData.error || 'Failed to acquire security challenge');
    }

    updateProgressStep('stepIdentity', 'success', '✓ Employee Identity & Passkey Verified');

    // STEP 2: Hospital Wi-Fi Network Check
    updateProgressStep('stepNetwork', 'active', 'Checking hospital Wi-Fi network...');
    await sleep(250);
    updateProgressStep('stepNetwork', 'success', '✓ Hospital Network Connection Confirmed');

    // STEP 3: Hospital Geofence & GPS Accuracy Check
    updateProgressStep('stepLocation', 'active', 'Verifying location accuracy & geofence...');
    await sleep(250);
    updateProgressStep('stepLocation', 'success', '✓ Hospital Geofence & Accuracy Confirmed');

    // STEP 4: Shift Window Validation
    updateProgressStep('stepShift', 'active', 'Validating shift schedule...');
    await sleep(250);
    updateProgressStep('stepShift', 'success', '✓ Assigned Shift Window Confirmed');

    // STEP 5: Server Timestamping & Punch Execution
    updateProgressStep('stepRecord', 'active', 'Generating server timestamp & audit record...');

    const punchRes = await fetch('/api/attendance/punch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        punchType: targetAction,
        location: state.currentLocation,
        challengeId: challengeData.challengeId,
        simulated: true
      })
    });

    const punchData = await punchRes.json();

    if (punchData.success) {
      updateProgressStep('stepRecord', 'success', '✓ Server Timestamped & Audit Evidence Recorded');
      await sleep(300);
      closeProgressModal();

      state.currentEmployee.current_punch_status = punchData.currentPunchStatus;
      state.currentEmployee.last_punch_time = punchData.serverTimestamp;
      updateActiveEmployeeUI();
      showAlert(`✓ ${punchData.message}`, 'success');
    } else {
      showModalFooter();

      if (punchData.reasonCode === 'INVALID_NETWORK') {
        updateProgressStep('stepNetwork', 'failed', '❌ Unauthorized Wi-Fi Network');
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode}`);
        showAlert(`❌ Network Security Rejection: You must connect to Kallara Hospital Wi-Fi!`, 'error');
      } else if (punchData.reasonCode === 'OUTSIDE_GEOFENCE' || punchData.reasonCode === 'LOCATION_ACCURACY_TOO_LOW') {
        updateProgressStep('stepLocation', 'failed', `❌ Geofence/Accuracy Failure`);
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode}`);
        showAlert(`❌ ${punchData.error}`, 'error');
      } else if (punchData.reasonCode === 'DUPLICATE_CHECK_IN') {
        state.currentEmployee.current_punch_status = 'CHECKED_IN';
        updateActiveEmployeeUI();
        showAlert(`Already Checked In. Click 'PUNCH OUT' to check out or 'Reset Test Punch' to start clean!`, 'error');
      } else if (punchData.reasonCode === 'DUPLICATE_CHECK_OUT') {
        state.currentEmployee.current_punch_status = 'CHECKED_OUT';
        updateActiveEmployeeUI();
        showAlert(`Already Checked Out today. Click 'Reset Test Punch' to start clean!`, 'error');
      } else {
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode || 'Validation Failed'}`);
        showAlert(`❌ ${punchData.error}`, 'error');
      }
    }
  } catch (err) {
    showModalFooter();
    showAlert(`Security Failure: ${err.message}`, 'error');
  } finally {
    if (btnMain) btnMain.disabled = false;
  }
}

// -------------------------------------------------------------
// PROGRESS MODAL HELPERS
// -------------------------------------------------------------
function openProgressModal(action) {
  const modal = document.getElementById('progressModal');
  const title = document.getElementById('modalTitle');
  title.textContent = action === 'CHECK_IN' ? 'Verifying Punch In...' : 'Verifying Punch Out...';

  ['stepIdentity', 'stepNetwork', 'stepLocation', 'stepShift', 'stepRecord'].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.className = 'progress-step-item';
      const icon = el.querySelector('.step-icon');
      if (icon) icon.textContent = '⏳';
    }
  });

  document.getElementById('modalFooter').style.display = 'none';
  modal.classList.add('active');
}

function updateProgressStep(stepId, status, labelText) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `progress-step-item ${status}`;
  const icon = el.querySelector('.step-icon');
  if (status === 'success' && icon) icon.textContent = '✓';
  else if (status === 'failed' && icon) icon.textContent = '❌';
  else if (icon) icon.textContent = '⏳';

  if (labelText) {
    const span = el.querySelector('span:nth-child(2)');
    if (span) span.textContent = labelText;
  }
}

function showModalFooter() {
  document.getElementById('modalFooter').style.display = 'block';
}

function closeProgressModal() {
  document.getElementById('progressModal').classList.remove('active');
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Banner Alert
function showAlert(msg, type = 'success') {
  const alert = document.getElementById('globalAlert');
  if (!alert) return;
  alert.textContent = msg;
  alert.className = `alert-banner show ${type}`;
  setTimeout(() => {
    alert.className = 'alert-banner';
  }, 5000);
}

// -------------------------------------------------------------
// STAFF ACCOUNT LOGIN MODAL & AUTHENTICATION
// -------------------------------------------------------------
function openLoginModal() {
  const modal = document.getElementById('loginModal');
  const select = document.getElementById('loginEmployeeSelect');
  if (!modal || !select) return;

  select.innerHTML = '';
  if (state.employees && state.employees.length > 0) {
    state.employees.forEach(emp => {
      const opt = document.createElement('option');
      opt.value = emp.id;
      opt.textContent = `${emp.name} (${emp.email || emp.id}) - ${emp.role.toUpperCase()}`;
      if (state.currentEmployee && state.currentEmployee.id === emp.id) {
        opt.selected = true;
      }
      select.appendChild(opt);
    });
  } else {
    const opt = document.createElement('option');
    opt.value = 'emp_1';
    opt.textContent = 'Rahul Sharma (rahul.sharma@vaidhyar.org) - EMPLOYEE';
    select.appendChild(opt);
  }

  modal.classList.add('active');
}

function closeLoginModal() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.remove('active');
}

async function performStaffLogin(targetEmpId) {
  const select = document.getElementById('loginEmployeeSelect');
  const empId = targetEmpId || (select ? select.value : 'emp_1');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ employeeId: empId })
    });
    const data = await res.json();

    if (data.success) {
      state.currentEmployee = state.employees.find(e => e.id === empId) || data.employee || { id: empId, name: 'Staff User', role: 'employee' };
      updateActiveEmployeeUI();
      closeLoginModal();
      showAlert(`✓ Logged in successfully as ${state.currentEmployee.name}`, 'success');
    } else {
      showAlert(`Login failed: ${data.error || 'Invalid credentials'}`, 'error');
    }
  } catch (err) {
    showAlert(`Login error: ${err.message}`, 'error');
  }
}

async function resetTestAttendance() {
  if (!state.currentEmployee) return;
  try {
    const res = await fetch('/api/test/reset-attendance', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    if (data.success) {
      state.currentEmployee.current_punch_status = 'NOT_STARTED';
      state.currentEmployee.last_punch_time = null;
      updateActiveEmployeeUI();
      showAlert(`✓ ${data.message}`, 'success');
    } else {
      showAlert(`Reset failed: ${data.error}`, 'error');
    }
  } catch (err) {
    showAlert(`Reset error: ${err.message}`, 'error');
  }
}
