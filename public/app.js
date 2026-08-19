// Global Application State
let state = {
  settings: null,
  employees: [],
  shifts: [],
  currentEmployee: null,
  currentLocation: { lat: 12.971598, lng: 77.594566, accuracy: 15 },
  simulator: {
    enabled: true,
    location: 'inside',
    network: '192.168.86.2',
    passkey: 'simulated',
    shift: 'valid'
  }
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

  // Set default date for correction form
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

      // URL Query Param Support for Testing (?emp=emp_1 or ?emp=emp_2 or ?role=admin)
      const params = new URLSearchParams(window.location.search);
      const empParam = params.get('emp');
      const roleParam = params.get('role');

      if (empParam) {
        state.currentEmployee = state.employees.find(e => e.id === empParam) || state.employees[0];
      } else if (roleParam === 'admin') {
        state.currentEmployee = state.employees.find(e => e.role === 'admin') || state.employees[0];
      } else {
        state.currentEmployee = state.employees.find(e => e.role === 'employee') || state.employees[0];
      }

      updateActiveEmployeeUI();
    }
  } catch (err) {
    showAlert('Failed to connect to backend server: ' + err.message, 'error');
  }
}

// Handle User Selector Change
function handleUserChange() {
  const selectedId = document.getElementById('userSelector').value;
  state.currentEmployee = state.employees.find(e => e.id === selectedId);
  updateActiveEmployeeUI();
}

// Update Employee Experience UI (VAIDHYAR MANDHIRAM Brand & Layout)
function updateActiveEmployeeUI() {
  if (!state.currentEmployee) return;

  const emp = state.currentEmployee;

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

  // Refresh tab lists
  loadMyCorrections();
  if (emp.role === 'admin') {
    loadAdminAuditLogs();
    loadAdminPendingRequests();
  }

  // Update hospital presence UI
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

// Show Punch Button ONLY when user is an EMPLOYEE AND physically inside hospital geofence
function updateHospitalPresenceUI() {
  const btnPunch = document.getElementById('btnPunchMain');
  const noticeBox = document.getElementById('outsideHospitalNotice');
  const noticeDetail = document.getElementById('outsideNoticeDetail');

  if (!btnPunch || !noticeBox) return;

  // Check role: Attendance marking is strictly for staff employees only
  if (state.currentEmployee && state.currentEmployee.role !== 'employee') {
    btnPunch.style.display = 'none';
    noticeBox.style.display = 'block';
    if (noticeDetail) {
      noticeDetail.textContent = '🔒 Admin Account: Attendance marking is restricted to hospital staff employees only.';
    }
    return;
  }

  const hospitalLat = state.settings?.geofence_lat || 8.750104;
  const hospitalLng = state.settings?.geofence_lng || 76.938646;
  const maxRadius = state.settings?.geofence_radius_meters || 500;

  const distanceMeters = calculateHaversineDistance(
    state.currentLocation.lat,
    state.currentLocation.lng,
    hospitalLat,
    hospitalLng
  );

  // Check physical presence inside Kallara Hospital geofence
  const isDevLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  const isInside = (distanceMeters <= maxRadius) || isDevLocal;

  if (isInside) {
    btnPunch.style.display = 'inline-flex';
    noticeBox.style.display = 'none';
  } else {
    btnPunch.style.display = 'none';
    noticeBox.style.display = 'block';
    if (noticeDetail) {
      noticeDetail.textContent = `You are currently ${Math.round(distanceMeters)} meters away from Kallara Hospital grounds (QW3Q+2CG, Kallara, Kerala 695608). Attendance punching is permitted only inside hospital premises (${maxRadius}m radius).`;
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

// Toggle Simulator
function toggleSimulatorMode() {
  state.simulator.enabled = document.getElementById('simulatorToggle').checked;
  document.getElementById('simulatorControls').style.opacity = state.simulator.enabled ? '1' : '0.4';
}

// Update Simulated Location Preset
function updateSimulatedLocation() {
  const preset = document.getElementById('simLocation').value;
  state.simulator.location = preset;

  if (preset === 'inside') {
    state.currentLocation = { lat: 12.971598, lng: 77.594566, accuracy: 15 };
  } else if (preset === 'outside') {
    state.currentLocation = { lat: 12.990000, lng: 77.610000, accuracy: 20 };
  } else if (preset === 'low_accuracy') {
    state.currentLocation = { lat: 12.971598, lng: 77.594566, accuracy: 250 };
  }
}

// -------------------------------------------------------------
// INSTANT HIGH-TRUST ATTENDANCE PUNCH PIPELINE
// -------------------------------------------------------------
async function initiateHighTrustPunch() {
  if (!state.currentEmployee) return showAlert('Please select an active staff member', 'error');

  const emp = state.currentEmployee;
  const targetAction = emp.current_punch_status === 'CHECKED_IN' ? 'CHECK_OUT' : 'CHECK_IN';

  const simPasskey = document.getElementById('simPasskey')?.value || 'simulated';
  const simNetwork = document.getElementById('simNetwork')?.value || '192.168.86.2';
  const isSimulated = true;

  // Disable button briefly to prevent double clicks
  const btnMain = document.getElementById('btnPunchMain');
  if (btnMain) btnMain.disabled = true;

  try {
    // 1. Acquire Fresh Single-Use Challenge Token
    const challengeRes = await fetch('/api/attendance/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ employeeId: emp.id, action: targetAction })
    });
    const challengeData = await challengeRes.json();
    if (!challengeData.success) throw new Error(challengeData.error || 'Failed to acquire security token');

    let credentialPayload = null;

    // 2. Execute Multi-Layer Verification & Server Timestamping
    const punchRes = await fetch('/api/attendance/punch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        employeeId: emp.id,
        punchType: targetAction,
        location: state.currentLocation,
        simulated_ip: undefined,
        challengeId: challengeData.challengeId,
        credential: credentialPayload,
        simulated: true
      })
    });

    const punchData = await punchRes.json();

    if (punchData.success) {
      state.currentEmployee.current_punch_status = punchData.currentPunchStatus;
      state.currentEmployee.last_punch_time = punchData.serverTimestamp;
      updateActiveEmployeeUI();
      showAlert(`✓ ${punchData.message}`, 'success');
    } else {
      showAlert(`❌ ${punchData.error}`, 'error');
    }
  } catch (err) {
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

  // Reset steps
  ['stepIdentity', 'stepNetwork', 'stepLocation', 'stepShift', 'stepRecord'].forEach(id => {
    const el = document.getElementById(id);
    el.className = 'progress-step-item';
    el.querySelector('.step-icon').textContent = '⏳';
  });

  document.getElementById('modalFooter').style.display = 'none';
  modal.classList.add('active');
}

function updateProgressStep(stepId, status, labelText) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `progress-step-item ${status}`;
  const icon = el.querySelector('.step-icon');
  if (status === 'success') icon.textContent = '✓';
  else if (status === 'failed') icon.textContent = '❌';
  else icon.textContent = '⏳';

  if (labelText) {
    el.querySelector('span:nth-child(2)').textContent = labelText;
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

// -------------------------------------------------------------
// CORRECTION REQUESTS
// -------------------------------------------------------------
async function submitCorrectionRequest(event) {
  event.preventDefault();
  const requestedDate = document.getElementById('corrDate').value;
  const requestedPunchType = document.getElementById('corrPunchType').value;
  const requestedTime = document.getElementById('corrTime').value;
  const reason = document.getElementById('corrReason').value;

  try {
    const res = await fetch('/api/corrections/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        employeeId: state.currentEmployee.id,
        requestedDate,
        requestedPunchType,
        requestedTime,
        reason
      })
    });
    const data = await res.json();
    if (data.success) {
      showAlert('✓ Correction request submitted for authorized review', 'success');
      document.getElementById('corrReason').value = '';
      loadMyCorrections();
      loadAdminPendingRequests();
    } else {
      showAlert(data.error, 'error');
    }
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

async function loadMyCorrections() {
  if (!state.currentEmployee) return;
  try {
    const res = await fetch(`/api/corrections/list?employeeId=${state.currentEmployee.id}`);
    const data = await res.json();
    const tbody = document.getElementById('myCorrectionsTable');
    tbody.innerHTML = '';
    data.requests.forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${r.requested_date} ${r.requested_time}</td>
        <td><b style="color:${r.requested_punch_type === 'CHECK_IN' ? 'var(--accent-emerald)' : 'var(--accent-rose)'}">${r.requested_punch_type}</b></td>
        <td>${r.reason}</td>
        <td><span style="font-weight:700; color:${r.status === 'APPROVED' ? 'var(--accent-emerald)' : (r.status === 'REJECTED' ? 'var(--accent-rose)' : 'var(--accent-amber)')}">${r.status}</span></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

// -------------------------------------------------------------
// ADMIN AUDIT LOGS & SETTINGS
// -------------------------------------------------------------
async function loadAdminAuditLogs() {
  try {
    const res = await fetch('/api/admin/audit-logs');
    const data = await res.json();
    const tbody = document.getElementById('auditLogsTable');
    tbody.innerHTML = '';
    data.logs.forEach(log => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-size:0.75rem; color:var(--text-muted);">${new Date(log.timestamp).toLocaleTimeString()}</td>
        <td><b>${log.employee_name}</b></td>
        <td><code>${log.event_type}</code></td>
        <td><span style="padding:0.2rem 0.5rem; border-radius:4px; font-weight:700; font-size:0.75rem; background:${log.severity==='INFO'?'#eff6ff':(log.severity==='WARNING'?'#fffbe6':'#fef2f2')}; color:${log.severity==='INFO'?'var(--accent-blue)':(log.severity==='WARNING'?'var(--accent-amber)':'var(--accent-rose)')}">${log.reason_code}</span></td>
        <td>${log.reason}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

async function loadAdminPendingRequests() {
  try {
    const corrRes = await fetch('/api/corrections/list');
    const corrData = await corrRes.json();
    const corrTbody = document.getElementById('adminCorrectionsTable');
    corrTbody.innerHTML = '';

    corrData.requests.filter(r => r.status === 'PENDING').forEach(r => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><b>${r.employee_name}</b></td>
        <td>${r.requested_punch_type} (${r.requested_date} ${r.requested_time})</td>
        <td>${r.reason}</td>
        <td>
          <button class="btn-secondary" style="background:#ecfdf5; color:var(--accent-emerald);" onclick="reviewCorrection('${r.id}', 'APPROVED')">Approve</button>
          <button class="btn-secondary" style="background:#fef2f2; color:var(--accent-rose);" onclick="reviewCorrection('${r.id}', 'REJECTED')">Reject</button>
        </td>
      `;
      corrTbody.appendChild(tr);
    });
  } catch (err) {}
}

async function reviewCorrection(requestId, action) {
  try {
    const res = await fetch('/api/corrections/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestId, action, adminNotes: 'Processed via Admin Portal' })
    });
    const data = await res.json();
    showAlert(data.message, 'success');
    loadAdminPendingRequests();
    loadAdminAuditLogs();
    fetchInitialData();
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

function populateAdminSettings() {
  if (!state.settings) return;
  document.getElementById('adminGeofenceLat').value = state.settings.geofence_lat;
  document.getElementById('adminGeofenceLng').value = state.settings.geofence_lng;
  document.getElementById('adminGeofenceRadius').value = state.settings.geofence_radius_meters;
  document.getElementById('adminMaxAccuracy').value = state.settings.max_allowed_accuracy_meters;
  document.getElementById('adminWifiIps').value = state.settings.hospital_wifi_ips;
}

async function saveAdminSettings() {
  try {
    const body = {
      hospital_name: 'VAIDHYAR MANDHIRAM',
      geofence_lat: document.getElementById('adminGeofenceLat').value,
      geofence_lng: document.getElementById('adminGeofenceLng').value,
      geofence_radius_meters: document.getElementById('adminGeofenceRadius').value,
      max_allowed_accuracy_meters: document.getElementById('adminMaxAccuracy').value,
      hospital_wifi_ips: document.getElementById('adminWifiIps').value,
      enforcement_strict_wifi: 1,
      enforcement_strict_geofence: 1,
      enforcement_strict_accuracy: 1,
      enforcement_strict_shift: 1
    };

    const res = await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (data.success) {
      showAlert('Hospital security parameters saved!', 'success');
      fetchInitialData();
    }
  } catch (err) {
    showAlert(err.message, 'error');
  }
}

// Tab Switcher
function switchTab(tabId) {
  document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

  document.getElementById(tabId).style.display = 'block';

  const btns = document.querySelectorAll('.tab-btn');
  if (tabId === 'punchTab') btns[0].classList.add('active');
  if (tabId === 'correctionTab') btns[1].classList.add('active');
  if (tabId === 'adminTab') {
    btns[2].classList.add('active');
    loadAdminAuditLogs();
    loadAdminPendingRequests();
  }
}

// Banner Alert
function showAlert(msg, type = 'success') {
  const alert = document.getElementById('globalAlert');
  alert.textContent = msg;
  alert.className = `alert-banner show ${type}`;
  setTimeout(() => {
    alert.className = 'alert-banner';
  }, 5000);
}
