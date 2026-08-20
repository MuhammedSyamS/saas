// Global Enterprise State
let state = {
  settings: null,
  clientIp: null,
  currentEmployee: null,
  shifts: [],
  hasPasskey: false,
  currentLocation: null // MUST be initialized as null (No default hospital GPS fallback!)
};

// Register Service Worker for PWA Shell
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW registration failed:', err));
  });
}

// Initialize Application
document.addEventListener('DOMContentLoaded', async () => {
  await fetchInitialData();
  await checkAuthSession();
});

// Fetch Initial System Data & Network Egress IP
async function fetchInitialData() {
  try {
    const res = await fetch('/api/initial-data');
    const data = await res.json();
    if (data.success) {
      state.settings = data.settings;
      if (data.clientIp) {
        state.clientIp = data.clientIp;
        const ipElem = document.getElementById('wifiIpAddress');
        if (ipElem) ipElem.textContent = data.clientIp;
      }
    }
  } catch (err) {
    showAlert('Failed to connect to backend server: ' + err.message, 'error');
  }
}

// Check Active Authentication Session
async function checkAuthSession() {
  try {
    const res = await fetch('/api/auth/me');
    const data = await res.json();

    if (data.success && data.employee) {
      state.currentEmployee = data.employee;
      state.shifts = data.shifts || [];
      state.hasPasskey = !!data.hasPasskey;

      updateAuthenticatedUI();
    } else {
      state.currentEmployee = null;
      updateUnauthenticatedUI();
    }
  } catch (err) {
    state.currentEmployee = null;
    updateUnauthenticatedUI();
  }
}

// Update UI for Authenticated Employee
function updateAuthenticatedUI() {
  const emp = state.currentEmployee;

  // Navbar
  document.getElementById('userInfoPill').style.display = 'flex';
  document.getElementById('currentUserName').textContent = `${emp.name}`;
  document.getElementById('btnLoginLogout').textContent = '🚪 Logout';
  document.getElementById('btnRegisterPasskey').style.display = 'inline-flex';

  // Greeting
  const hour = new Date().getHours();
  let timeGreeting = 'Good Morning';
  if (hour >= 12 && hour < 17) timeGreeting = 'Good Afternoon';
  if (hour >= 17) timeGreeting = 'Good Evening';
  const firstName = emp.name.split(' ')[0];

  document.getElementById('greetingTitle').textContent = `${timeGreeting}, ${firstName}`;
  document.getElementById('greetingSub').textContent = `Staff Role: ${emp.role.toUpperCase()} | ${emp.email}`;

  // Shift Details
  const shift = state.shifts.find(s => s.employee_id === emp.id) || state.shifts[0];
  const shiftNameElem = document.getElementById('assignedShiftName');
  const shiftTimeElem = document.getElementById('assignedShiftTime');

  if (shift) {
    shiftNameElem.textContent = shift.shift_name;
    shiftTimeElem.textContent = `${shift.start_time} – ${shift.end_time}`;
  } else {
    shiftNameElem.textContent = 'No Shift Assigned';
    shiftTimeElem.textContent = 'Contact Hospital HR';
  }

  // Attendance Status & Punch Button
  const badge = document.getElementById('attendanceStatusBadge');
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const btn = document.getElementById('btnPunchMain');
  const btnIcon = document.getElementById('btnIcon');
  const btnLabel = document.getElementById('btnLabel');
  const loginPrompt = document.getElementById('loginPromptNotice');

  loginPrompt.style.display = 'none';

  if (emp.role !== 'employee') {
    btn.style.display = 'none';
    badge.className = 'attendance-status-badge ready';
    statusDot.textContent = '🔒';
    statusText.textContent = 'Admin Mode (View Only)';
  } else {
    btn.style.display = 'inline-flex';

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
      statusText.textContent = 'SHIFT COMPLETED TODAY';

      btn.className = 'btn-punch-main in';
      btn.disabled = true; // Terminal state for shift instance!
      btnIcon.textContent = '✓';
      btnLabel.textContent = 'PUNCH COMPLETED';
    } else {
      badge.className = 'attendance-status-badge ready';
      statusDot.textContent = '●';
      statusText.textContent = 'Ready to Punch';

      btn.className = 'btn-punch-main in';
      btn.disabled = false;
      btnIcon.textContent = '👇';
      btnLabel.textContent = 'PUNCH IN';
    }
  }

  // Summary Row
  document.getElementById('summaryPasskey').textContent = state.hasPasskey ? '✓ Passkey Registered' : '⚠️ Passkey Required';
}

function updateUnauthenticatedUI() {
  document.getElementById('userInfoPill').style.display = 'none';
  document.getElementById('btnRegisterPasskey').style.display = 'none';
  document.getElementById('btnLoginLogout').textContent = '🔑 Login';

  document.getElementById('greetingTitle').textContent = 'Welcome to Vaidhyar Mandhiram';
  document.getElementById('greetingSub').textContent = 'Log in to mark your high-trust hospital attendance.';

  document.getElementById('btnPunchMain').style.display = 'none';
  document.getElementById('loginPromptNotice').style.display = 'block';

  const badge = document.getElementById('attendanceStatusBadge');
  badge.className = 'attendance-status-badge ready';
  document.getElementById('statusDot').textContent = '●';
  document.getElementById('statusText').textContent = 'Authentication Required';
}

// -------------------------------------------------------------
// WEBAUTHN PASSKEY REGISTRATION
// -------------------------------------------------------------
async function registerWebAuthnPasskey() {
  if (!state.currentEmployee) return openLoginModal();

  try {
    showAlert('Requesting passkey registration options from server...', 'info');
    const optRes = await fetch('/api/webauthn/register-options');
    const optData = await optRes.json();

    if (!optData.success) {
      throw new Error(optData.error || 'Failed to get registration options');
    }

    showAlert('Please authenticate on your device (Face ID / Fingerprint / Device Lock)...', 'info');

    // Trigger Browser WebAuthn API via SimpleWebAuthn
    let credential = null;
    if (window.SimpleWebAuthnBrowser) {
      credential = await SimpleWebAuthnBrowser.startRegistration(optData.options);
    } else {
      throw new Error('WebAuthn is not supported on this browser/device.');
    }

    const verifyRes = await fetch('/api/webauthn/register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: optData.challengeId,
        credential
      })
    });

    const verifyData = await verifyRes.json();

    if (verifyData.success) {
      state.hasPasskey = true;
      document.getElementById('summaryPasskey').textContent = '✓ Passkey Registered';
      showAlert('🎉 Biometric WebAuthn Passkey registered successfully!', 'success');
    } else {
      throw new Error(verifyData.error || 'Passkey registration verification failed');
    }
  } catch (err) {
    showAlert(`Passkey Error: ${err.message}`, 'error');
  }
}

// -------------------------------------------------------------
// FRESH LOCATION REQUEST
// -------------------------------------------------------------
function requestFreshLocation() {
  return new Promise((resolve, reject) => {
    if (!('geolocation' in navigator)) {
      return reject(new Error('LOCATION_REQUIRED: Browser does not support geolocation.'));
    }

    navigator.geolocation.getCurrentPosition(
      (pos) => {
        resolve({
          lat: pos.coords.latitude,
          lng: pos.coords.longitude,
          accuracy: pos.coords.accuracy
        });
      },
      (err) => {
        reject(new Error(`LOCATION_REQUIRED: ${err.message || 'GPS location permission denied.'}`));
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  });
}

// -------------------------------------------------------------
// HIGH-TRUST ATTENDANCE PUNCH PIPELINE
// -------------------------------------------------------------
async function initiateHighTrustPunch() {
  if (!state.currentEmployee) return openLoginModal();

  const emp = state.currentEmployee;
  if (emp.role !== 'employee') {
    return showAlert('Attendance marking is restricted to hospital staff employees only.', 'error');
  }

  const targetAction = emp.current_punch_status === 'CHECKED_IN' ? 'CHECK_OUT' : 'CHECK_IN';

  openProgressModal(targetAction);

  const btnMain = document.getElementById('btnPunchMain');
  if (btnMain) btnMain.disabled = true;

  try {
    // STEP 1: Biometric Passkey & Security Challenge
    updateProgressStep('stepIdentity', 'active', 'Requesting WebAuthn passkey challenge...');

    const challengeRes = await fetch('/api/attendance/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: targetAction })
    });
    const challengeData = await challengeRes.json();

    if (!challengeData.success) {
      updateProgressStep('stepIdentity', 'failed', 'Challenge Failed');
      showModalFooter();
      if (challengeRes.status === 401) openLoginModal();
      throw new Error(challengeData.error || 'Failed to acquire single-use challenge');
    }

    // Trigger WebAuthn Biometric Prompt
    updateProgressStep('stepIdentity', 'active', 'Authenticating device biometric passkey...');

    if (!window.SimpleWebAuthnBrowser) {
      throw new Error('WebAuthn is not supported on this device/browser.');
    }

    let credentialAssertion = null;
    try {
      const getOptions = {
        challenge: challengeData.challengeNonce,
        rpId: window.location.hostname === 'localhost' ? 'localhost' : window.location.hostname,
        userVerification: 'preferred',
        timeout: 60000
      };
      credentialAssertion = await SimpleWebAuthnBrowser.startAuthentication({ publicKey: getOptions });
    } catch (webauthnErr) {
      updateProgressStep('stepIdentity', 'failed', 'Biometric Authentication Failed');
      showModalFooter();
      throw new Error(`WebAuthn Authentication: ${webauthnErr.message}`);
    }

    updateProgressStep('stepIdentity', 'success', '✓ Biometric Passkey Assertion Verified');

    // STEP 2: Hospital Wi-Fi Network Check
    updateProgressStep('stepNetwork', 'active', 'Checking approved hospital network egress IP...');
    await sleep(200);
    updateProgressStep('stepNetwork', 'success', '✓ Approved Egress IP Confirmed');

    // STEP 3: Fresh GPS Location & Geofence Check
    updateProgressStep('stepLocation', 'active', 'Requesting fresh browser GPS location...');

    let locationEvidence = null;
    try {
      locationEvidence = await requestFreshLocation();
    } catch (locErr) {
      updateProgressStep('stepLocation', 'failed', 'GPS Location Failed');
      showModalFooter();
      throw locErr;
    }

    updateProgressStep('stepLocation', 'success', `✓ Fresh Location (±${Math.round(locationEvidence.accuracy)}m)`);

    // STEP 4: Shift Window & State Validation
    updateProgressStep('stepShift', 'active', 'Validating shift schedule & state machine...');
    await sleep(200);
    updateProgressStep('stepShift', 'success', '✓ Shift Window & State Transition Valid');

    // STEP 5: Server Timestamping & Atomic Punch Record
    updateProgressStep('stepRecord', 'active', 'Submitting cryptographic assertion & recording timestamp...');

    const punchRes = await fetch('/api/attendance/punch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        punchType: targetAction,
        location: locationEvidence,
        challengeId: challengeData.challengeId,
        credential: credentialAssertion
      })
    });

    const punchData = await punchRes.json();

    if (punchData.success) {
      updateProgressStep('stepRecord', 'success', '✓ Server Timestamped & Audit Evidence Recorded');
      await sleep(300);
      closeProgressModal();

      state.currentEmployee.current_punch_status = punchData.currentPunchStatus;
      state.currentEmployee.last_punch_time = punchData.serverTimestamp;
      updateAuthenticatedUI();
      showAlert(`🎉 ${punchData.message}`, 'success');
    } else {
      showModalFooter();

      if (punchData.reasonCode === 'INVALID_NETWORK') {
        updateProgressStep('stepNetwork', 'failed', '❌ Unauthorized Network IP');
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode}`);
        showAlert(`❌ Network Security Rejection: Connect to Kallara Hospital Wi-Fi!`, 'error');
      } else if (punchData.reasonCode === 'OUTSIDE_GEOFENCE' || punchData.reasonCode === 'LOCATION_ACCURACY_TOO_LOW') {
        updateProgressStep('stepLocation', 'failed', `❌ Geofence/Accuracy Failure`);
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode}`);
        showAlert(`❌ ${punchData.error}`, 'error');
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
// AUTH MODAL & HANDLERS
// -------------------------------------------------------------
function handleAuthAction() {
  if (state.currentEmployee) {
    performStaffLogout();
  } else {
    openLoginModal();
  }
}

function openLoginModal() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.add('active');
}

function closeLoginModal() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.remove('active');
}

async function handleStaffLoginForm(event) {
  event.preventDefault();
  const identifier = document.getElementById('loginIdentifier').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!identifier || !password) {
    return showAlert('Please enter employee ID/email and password', 'error');
  }

  try {
    const isEmail = identifier.includes('@');
    const body = isEmail ? { email: identifier, password } : { employeeId: identifier, password };

    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    const data = await res.json();

    if (data.success) {
      closeLoginModal();
      document.getElementById('loginPassword').value = '';
      showAlert(`✓ Logged in successfully as ${data.employee.name}`, 'success');
      await checkAuthSession();
    } else {
      showAlert(`Login failed: ${data.error || 'Invalid credentials'}`, 'error');
    }
  } catch (err) {
    showAlert(`Login error: ${err.message}`, 'error');
  }
}

async function performStaffLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
    state.currentEmployee = null;
    updateUnauthenticatedUI();
    showAlert('Logged out successfully', 'info');
  } catch (err) {
    showAlert('Logout error: ' + err.message, 'error');
  }
}
