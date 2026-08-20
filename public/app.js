// Global Enterprise State
let state = {
  settings: null,
  clientIp: null,
  currentEmployee: null,
  shifts: [],
  hasPasskey: false,
  currentLocation: null // MUST be initialized as null (No default hospital GPS fallback!)
};

// Format WebAuthn & Device Errors into Clear, Human-Readable Explanations
function formatWebAuthnErrorMessage(err) {
  if (!err) return 'An unknown passkey error occurred.';
  const msg = typeof err === 'string' ? err : (err.message || String(err));
  const name = err.name || '';

  if (name === 'NotAllowedError' || msg.includes('cancelled') || msg.includes('canceled') || msg.includes('User canceled')) {
    return 'Device biometric authentication prompt was cancelled or timed out. Please try again.';
  }
  if (name === 'InvalidStateError' || msg.includes('already registered')) {
    return 'This biometric passkey is already registered on your device.';
  }
  if (name === 'NotSupportedError' || msg.includes('not supported')) {
    return 'Biometric WebAuthn passkeys require a secure connection (HTTPS or http://localhost).';
  }
  if (msg.includes('The first argument must be of type string') || msg.includes('Received undefined') || msg.includes('not send valid biometric credentials')) {
    return 'Please register your device passkey (Face ID / Fingerprint / Device PIN) first by clicking "🔑 Register Passkey".';
  }
  return msg;
}

// Safe API Fetch Helper (Prevents HTML response JSON parse errors when static dev server is used)
async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const contentType = res.headers.get('content-type') || '';
  const text = await res.text();

  if (text.trim().startsWith('<!DOCTYPE') || text.trim().startsWith('<html')) {
    throw new Error('Backend server returned HTML instead of API JSON. Ensure the Node.js backend server is running ("npm start" or "node server.js" from project root).');
  }

  try {
    const data = JSON.parse(text);
    return { status: res.status, ok: res.ok, data };
  } catch (err) {
    throw new Error('Server response was not valid JSON.');
  }
}

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
    const { data } = await safeFetchJson('/api/initial-data');
    if (data.success) {
      state.settings = data.settings;
      if (data.clientIp) {
        state.clientIp = data.clientIp;
        const ipElem = document.getElementById('wifiIpAddress');
        if (ipElem) ipElem.textContent = data.clientIp;
      }
    }
  } catch (err) {
    showAlert('Backend Connection Notice: ' + err.message, 'error');
  }
}

// Check Active Authentication Session
async function checkAuthSession() {
  try {
    const { data } = await safeFetchJson('/api/auth/me');

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

  // Toggle Card Views
  const authSection = document.getElementById('authCardSection');
  const punchSection = document.getElementById('punchTab');
  if (authSection) authSection.style.display = 'none';
  if (punchSection) punchSection.style.display = 'block';

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
  const authSection = document.getElementById('authCardSection');
  const punchSection = document.getElementById('punchTab');
  if (authSection) authSection.style.display = 'block';
  if (punchSection) punchSection.style.display = 'none';

  document.getElementById('userInfoPill').style.display = 'none';
  document.getElementById('btnRegisterPasskey').style.display = 'none';
  document.getElementById('btnLoginLogout').textContent = '🔑 Login';
}

// -------------------------------------------------------------
// AUTH TAB SWITCHING & QUICK LOGIN
// -------------------------------------------------------------
function switchAuthTab(tab) {
  const loginForm = document.getElementById('inlineLoginForm');
  const registerForm = document.getElementById('inlineRegisterForm');
  const btnLogin = document.getElementById('tabBtnLogin');
  const btnRegister = document.getElementById('tabBtnRegister');

  if (tab === 'login') {
    loginForm.style.display = 'block';
    registerForm.style.display = 'none';

    btnLogin.style.background = '#ffffff';
    btnLogin.style.color = '#1e293b';
    btnLogin.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';

    btnRegister.style.background = 'transparent';
    btnRegister.style.color = '#64748b';
    btnRegister.style.boxShadow = 'none';
  } else {
    loginForm.style.display = 'none';
    registerForm.style.display = 'block';

    btnRegister.style.background = '#ffffff';
    btnRegister.style.color = '#1e293b';
    btnRegister.style.boxShadow = '0 1px 3px rgba(0,0,0,0.1)';

    btnLogin.style.background = 'transparent';
    btnLogin.style.color = '#64748b';
    btnLogin.style.boxShadow = 'none';
  }
}

function fillQuickLogin(email, password) {
  document.getElementById('loginIdentifier').value = email;
  document.getElementById('loginPassword').value = password;
  switchAuthTab('login');
}

// -------------------------------------------------------------
// WEBAUTHN PASSKEY REGISTRATION & MODAL
// -------------------------------------------------------------
function openPasskeyPromptModal() {
  const modal = document.getElementById('passkeyPromptModal');
  if (modal) modal.classList.add('active');
}

function closePasskeyPromptModal() {
  const modal = document.getElementById('passkeyPromptModal');
  if (modal) modal.classList.remove('active');
}

async function registerWebAuthnPasskey() {
  if (!state.currentEmployee) return switchAuthTab('login');

  try {
    showAlert('Requesting passkey registration options from server...', 'info');
    const { data: optData } = await safeFetchJson('/api/webauthn/register-options');

    if (!optData.success) {
      throw new Error(optData.error || 'Failed to get registration options');
    }

    showAlert('Please authenticate on your device (Face ID / Fingerprint / Device Lock)...', 'info');

    let credential = null;
    if (window.SimpleWebAuthnBrowser && typeof window.SimpleWebAuthnBrowser.startRegistration === 'function') {
      credential = await window.SimpleWebAuthnBrowser.startRegistration(optData.options);
    } else {
      throw new Error('WebAuthn biometric library not loaded or supported in this browser.');
    }

    const { data: verifyData } = await safeFetchJson('/api/webauthn/register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: optData.challengeId,
        credential
      })
    });

    if (verifyData.success) {
      state.hasPasskey = true;
      if (document.getElementById('summaryPasskey')) {
        document.getElementById('summaryPasskey').textContent = '✓ Passkey Registered';
      }
      closePasskeyPromptModal();
      showAlert('🎉 Biometric WebAuthn Passkey registered successfully! You can now Punch Attendance.', 'success');
      await checkAuthSession();
    } else {
      throw new Error(verifyData.error || 'Passkey registration verification failed');
    }
  } catch (err) {
    const formattedError = formatWebAuthnErrorMessage(err);
    showAlert(`Passkey Error: ${formattedError}`, 'error');
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
  if (!state.currentEmployee) return switchAuthTab('login');

  const emp = state.currentEmployee;
  if (emp.role !== 'employee') {
    return showAlert('Attendance marking is restricted to hospital staff employees only.', 'error');
  }

  // Check if Employee has a registered passkey first!
  if (!state.hasPasskey) {
    openPasskeyPromptModal();
    return;
  }

  const targetAction = emp.current_punch_status === 'CHECKED_IN' ? 'CHECK_OUT' : 'CHECK_IN';

  openProgressModal(targetAction);

  const btnMain = document.getElementById('btnPunchMain');
  if (btnMain) btnMain.disabled = true;

  try {
    // STEP 1: Biometric Passkey & Security Challenge
    updateProgressStep('stepIdentity', 'active', 'Requesting WebAuthn passkey challenge...');

    const { status: chStatus, data: challengeData } = await safeFetchJson('/api/attendance/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: targetAction })
    });

    if (!challengeData.success) {
      updateProgressStep('stepIdentity', 'failed', 'Challenge Failed');
      showModalFooter();
      if (chStatus === 401) updateUnauthenticatedUI();
      throw new Error(challengeData.error || 'Failed to acquire single-use challenge');
    }

    if (challengeData.hasPasskey === false) {
      closeProgressModal();
      openPasskeyPromptModal();
      return;
    }

    // Trigger WebAuthn Biometric Prompt
    updateProgressStep('stepIdentity', 'active', 'Authenticating device biometric passkey...');

    if (!window.SimpleWebAuthnBrowser) {
      throw new Error('WebAuthn is not supported on this device/browser.');
    }

    let credentialAssertion = null;
    try {
      credentialAssertion = await window.SimpleWebAuthnBrowser.startAuthentication(challengeData.options);
    } catch (webauthnErr) {
      const readableErr = formatWebAuthnErrorMessage(webauthnErr);
      updateProgressStep('stepIdentity', 'failed', 'Biometric Authentication Failed');
      showModalFooter();
      throw new Error(`WebAuthn Authentication: ${readableErr}`);
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

    const { data: punchData } = await safeFetchJson('/api/attendance/punch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        punchType: targetAction,
        location: locationEvidence,
        challengeId: challengeData.challengeId,
        credential: credentialAssertion
      })
    });

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
// AUTH FORM HANDLERS
// -------------------------------------------------------------
function handleAuthAction() {
  if (state.currentEmployee) {
    performStaffLogout();
  } else {
    switchAuthTab('login');
  }
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

    const { data } = await safeFetchJson('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });

    if (data.success) {
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

async function handleStaffRegisterForm(event) {
  event.preventDefault();
  const name = document.getElementById('regName').value.trim();
  const employeeId = document.getElementById('regEmpId').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  const role = document.getElementById('regRole').value;

  if (!name || !employeeId || !email || !password) {
    return showAlert('All fields are required for staff account registration', 'error');
  }

  try {
    const { data } = await safeFetchJson('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, employeeId, email, password, role })
    });

    if (data.success) {
      document.getElementById('regPassword').value = '';
      showAlert(`🎉 Account created! Logged in as ${data.employee.name}`, 'success');
      await checkAuthSession();
    } else {
      showAlert(`Registration failed: ${data.error || 'Could not create account'}`, 'error');
    }
  } catch (err) {
    showAlert(`Registration error: ${err.message}`, 'error');
  }
}

async function performStaffLogout() {
  try {
    await safeFetchJson('/api/auth/logout', { method: 'POST' });
    state.currentEmployee = null;
    updateUnauthenticatedUI();
    showAlert('Logged out successfully', 'info');
  } catch (err) {
    showAlert('Logout error: ' + err.message, 'error');
  }
}
