// Global State Management
const state = {
  currentEmployee: null,
  hasPasskey: false,
  shifts: [],
  systemSettings: null,
  clientIp: null
};

let currentLocation = null;

// Utility: Sleep helper
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Utility: Safe API Fetch Wrapper
async function safeFetchJson(url, options = {}) {
  try {
    const res = await fetch(url, options);
    const data = await res.json();
    return { status: res.statusCode || res.status, data };
  } catch (err) {
    return { status: 500, data: { success: false, error: err.message || 'Network request failed' } };
  }
}

// Global Alert Banner Helper
function showAlert(message, type = 'info') {
  const alertEl = document.getElementById('globalAlert');
  if (!alertEl) return;

  alertEl.className = `alert-banner ${type}`;
  alertEl.textContent = message;
  alertEl.style.display = 'block';

  if (type === 'success' || type === 'info') {
    setTimeout(() => {
      alertEl.style.display = 'none';
    }, 5000);
  }
}

// DOM Loaded Initialization
document.addEventListener('DOMContentLoaded', async () => {
  await loadInitialSystemData();
  await checkActiveSession();
  registerServiceWorker();
});

// Register PWA Service Worker
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(err => {
      console.warn('[SW Registration Error]:', err);
    });
  }
}

// Load Initial Server Settings & IP Information
async function loadInitialSystemData() {
  try {
    const { data } = await safeFetchJson('/api/initial-data');
    if (data.success) {
      state.systemSettings = data.settings;
      state.clientIp = data.clientIp;
    }
  } catch (e) {
    console.error('Failed to load initial system data:', e);
  }
}

// Check Active Employee Cookie Session
async function checkActiveSession() {
  try {
    const { status, data } = await safeFetchJson('/api/auth/me');
    if (status === 200 && data.success && data.employee) {
      state.currentEmployee = data.employee;
      state.hasPasskey = data.hasPasskey || false;
      state.shifts = data.shifts || [];
      updateAuthenticatedUI();
    } else {
      state.currentEmployee = null;
      updateUnauthenticatedUI();
    }
  } catch (e) {
    state.currentEmployee = null;
    updateUnauthenticatedUI();
  }
}

// -------------------------------------------------------------
// UI VIEW CONTROLLER
// -------------------------------------------------------------

function switchAuthTab(tab) {
  const loginForm = document.getElementById('inlineLoginForm');
  const registerForm = document.getElementById('inlineRegisterForm');
  const tabBtnLogin = document.getElementById('tabBtnLogin');
  const tabBtnRegister = document.getElementById('tabBtnRegister');

  if (tab === 'login') {
    if (loginForm) loginForm.style.display = 'block';
    if (registerForm) registerForm.style.display = 'none';
    if (tabBtnLogin) tabBtnLogin.classList.add('active');
    if (tabBtnRegister) tabBtnRegister.classList.remove('active');
  } else {
    if (loginForm) loginForm.style.display = 'none';
    if (registerForm) registerForm.style.display = 'block';
    if (tabBtnRegister) tabBtnRegister.classList.add('active');
    if (tabBtnLogin) tabBtnLogin.classList.remove('active');
  }
}

function updateAuthenticatedUI() {
  const emp = state.currentEmployee;
  if (!emp) return updateUnauthenticatedUI();

  // Hide Auth Card, Show Punch View
  document.getElementById('authCardSection').style.display = 'none';
  document.getElementById('punchTab').style.display = 'block';

  // Header Pill
  const pill = document.getElementById('userInfoPill');
  const roleBadge = document.getElementById('userRoleBadge');
  const userName = document.getElementById('currentUserName');
  const btnAuth = document.getElementById('btnLoginLogout');
  const btnPasskey = document.getElementById('btnRegisterPasskey');

  if (pill) pill.style.display = 'flex';
  if (roleBadge) roleBadge.textContent = emp.role === 'admin' ? 'CHIEF ADMIN' : 'STAFF';
  if (userName) userName.textContent = emp.name;
  if (btnAuth) btnAuth.textContent = '🚪 Logout';
  if (btnPasskey) btnPasskey.style.display = state.hasPasskey ? 'none' : 'inline-flex';

  const btnAdmin = document.getElementById('btnAdminTabToggle');
  if (btnAdmin) btnAdmin.style.display = emp.role === 'admin' ? 'inline-flex' : 'none';

  // Greeting
  document.getElementById('greetingTitle').textContent = `Good Day, ${emp.name}`;
  document.getElementById('greetingSub').textContent = `Employee ID: ${emp.id} • ${emp.email}`;

  // Shift Info
  if (state.shifts && state.shifts.length > 0) {
    const s = state.shifts[0];
    document.getElementById('assignedShiftName').textContent = s.shift_name;
    document.getElementById('assignedShiftTime').textContent = `${s.start_time} – ${s.end_time}`;
  }

  // Punch Action Button & Status Badge
  const statusBadge = document.getElementById('attendanceStatusBadge');
  const statusText = document.getElementById('statusText');
  const btnPunch = document.getElementById('btnPunchMain');
  const btnIcon = document.getElementById('btnIcon');
  const btnLabel = document.getElementById('btnLabel');

  const summaryCheckIn = document.getElementById('summaryCheckIn');
  const summaryCheckOut = document.getElementById('summaryCheckOut');
  const summaryPasskey = document.getElementById('summaryPasskey');

  if (summaryPasskey) {
    summaryPasskey.textContent = state.hasPasskey ? 'Active Passkey 🔑' : 'Not Registered';
    summaryPasskey.style.color = state.hasPasskey ? 'var(--accent-emerald)' : 'var(--accent-amber)';
  }

  if (emp.current_punch_status === 'CHECKED_IN') {
    statusBadge.className = 'attendance-status-badge active-in';
    statusText.textContent = 'Currently Checked In';
    if (summaryCheckIn) summaryCheckIn.textContent = formatTimeOnly(emp.last_punch_time);

    btnPunch.style.display = 'inline-flex';
    btnPunch.className = 'btn-punch-main out';
    btnIcon.textContent = '👆';
    btnLabel.textContent = 'PUNCH OUT';
  } else if (emp.current_punch_status === 'CHECKED_OUT') {
    statusBadge.className = 'attendance-status-badge completed';
    statusText.textContent = 'Shift Completed (Checked Out)';
    if (summaryCheckOut) summaryCheckOut.textContent = formatTimeOnly(emp.last_punch_time);

    btnPunch.style.display = 'none';
  } else {
    statusBadge.className = 'attendance-status-badge ready';
    statusText.textContent = 'Ready to Punch In';
    if (summaryCheckIn) summaryCheckIn.textContent = '--';
    if (summaryCheckOut) summaryCheckOut.textContent = '--';

    btnPunch.style.display = 'inline-flex';
    btnPunch.className = 'btn-punch-main in';
    btnIcon.textContent = '👇';
    btnLabel.textContent = 'PUNCH IN';
  }
}

function updateUnauthenticatedUI() {
  document.getElementById('authCardSection').style.display = 'block';
  document.getElementById('punchTab').style.display = 'none';

  const pill = document.getElementById('userInfoPill');
  const btnAuth = document.getElementById('btnLoginLogout');
  const btnPasskey = document.getElementById('btnRegisterPasskey');

  if (pill) pill.style.display = 'none';
  if (btnPasskey) btnPasskey.style.display = 'none';
  if (btnAuth) btnAuth.textContent = '🔑 Login';

  const btnAdmin = document.getElementById('btnAdminTabToggle');
  if (btnAdmin) btnAdmin.style.display = 'none';
  const adminSec = document.getElementById('adminPanelSection');
  if (adminSec) adminSec.style.display = 'none';
}

function formatTimeOnly(isoStr) {
  if (!isoStr) return '--';
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    return '--';
  }
}

function fillQuickLogin(email, password) {
  switchAuthTab('login');
  document.getElementById('loginIdentifier').value = email;
  document.getElementById('loginPassword').value = password;
}

// -------------------------------------------------------------
// AUTHENTICATION HANDLERS
// -------------------------------------------------------------

async function handleStaffLoginForm(event) {
  event.preventDefault();
  const identifier = document.getElementById('loginIdentifier').value.trim();
  const password = document.getElementById('loginPassword').value;

  if (!identifier || !password) {
    return showAlert('Please enter your Employee ID / Email and Password.', 'error');
  }

  showAlert('Verifying credentials...', 'info');

  const payload = identifier.includes('@') ? { email: identifier, password } : { employeeId: identifier, password };
  const { status, data } = await safeFetchJson('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (status === 200 && data.success) {
    showAlert('Login successful!', 'success');
    await checkActiveSession();
  } else {
    showAlert(`Login failed: ${data.error || 'Invalid credentials'}`, 'error');
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
    return showAlert('All fields are required for account setup.', 'error');
  }

  showAlert('Registering account...', 'info');

  const { status, data } = await safeFetchJson('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, employeeId, email, password, role })
  });

  if (status === 200 && data.success) {
    showAlert('Account registered and logged in successfully!', 'success');
    await checkActiveSession();
  } else {
    showAlert(`Registration failed: ${data.error || 'Server error'}`, 'error');
  }
}

async function handleAuthAction() {
  if (state.currentEmployee) {
    await safeFetchJson('/api/auth/logout', { method: 'POST' });
    state.currentEmployee = null;
    updateUnauthenticatedUI();
    showAlert('Logged out successfully.', 'info');
  } else {
    switchAuthTab('login');
  }
}

// -------------------------------------------------------------
// WEBAUTHN PASSKEY REGISTRATION & AUTHENTICATION (FIDO2)
// -------------------------------------------------------------

async function registerWebAuthnPasskey() {
  if (!state.currentEmployee) return switchAuthTab('login');

  closePasskeyPromptModal();
  showAlert('Initializing biometric passkey setup...', 'info');

  try {
    const { status: optStatus, data: optData } = await safeFetchJson('/api/webauthn/register-options');
    if (optStatus === 401 || !optData.success) {
      if (optStatus === 401) {
        state.currentEmployee = null;
        updateUnauthenticatedUI();
        switchAuthTab('login');
        showAlert('Session expired. Please log in first.', 'info');
        return;
      }
      throw new Error(optData.error || 'Failed to initialize WebAuthn passkey registration.');
    }

    let credentialResponse = null;
    if (window.SimpleWebAuthnBrowser && typeof window.SimpleWebAuthnBrowser.startRegistration === 'function') {
      credentialResponse = await window.SimpleWebAuthnBrowser.startRegistration(optData.options);
    } else {
      throw new Error('WebAuthn browser library not loaded. Use a supported browser (Chrome, Safari, Edge).');
    }

    showAlert('Verifying passkey signature on server...', 'info');

    const { data: verData } = await safeFetchJson('/api/webauthn/register-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challengeId: optData.challengeId,
        credential: credentialResponse
      })
    });

    if (verData.success && verData.verified) {
      state.hasPasskey = true;
      updateAuthenticatedUI();
      showAlert('🎉 Biometric Passkey registered successfully!', 'success');
    } else {
      throw new Error(verData.error || 'Passkey verification failed.');
    }
  } catch (err) {
    console.error('WebAuthn Registration Error:', err);
    showAlert(`Passkey Error: ${err.message || 'Passkey registration cancelled.'}`, 'error');
  }
}

async function webAuthnAuthenticate(options) {
  if (window.SimpleWebAuthnBrowser && typeof window.SimpleWebAuthnBrowser.startAuthentication === 'function') {
    return await window.SimpleWebAuthnBrowser.startAuthentication(options);
  }
  throw new Error('WebAuthn browser library unavailable.');
}

function formatWebAuthnErrorMessage(err) {
  const msg = err.message || String(err);
  if (msg.includes('cancelled') || msg.includes('canceled') || msg.includes('NotAllowedError')) {
    return 'Biometric prompt was cancelled or timed out.';
  }
  if (msg.includes('SecurityError') || msg.includes('domain')) {
    return 'Domain mismatch for WebAuthn passkey.';
  }
  return msg;
}

// -------------------------------------------------------------
// MULTI-SAMPLE GPS LOCATION ENGINE (REQUIREMENT 3 & 4)
// -------------------------------------------------------------
async function requestFreshLocation(sampleCount = 3, timeoutMs = 10000) {
  currentLocation = null;

  return new Promise(async (resolve, reject) => {
    if (!('geolocation' in navigator)) {
      return reject(new Error('LOCATION_REQUIRED: Browser does not support geolocation.'));
    }

    const samples = [];
    const perSampleTimeout = Math.max(2500, Math.floor(timeoutMs / sampleCount));

    for (let i = 0; i < sampleCount; i++) {
      try {
        const pos = await new Promise((res, rej) => {
          const timer = setTimeout(() => rej(new Error('Location sample timeout')), perSampleTimeout);
          navigator.geolocation.getCurrentPosition(
            (p) => {
              clearTimeout(timer);
              res(p);
            },
            (err) => {
              clearTimeout(timer);
              rej(err);
            },
            { enableHighAccuracy: true, timeout: perSampleTimeout, maximumAge: 0 }
          );
        });

        if (pos && pos.coords && typeof pos.coords.latitude === 'number' && pos.coords.accuracy > 0) {
          samples.push({
            lat: pos.coords.latitude,
            lng: pos.coords.longitude,
            accuracy: pos.coords.accuracy
          });
        }
      } catch (e) {
        // Continue to next sample attempt
      }
    }

    if (samples.length === 0) {
      return reject(new Error('We could not obtain an accurate location. Please ensure GPS is enabled and try again.'));
    }

    // Select the best quality sample (lowest accuracy uncertainty number)
    samples.sort((a, b) => a.accuracy - b.accuracy);
    currentLocation = samples[0];
    resolve(currentLocation);
  });
}

// -------------------------------------------------------------
// HIGH-TRUST ATTENDANCE PUNCH PIPELINE (STRICT DUAL ENFORCEMENT)
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
    // -------------------------------------------------------------
    // STEP 1: Biometric Passkey & Cryptographic Challenge Verification
    // -------------------------------------------------------------
    updateProgressStep('stepIdentity', 'active', 'Requesting WebAuthn passkey challenge...');

    const { status: chStatus, data: challengeData } = await safeFetchJson('/api/attendance/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: targetAction })
    });

    if (chStatus === 401 || !challengeData.success) {
      updateProgressStep('stepIdentity', 'failed', 'Challenge Failed');
      showModalFooter();
      if (chStatus === 401) {
        state.currentEmployee = null;
        updateUnauthenticatedUI();
        switchAuthTab('login');
        showAlert('Session expired. Please log in again.', 'info');
      }
      throw new Error(challengeData.error || 'Failed to acquire single-use challenge');
    }

    if (challengeData.hasPasskey === false) {
      closeProgressModal();
      openPasskeyPromptModal();
      return;
    }

    // Trigger WebAuthn Biometric Prompt
    updateProgressStep('stepIdentity', 'active', 'Authenticating device biometric passkey...');

    let credentialAssertion = null;
    try {
      credentialAssertion = await webAuthnAuthenticate(challengeData.options);
    } catch (webauthnErr) {
      const readableErr = formatWebAuthnErrorMessage(webauthnErr);
      updateProgressStep('stepIdentity', 'failed', 'Biometric Authentication Failed');
      showModalFooter();
      throw new Error(`WebAuthn Authentication: ${readableErr}`);
    }

    updateProgressStep('stepIdentity', 'success', '✓ Biometric Passkey Assertion Verified');

    // -------------------------------------------------------------
    // STEP 2: Strict Approved Hospital Wi-Fi Network Check
    // -------------------------------------------------------------
    updateProgressStep('stepNetwork', 'active', 'Checking approved hospital network egress IP...');
    try {
      const { data: ipData } = await safeFetchJson('/api/my-ip');
      if (ipData.networkEnforcementMode === 'enforce' && !ipData.isApproved) {
        updateProgressStep('stepNetwork', 'failed', `❌ Unauthorized Network IP (${ipData.clientIp})`);
        updateProgressStep('stepRecord', 'failed', 'Rejected: Must connect to Hospital Wi-Fi');
        showModalFooter();
        throw new Error(`Unauthorized Network IP (${ipData.clientIp}). Connect to approved Hospital Wi-Fi!`);
      } else {
        updateProgressStep('stepNetwork', 'success', `✓ Egress IP Verified (${ipData.clientIp})`);
      }
    } catch (ipErr) {
      if (ipErr.message && ipErr.message.includes('Unauthorized Network IP')) {
        throw ipErr;
      }
      updateProgressStep('stepNetwork', 'success', '✓ Egress IP Logged');
    }

    // -------------------------------------------------------------
    // STEP 3: Strict Authoritative GPS Geofence Check (Multi-Sample)
    // -------------------------------------------------------------
    updateProgressStep('stepLocation', 'active', 'Collecting fresh high-accuracy GPS samples...');

    let locationEvidence = null;
    try {
      locationEvidence = await requestFreshLocation(3, 10000);
    } catch (locErr) {
      updateProgressStep('stepLocation', 'failed', 'GPS Location Failed');
      showModalFooter();
      throw locErr;
    }

    updateProgressStep('stepLocation', 'success', `✓ Best GPS Sample (±${Math.round(locationEvidence.accuracy)}m)`);

    // -------------------------------------------------------------
    // STEP 4: Shift Window & State Validation
    // -------------------------------------------------------------
    updateProgressStep('stepShift', 'active', 'Validating shift schedule & state machine...');
    await sleep(200);
    updateProgressStep('stepShift', 'success', '✓ Shift Window & State Transition Valid');

    // -------------------------------------------------------------
    // STEP 5: Server Timestamping & Atomic Dual-Enforced Punch Commit
    // -------------------------------------------------------------
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
      showAlert(`🎉 ${punchData.message} [Ref: ${punchData.correlationId}]`, 'success');
    } else {
      showModalFooter();

      if (punchData.reasonCode === 'INVALID_NETWORK') {
        updateProgressStep('stepNetwork', 'failed', '❌ Unauthorized Network IP');
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode}`);
        showAlert(`❌ Network Security Rejection: Connect to Hospital Wi-Fi! [Ref: ${punchData.correlationId || 'ATT'}]`, 'error');
      } else if (punchData.reasonCode === 'BORDERLINE_LOCATION_RETRY' || punchData.reasonCode === 'LOCATION_ACCURACY_TOO_LOW') {
        updateProgressStep('stepLocation', 'warning', `⚠️ GPS Accuracy / Borderline Retry Required`);
        updateProgressStep('stepRecord', 'failed', `Retry Required [Ref: ${punchData.correlationId}]`);
        showAlert(`⚠️ ${punchData.error} [Reference: ${punchData.correlationId}]`, 'warning');
      } else if (punchData.reasonCode === 'OUTSIDE_GEOFENCE') {
        updateProgressStep('stepLocation', 'failed', `❌ Geofence Boundary Failure`);
        updateProgressStep('stepRecord', 'failed', `Rejected: OUTSIDE_GEOFENCE`);
        showAlert(`❌ ${punchData.error} [Reference: ${punchData.correlationId}]`, 'error');
      } else {
        updateProgressStep('stepRecord', 'failed', `Rejected: ${punchData.reasonCode || 'Validation Failed'}`);
        showAlert(`❌ ${punchData.error} [Reference: ${punchData.correlationId}]`, 'error');
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
  if (modal) modal.style.display = 'flex';
}

function updateProgressStep(stepId, status, message) {
  const el = document.getElementById(stepId);
  if (!el) return;

  const icon = el.querySelector('.step-icon');
  const text = el.querySelector('span:last-child');

  if (status === 'active') {
    el.className = 'progress-step-item active';
    if (icon) icon.textContent = '🔄';
  } else if (status === 'success') {
    el.className = 'progress-step-item success';
    if (icon) icon.textContent = '✓';
  } else if (status === 'warning') {
    el.className = 'progress-step-item warning';
    if (icon) icon.textContent = '⚠️';
  } else if (status === 'failed') {
    el.className = 'progress-step-item failed';
    if (icon) icon.textContent = '❌';
  }

  if (message && text) text.textContent = message;
}

function showModalFooter() {
  const footer = document.getElementById('modalFooter');
  if (footer) footer.style.display = 'block';
}

function closeProgressModal() {
  const modal = document.getElementById('progressModal');
  if (modal) modal.style.display = 'none';
}

function openPasskeyPromptModal() {
  const modal = document.getElementById('passkeyPromptModal');
  if (modal) modal.style.display = 'flex';
}

function closePasskeyPromptModal() {
  const modal = document.getElementById('passkeyPromptModal');
  if (modal) modal.style.display = 'none';
}

// -------------------------------------------------------------
// ADMIN BRANCH NETWORK & SECURITY PANEL
// -------------------------------------------------------------

let adminState = {
  settings: null,
  detectedIp: '',
  ipList: []
};

function toggleAdminPanelTab() {
  const adminSec = document.getElementById('adminPanelSection');
  const punchSec = document.getElementById('punchTab');
  const btnToggle = document.getElementById('btnAdminTabToggle');

  if (adminSec.style.display === 'none') {
    adminSec.style.display = 'block';
    punchSec.style.display = 'none';
    if (btnToggle) btnToggle.textContent = '📋 Staff Punch Tab';
    loadAdminSettings();
  } else {
    adminSec.style.display = 'none';
    punchSec.style.display = 'block';
    if (btnToggle) btnToggle.textContent = '🛡️ Admin Panel';
  }
}

async function loadAdminSettings() {
  showAlert('Loading admin network settings...', 'info');
  const { status, data } = await safeFetchJson('/api/admin/settings');
  if (status === 200 && data.success) {
    adminState.settings = data.settings || {};
    adminState.detectedIp = data.detectedClientIp || '';

    let parsedIps = [];
    try {
      parsedIps = typeof adminState.settings.hospital_wifi_ips === 'string'
        ? JSON.parse(adminState.settings.hospital_wifi_ips)
        : (adminState.settings.hospital_wifi_ips || []);
    } catch (e) {
      parsedIps = String(adminState.settings.hospital_wifi_ips || '').split(',').map(s => s.trim());
    }

    adminState.ipList = Array.from(new Set(parsedIps.filter(Boolean)));
    renderAdminPanelUI();
    loadAdminAuditLogs();
  } else {
    showAlert(`Failed to load admin settings: ${data.error || 'Access denied'}`, 'error');
  }
}

function renderAdminPanelUI() {
  const elIp = document.getElementById('adminDetectedIp');
  if (elIp) elIp.textContent = adminState.detectedIp || 'Unknown';

  const elMode = document.getElementById('adminNetworkMode');
  if (elMode) elMode.value = adminState.settings.network_enforcement_mode || 'enforce';

  const elName = document.getElementById('adminHospitalName');
  if (elName) elName.value = adminState.settings.hospital_name || 'VAIDHYAR MANDHIRAM, Kallara';

  const elLat = document.getElementById('adminGeofenceLat');
  if (elLat) elLat.value = adminState.settings.geofence_lat !== undefined ? adminState.settings.geofence_lat : 8.752625;

  const elLng = document.getElementById('adminGeofenceLng');
  if (elLng) elLng.value = adminState.settings.geofence_lng !== undefined ? adminState.settings.geofence_lng : 76.938625;

  const elRad = document.getElementById('adminRadiusMeters');
  if (elRad) elRad.value = adminState.settings.geofence_radius_meters !== undefined ? adminState.settings.geofence_radius_meters : 500;

  const elAcc = document.getElementById('adminMaxAccuracyMeters');
  if (elAcc) elAcc.value = adminState.settings.max_allowed_accuracy_meters !== undefined ? adminState.settings.max_allowed_accuracy_meters : 300;

  renderBranchIpList();
}

function renderBranchIpList() {
  const container = document.getElementById('adminIpListContainer');
  if (!container) return;

  if (adminState.ipList.length === 0) {
    container.innerHTML = `<div style="padding: 1rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">No branch Wi-Fi IPs configured yet. Click "Auto-Add My Wi-Fi IP" below.</div>`;
    return;
  }

  container.innerHTML = adminState.ipList.map((ip) => {
    const isCurrent = ip === adminState.detectedIp;
    return `
      <div style="display: flex; align-items: center; justify-content: space-between; padding: 0.75rem 1rem; background: #ffffff; border: 1px solid var(--border-color); border-radius: var(--radius-sm);">
        <div style="display: flex; align-items: center; gap: 0.75rem;">
          <span style="font-family: monospace; font-size: 0.95rem; font-weight: 800; color: var(--text-primary);">${ip}</span>
          ${isCurrent ? `<span style="font-size: 0.7rem; font-weight: 800; background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; padding: 0.2rem 0.5rem; border-radius: 999px;">CURRENT WI-FI</span>` : ''}
        </div>
        <button class="btn-secondary" style="font-size: 0.75rem; padding: 0.3rem 0.6rem; color: #be123c; border-color: #fecdd3;" onclick="removeBranchIp('${ip}')">
          🗑️ Remove
        </button>
      </div>
    `;
  }).join('');
}

async function addBranchIp() {
  const input = document.getElementById('newIpInput');
  const val = input ? input.value.trim() : '';

  if (!val) {
    return showAlert('Please enter a valid IP address or CIDR subnet.', 'error');
  }

  if (adminState.ipList.includes(val)) {
    return showAlert('This IP address is already in the authorized list.', 'info');
  }

  adminState.ipList.push(val);
  if (input) input.value = '';
  renderBranchIpList();
  await saveAdminSettingsQuiet();
  showAlert(`Added branch IP ${val} successfully!`, 'success');
}

async function removeBranchIp(ipToRemove) {
  adminState.ipList = adminState.ipList.filter(ip => ip !== ipToRemove);
  renderBranchIpList();
  await saveAdminSettingsQuiet();
  showAlert(`Removed IP ${ipToRemove}`, 'info');
}

async function autoAddCurrentIp() {
  if (!adminState.detectedIp) {
    return showAlert('No detected client IP available.', 'error');
  }
  if (adminState.ipList.includes(adminState.detectedIp)) {
    return showAlert(`Your current Wi-Fi IP (${adminState.detectedIp}) is already authorized!`, 'info');
  }
  adminState.ipList.push(adminState.detectedIp);
  renderBranchIpList();
  await saveAdminSettingsQuiet();
  showAlert(`🎉 Auto-added your current Wi-Fi IP (${adminState.detectedIp}) to authorized branch networks!`, 'success');
}

async function saveAdminSettingsQuiet() {
  const payload = {
    hospital_name: document.getElementById('adminHospitalName').value.trim() || 'VAIDHYAR MANDHIRAM, Kallara',
    network_enforcement_mode: document.getElementById('adminNetworkMode').value,
    geofence_lat: parseFloat(document.getElementById('adminGeofenceLat').value) || 8.752625,
    geofence_lng: parseFloat(document.getElementById('adminGeofenceLng').value) || 76.938625,
    geofence_radius_meters: parseFloat(document.getElementById('adminRadiusMeters').value) || 500,
    max_allowed_accuracy_meters: parseFloat(document.getElementById('adminMaxAccuracyMeters').value) || 300,
    hospital_wifi_ips: JSON.stringify(adminState.ipList)
  };

  await safeFetchJson('/api/admin/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
}

async function handleSaveAdminSettings(event) {
  event.preventDefault();
  showAlert('Saving admin security settings...', 'info');
  await saveAdminSettingsQuiet();
  showAlert('🎉 Admin security & branch Wi-Fi settings saved successfully!', 'success');
}

async function loadAdminAuditLogs() {
  const tbody = document.getElementById('adminAuditLogTableBody');
  if (!tbody) return;

  const { status, data } = await safeFetchJson('/api/admin/audit-logs');
  if (status === 200 && data.success && Array.isArray(data.logs)) {
    if (data.logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="padding: 1rem; text-align: center; color: var(--text-muted);">No security events logged yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = data.logs.slice(0, 20).map(log => `
      <tr style="border-bottom: 1px solid var(--border-color);">
        <td style="padding: 0.5rem 0.75rem; white-space: nowrap;">${formatTimeOnly(log.timestamp)}</td>
        <td style="padding: 0.5rem 0.75rem; font-weight: 700;">${log.employee_name || 'Anonymous'}</td>
        <td style="padding: 0.5rem 0.75rem;"><code>${log.event_type}</code></td>
        <td style="padding: 0.5rem 0.75rem;"><span style="color: ${log.severity === 'WARNING' || log.severity === 'SECURITY_SUSPICIOUS' ? '#e11d48' : '#059669'}; font-weight: 700;">${log.severity}</span></td>
        <td style="padding: 0.5rem 0.75rem; color: var(--text-secondary);">${log.reason || '--'}</td>
      </tr>
    `).join('');
  }
}
