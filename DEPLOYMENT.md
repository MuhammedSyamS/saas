# VAIDHYAR MANDHIRAM - High-Trust Attendance Module Production Deployment Guide

This guide details step-by-step instructions for deploying the **VAIDHYAR MANDHIRAM** Attendance PWA to **Vercel** under the custom domain:

```text
https://staff.vaidhyarmandhiram.com
```

---

## 1. Prerequisites & Preparation

Before deploying, ensure:
1. All automated tests pass cleanly:
   ```bash
   npm test
   ```
2. Your `.gitignore` excludes:
   - `node_modules`
   - `.env`
   - `attendance.db` (local development SQLite file)

---

## 2. GitHub Repository Push

Push your complete repository code to GitHub:

```bash
git add .
git commit -m "Prepare High-Trust Attendance Module for Vercel production deployment"
git push -u origin main
```

---

## 3. Vercel Project Setup

1. Log into your [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** → **Project**.
3. Import your GitHub repository (`MuhammedSyamS/saas`).
4. Keep the default build settings:
   - **Framework Preset**: Other / Node.js
   - **Root Directory**: `./`

---

## 4. Configure Production Environment Variables

In Vercel **Project Settings → Environment Variables**, add the following production variables:

| Variable Name | Production Value | Explanation |
| :--- | :--- | :--- |
| `NODE_ENV` | `production` | Enables production mode |
| `SESSION_SECRET` | `<random-secure-secret-32-chars>` | Secret key for HTTP-only session cookies |
| `WEBAUTHN_RP_ID` | `staff.vaidhyarmandhiram.com` | WebAuthn Relying Party ID |
| `WEBAUTHN_ORIGIN` | `https://staff.vaidhyarmandhiram.com` | WebAuthn production HTTPS origin |
| `HOSPITAL_LAT` | `8.750104` | Kallara Hospital latitude |
| `HOSPITAL_LNG` | `76.938646` | Kallara Hospital longitude |
| `GEOFENCE_RADIUS_METERS` | `120` | Radius threshold around hospital premises |
| `MAX_LOCATION_ACCURACY_METERS` | `60` | Maximum allowed GPS accuracy threshold |
| `HOSPITAL_ALLOWED_PUBLIC_IPS` | `103.15.22.4,103.15.22.5` | Approved public IP addresses of hospital Wi-Fi |
| `NETWORK_ENFORCEMENT_MODE` | `observe` | Start with `observe` for initial IP calibration |
| `MONGODB_URI` | `mongodb+srv://...` | MongoDB Atlas database cluster connection URI |

---

## 5. Custom Subdomain Configuration (`staff.vaidhyarmandhiram.com`)

To bind your staff PWA to `staff.vaidhyarmandhiram.com` without affecting `vaidhyarmandhiram.com`:

1. In Vercel, go to **Project Settings → Domains**.
2. Add domain:
   ```text
   staff.vaidhyarmandhiram.com
   ```
3. In your DNS provider for `vaidhyarmandhiram.com` (e.g. Cloudflare / GoDaddy / Namecheap):
   - Add a **CNAME** record:
     - **Host / Name**: `staff`
     - **Target / Value**: `cname.vercel-dns.com`
     - **TTL**: Auto / 3600
4. Wait for Vercel to issue the automatic SSL/TLS HTTPS Certificate.
5. Verify access by navigating to:
   ```text
   https://staff.vaidhyarmandhiram.com
   ```

---

## 6. Real Hospital Testing & Network Enforcement Workflow

Follow this procedure to safely calibrate hospital network IP detection:

### Step A: Initial Observation Mode (`NETWORK_ENFORCEMENT_MODE=observe`)
1. Deploy with `NETWORK_ENFORCEMENT_MODE=observe`.
2. Connect to real hospital Wi-Fi on a smartphone and open `https://staff.vaidhyarmandhiram.com`.
3. Perform a test **PUNCH IN**.
4. Log into Admin Audit Evidence at `https://staff.vaidhyarmandhiram.com/api/admin/audit-logs`.
5. Inspect the `source_ip` recorded in `attendance_attempts`.

### Step B: Configure Hospital Public IP
1. Copy the exact public IP address detected during hospital Wi-Fi punching.
2. Update the `HOSPITAL_ALLOWED_PUBLIC_IPS` environment variable in Vercel.

### Step C: Enable Strict Rejection Mode (`NETWORK_ENFORCEMENT_MODE=enforce`)
1. Update environment variable in Vercel:
   ```text
   NETWORK_ENFORCEMENT_MODE=enforce
   ```
2. Redeploy application.
3. Test punches:
   - **Inside Hospital Wi-Fi + Inside Geofence**: `✓ ATTENDANCE ACCEPTED`
   - **Mobile Data / Cellular Network**: `❌ ATTENDANCE REJECTED (INVALID_NETWORK)`
   - **Outside Hospital Grounds**: `❌ ATTENDANCE REJECTED (OUTSIDE_GEOFENCE)`

---

## 7. Security Failure & Verification Checklist

| Scenario | Expected Result | Reason Code |
| :--- | :--- | :--- |
| Unauthenticated request | Rejected (`401`) | `UNAUTHENTICATED` |
| Attempt to impersonate employee | Rejected (`401`) | `UNAUTHENTICATED` |
| Missing/expired WebAuthn challenge | Rejected (`400`) | `CHALLENGE_EXPIRED` |
| Replayed challenge | Rejected (`400`) | `CHALLENGE_ALREADY_USED` |
| Off-hospital Wi-Fi (in enforce mode) | Rejected (`403`) | `INVALID_NETWORK` |
| Outside geofence (>120m) | Rejected (`403`) | `OUTSIDE_GEOFENCE` |
| Low GPS accuracy (>60m) | Rejected (`400`) | `LOCATION_ACCURACY_TOO_LOW` |
| Duplicate Punch In | Rejected (`400`) | `DUPLICATE_CHECK_IN` |
| Punch Out before Check In | Rejected (`400`) | `INVALID_ATTENDANCE_STATE` |
| Duplicate Punch Out | Rejected (`400`) | `DUPLICATE_CHECK_OUT` |
| Manipulated phone clock | Has no effect; server timestamp is used | N/A |
