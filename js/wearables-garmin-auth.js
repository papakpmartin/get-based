// @ts-check
// wearables-garmin-auth.js — Garmin Connect credentials-based auth
//
// Garmin Connect does not offer a public OAuth2 flow for web apps. The
// browser collects the user's email + password, sends it to /api/proxy as
// `garmin_credentials`, and the proxy performs the server-side Garmin login
// (including any Cloudflare/cookie/CSRF dance). The proxy returns an opaque
// session token + refresh token. Tokens are encrypted on-device via the
// wearable credential vault, exactly like OAuth adapters.
//
// Token refresh follows the same contract as OAuth adapters: the browser
// sends `garmin_token_refresh` to the proxy with the stored refresh token;
// the proxy returns a new session token.

import { getProxyApiUrl } from './proxy-runtime.js';
import { isDebugMode } from './utils.js';
import { exposeWearableAuthDebug } from './wearables-auth-runtime.js';

const PROXY_URL = getProxyApiUrl();
const REFRESH_LEAD_MS = 5 * 60 * 1000;
const REFRESH_LOCK_KEY = 'garmin-auth-refresh';

// Pending credentials connect is stored in sessionStorage so the connect modal
// can survive a page reload without re-typing the password. We deliberately
// do NOT store the password here; only the email and a flow nonce.
const PENDING_KEY = 'garmin-credentials-pending';

// ─────────────────────────────────────────────────────────
// Credentials connect
// ─────────────────────────────────────────────────────────

function randomState(nBytes = 16) {
  const bytes = new Uint8Array(nBytes);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Start the Garmin credentials connect flow.
 *
 * Unlike OAuth adapters, this does not navigate away. The caller should call
 * `completeCredentialsConnect(email, password)` to exchange the credentials
 * for a session token.
 *
 * @param {{ profileId?: string | null, email?: string | null }} [args]
 */
export function beginCredentialsConnect({ profileId = null, email = null } = {}) {
  const state = randomState();
  sessionStorage.setItem(PENDING_KEY, JSON.stringify({ state, startedAt: Date.now(), profileId, email }));
  return state;
}

export function getPendingCredentialsState() {
  const raw = sessionStorage.getItem(PENDING_KEY);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return null; }
}

export function clearPendingCredentialsState() {
  sessionStorage.removeItem(PENDING_KEY);
}

/**
 * Exchange email + password for a Garmin session token via the proxy.
 *
 * @param {{ email: string, password: string, profileId?: string | null }} args
 * @returns {Promise<{ ok: true, tokens: object, profileId?: string | null } | { ok: false, error: string, status?: number | null }>}
 */
export async function completeCredentialsConnect({ email, password, profileId = null }) {
  const pending = getPendingCredentialsState();
  if (pending && typeof pending.startedAt === 'number' && Date.now() - pending.startedAt > 10 * 60 * 1000) {
    clearPendingCredentialsState();
    return { ok: false, error: 'Credentials flow expired — please try connecting again' };
  }

  const res = await fetch(PROXY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      garmin_credentials: { email, password },
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    return {
      ok: false,
      error: body?.error_description || body?.error || body?.message || `Garmin sign-in failed (${res.status})`,
      status: res.status,
    };
  }
  if (!body?.access_token) {
    return { ok: false, error: body?.error || 'Garmin sign-in returned no session token' };
  }

  clearPendingCredentialsState();
  return {
    ok: true,
    tokens: normalizeTokenResponse(body),
    profileId: pending?.profileId || profileId || null,
  };
}

// ─────────────────────────────────────────────────────────
// Refresh
// ─────────────────────────────────────────────────────────

export async function refreshTokens({ refreshToken }) {
  const res = await fetch(PROXY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      garmin_token_refresh: { refresh_token: refreshToken },
    }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    /** @type {Error & { status?: number }} */
    const err = new Error(body?.error_description || body?.error || `Garmin refresh failed (${res.status})`);
    err.status = res.status;
    throw err;
  }
  return normalizeTokenResponse(body);
}

function normalizeTokenResponse(body) {
  const expiresIn = typeof body.expires_in === 'number' ? body.expires_in : 3600;
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token,
    expiresAt: Date.now() + (expiresIn * 1000),
    scope: body.scope || '',
    tokenType: body.token_type || 'bearer',
    userId: body.user_id || null,
  };
}

// ─────────────────────────────────────────────────────────
// Refresh middleware — same contract as OAuth adapters
// ─────────────────────────────────────────────────────────

export async function withFreshToken(connection, _clientId, refreshedWrite, readLatest) {
  const needsRefresh = !connection.accessToken || !connection.expiresAt || (connection.expiresAt - Date.now()) < REFRESH_LEAD_MS;
  if (!needsRefresh) return connection;

  const run = async () => {
    const latest = (readLatest?.() ?? connection);
    if (latest.expiresAt && (latest.expiresAt - Date.now()) >= REFRESH_LEAD_MS) return latest;
    if (!latest.refreshToken) {
      /** @type {Error & { code?: string }} */
      const e = new Error('No refresh token stored — user must reconnect');
      e.code = 'needs-reauth';
      throw e;
    }
    const fresh = await refreshTokens({ refreshToken: latest.refreshToken });
    const updated = {
      ...latest,
      accessToken: fresh.accessToken,
      refreshToken: fresh.refreshToken || latest.refreshToken,
      expiresAt: fresh.expiresAt,
      scope: fresh.scope || latest.scope,
      userId: fresh.userId || latest.userId,
    };
    await refreshedWrite(updated);
    return updated;
  };

  if (navigator.locks && typeof navigator.locks.request === 'function') {
    return navigator.locks.request(REFRESH_LOCK_KEY, { mode: 'exclusive' }, run);
  }
  return run();
}

exposeWearableAuthDebug('_garminAuth', { beginCredentialsConnect, completeCredentialsConnect, refreshTokens, withFreshToken }, Boolean(isDebugMode?.()));
