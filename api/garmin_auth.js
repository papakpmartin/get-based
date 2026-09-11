// garmin_auth.js — Node.js serverless function for Garmin Connect authentication.
// Ports the garth library's OAuth1 → OAuth2 exchange to JS so it runs in
// Vercel's Node.js runtime (Python functions don't deploy with outputDirectory: ".").
//
// Flow: SSO login → service ticket → OAuth1 token → OAuth2 exchange.

/** @ts-check */
import crypto from 'node:crypto';

// ── Constants (from garth/sso.py) ───────────────────────────────
const CLIENT_ID = 'GCM_ANDROID_DARK';
const OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';
const SSO_SUCCESSFUL = 'SUCCESSFUL';
const SSO_MFA_REQUIRED = 'MFA_REQUIRED';

const DOMAIN = 'garmin.com';

const SSO_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) ' +
  'AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';

const SSO_PAGE_HEADERS = {
  'User-Agent': SSO_UA,
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Dest': 'document',
};

const OAUTH_USER_AGENT = 'com.garmin.android.apps.connectmobile';

const ALLOWED_ORIGINS = new Set([
  'https://app.getbased.health',
  'https://getbased.health',
  'https://www.getbased.health',
  'https://beta.getbased.health',
  'https://get-based.vercel.app',
  'https://get-based-managed-subscription-v2.vercel.app',
  'https://getbased.kpmartin.com',
]);

// ── Cookie jar (manual, since Vercel Node fetch doesn't have one) ──
class CookieJar {
  constructor() {
    this.map = new Map();
  }

  /** Parse Set-Cookie header(s) and store. */
  capture(setCookieHeaders) {
    if (!setCookieHeaders) return;
    const headers = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
    for (const raw of headers) {
      if (!raw) continue;
      const parts = raw.split(';')[0].trim();
      if (!parts) continue;
      const eq = parts.indexOf('=');
      if (eq < 0) continue;
      const name = parts.slice(0, eq).trim();
      const value = parts.slice(eq + 1).trim();
      this.map.set(name, value);
    }
  }

  /** Produce a Cookie header string for outgoing requests. */
  header() {
    if (this.map.size === 0) return undefined;
    return Array.from(this.map, ([k, v]) => `${k}=${v}`).join('; ');
  }
}

// ── OAuth1 HMAC-SHA1 signing ────────────────────────────────────
// Ports oauthlib's request signing for the Garmin OAuth1 flow.

function percentEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase())
    .replace(/%20/g, '%20');
}

/**
 * Sign an OAuth1 request and return the Authorization header value.
 * Implements HMAC-SHA1 per RFC 5849 (OAuth 1.0).
 */
function signOAuth1({ method, url, params, consumerKey, consumerSecret, tokenKey, tokenSecret }) {
  // Collect all parameters (OAuth + query params)
  const allParams = { ...params };
  allParams.oauth_consumer_key = consumerKey;
  allParams.oauth_signature_method = 'HMAC-SHA1';
  allParams.oauth_timestamp = String(Math.floor(Date.now() / 1000));
  allParams.oauth_nonce = crypto.randomBytes(16).toString('hex');
  allParams.oauth_version = '1.0';
  if (tokenKey) allParams.oauth_token = tokenKey;

  // Normalize parameters: sort by key, then value
  const encoded = Object.entries(allParams)
    .map(([k, v]) => [percentEncode(String(k)), percentEncode(String(v))])
    .sort(([a1, a2], [b1, b2]) => (a1 < b1 ? -1 : a1 > b1 ? 1 : a2 < b2 ? -1 : a2 > b2 ? 1 : 0));

  const paramString = encoded.map(([k, v]) => `${k}=${v}`).join('&');

  // Build signature base string
  const baseUrl = url.split('#')[0].split('?')[0];
  const signatureBase = [
    method.toUpperCase(),
    percentEncode(baseUrl),
    percentEncode(paramString),
  ].join('&');

  // Sign with HMAC-SHA1
  const signingKey = `${percentEncode(consumerSecret)}&${percentEncode(tokenSecret || '')}`;
  const signature = crypto.createHmac('sha1', signingKey).update(signatureBase).digest('base64');

  // Build Authorization header
  const authParams = { ...allParams, oauth_signature: signature };
  return (
    'OAuth ' +
    Object.entries(authParams)
      .map(([k, v]) => `${percentEncode(k)}="${percentEncode(String(v))}"`)
      .join(',')
  );
}

// ── Fetch helper with cookie jar ────────────────────────────────
async function garminFetch(url, options, cookies, extraHeaders = {}) {
  const cookieHeader = cookies.header();
  const headers = { ...extraHeaders };
  if (cookieHeader) headers.Cookie = cookieHeader;

  const res = await fetch(url, {
    ...options,
    headers: { ...headers, ...(options?.headers || {}) },
    redirect: 'manual', // handle redirects manually to capture cookies at each step
  });

  // Capture cookies from Set-Cookie
  const setCookie = res.headers.getsetcookie?.();
  if (setCookie) cookies.capture(setCookie);
  else {
    // Node 18 fallback — getSetCookie() may not exist
    const sc = res.headers.get('set-cookie');
    if (sc) cookies.capture(sc);
  }

  return res;
}

// ── Token serialization helpers ─────────────────────────────────

function oauth1ToRefreshToken(oauth1) {
  const payload = {
    oauth_token: oauth1.oauth_token,
    oauth_token_secret: oauth1.oauth_token_secret,
  };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function refreshTokenToOAuth1(refreshToken) {
  const raw = Buffer.from(refreshToken, 'base64').toString('utf-8');
  return JSON.parse(raw);
}

function setExpirations(token) {
  const now = Math.floor(Date.now() / 1000);
  return {
    ...token,
    expires_at: now + (token.expires_in || 3600),
    refresh_token_expires_at: now + (token.refresh_token_expires_in || 7776000),
  };
}

// ── Main auth flows ─────────────────────────────────────────────

/**
 * Fetch OAuth consumer key/secret from S3 (garth's public consumer).
 */
let cachedConsumer = null;
async function getOAuthConsumer() {
  if (cachedConsumer) return cachedConsumer;
  const res = await fetch(OAUTH_CONSUMER_URL);
  if (!res.ok) throw new Error(`Failed to fetch OAuth consumer: ${res.status}`);
  cachedConsumer = await res.json();
  return cachedConsumer;
}

/**
 * Login to Garmin SSO and return { oauth1, oauth2 } or { mfa_required, mfa_method }.
 */
async function garminLogin(email, password) {
  const cookies = new CookieJar();
  const consumer = await getOAuthConsumer();
  const serviceUrl = `https://mobile.integration.${DOMAIN}/gcm/android`;
  const loginParams = {
    clientId: CLIENT_ID,
    locale: 'en-US',
    service: serviceUrl,
  };

  // Step 1: GET SSO sign-in page (sets cookies)
  const ssoPageUrl = new URL(`https://sso.${DOMAIN}/mobile/sso/en/sign-in`);
  ssoPageUrl.searchParams.set('clientId', CLIENT_ID);
  await garminFetch(ssoPageUrl.href, {
    method: 'GET',
  }, cookies, {
    ...SSO_PAGE_HEADERS,
    'Sec-Fetch-Site': 'none',
  });

  // Step 2: POST credentials to SSO login API
  const loginUrl = new URL(`https://sso.${DOMAIN}/mobile/api/login`);
  for (const [k, v] of Object.entries(loginParams)) loginUrl.searchParams.set(k, v);

  const loginRes = await garminFetch(loginUrl.href, {
    method: 'POST',
    headers: { ...SSO_PAGE_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: email,
      password,
      rememberMe: false,
      captchaToken: '',
    }),
  }, cookies);

  const loginBody = await loginRes.json().catch(() => ({}));
  const respType = loginBody?.responseStatus?.type;

  if (respType === SSO_SUCCESSFUL) {
    const ticket = loginBody.serviceTicketId;
    return completeLogin(ticket, cookies, consumer);
  }

  if (respType === SSO_MFA_REQUIRED) {
    const mfaInfo = loginBody?.customerMfaInfo || {};
    const mfaMethod = mfaInfo.mfaLastMethodUsed || 'email';
    return { mfa_required: true, mfa_method: mfaMethod };
  }

  if (loginRes.status === 401 || respType === 'INVALID_CREDENTIALS') {
    const err = new Error('Invalid Garmin credentials.');
    err.status = 401;
    throw err;
  }

  const detail = loginBody?.responseStatus?.message || respType || 'unknown';
  const err = new Error(`SSO error: ${detail}`);
  err.status = 502;
  throw err;
}

/**
 * Complete login: get OAuth1 token via service ticket, then exchange for OAuth2.
 */
async function completeLogin(ticket, cookies, consumer) {
  // Best-effort: GET embed page to set Cloudflare LB cookie
  try {
    const embedUrl = new URL(`https://sso.${DOMAIN}/portal/sso/embed`);
    await garminFetch(embedUrl.href, {
      method: 'GET',
    }, cookies, {
      ...SSO_PAGE_HEADERS,
      'Sec-Fetch-Site': 'same-origin',
      Referer: `https://sso.${DOMAIN}/`,
    });
  } catch {
    // best-effort, ignore
  }

  // Step 3: Get OAuth1 token via service ticket
  const oauth1 = await getOAuth1Token(ticket, cookies, consumer);

  // Step 4: Exchange OAuth1 for OAuth2
  const oauth2 = await exchangeOAuth1ForOAuth2(oauth1, cookies, consumer, true);

  return { oauth1, oauth2 };
}

/**
 * Get OAuth1 token using the service ticket from SSO login.
 * Uses OAuth1-signed GET to the preauthorized endpoint.
 */
async function getOAuth1Token(ticket, cookies, consumer) {
  const baseUrl = `https://connectapi.${DOMAIN}/oauth-service/oauth/`;
  const loginUrl = `https://mobile.integration.${DOMAIN}/gcm/android`;
  const url = `${baseUrl}preauthorized?ticket=${encodeURIComponent(ticket)}&login-url=${encodeURIComponent(loginUrl)}&accepts-mfa-tokens=true`;

  // Sign the request with OAuth1
  const authHeader = signOAuth1({
    method: 'GET',
    url,
    params: {}, // query params are already in the URL
    consumerKey: consumer.consumer_key,
    consumerSecret: consumer.consumer_secret,
  });

  const res = await garminFetch(url, {
    method: 'GET',
    headers: {
      'User-Agent': OAUTH_USER_AGENT,
      Authorization: authHeader,
    },
  }, cookies);

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`OAuth1 token request failed: ${res.status} ${text}`);
  }

  const text = await res.text();
  // Response is URL-encoded form data (oauth_token=...&oauth_token_secret=...)
  const params = new URLSearchParams(text);
  return {
    oauth_token: params.get('oauth_token'),
    oauth_token_secret: params.get('oauth_token_secret'),
    mfa_token: params.get('mfa_token') || null,
    domain: DOMAIN,
  };
}

/**
 * Exchange OAuth1 token for OAuth2 access token.
 */
async function exchangeOAuth1ForOAuth2(oauth1, cookies, consumer, isLogin = false) {
  const baseUrl = `https://connectapi.${DOMAIN}/oauth-service/oauth/`;
  const url = `${baseUrl}exchange/user/2.0`;

  // Build form data
  const formData = new URLSearchParams();
  if (isLogin) formData.set('audience', 'GARMIN_CONNECT_MOBILE_ANDROID_DI');
  if (oauth1.mfa_token) formData.set('mfa_token', oauth1.mfa_token);

  // Sign the request with OAuth1 (including the token)
  const authHeader = signOAuth1({
    method: 'POST',
    url,
    params: {},
    consumerKey: consumer.consumer_key,
    consumerSecret: consumer.consumer_secret,
    tokenKey: oauth1.oauth_token,
    tokenSecret: oauth1.oauth_token_secret,
  });

  const res = await garminFetch(url, {
    method: 'POST',
    headers: {
      'User-Agent': OAUTH_USER_AGENT,
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: authHeader,
    },
    body: formData.toString(),
  }, cookies);

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`OAuth2 exchange failed: ${res.status} ${text}`);
  }

  const token = await res.json();
  return setExpirations(token);
}

/**
 * Refresh an OAuth2 token using the stored OAuth1 refresh token.
 */
async function garminRefresh(refreshToken) {
  const oauth1 = refreshTokenToOAuth1(refreshToken);
  const consumer = await getOAuthConsumer();
  const cookies = new CookieJar();

  const oauth2 = await exchangeOAuth1ForOAuth2(oauth1, cookies, consumer, false);
  return { oauth1, oauth2 };
}

// ── Token response builder ──────────────────────────────────────

function buildTokenResponse(oauth1, oauth2) {
  return {
    access_token: oauth2.access_token,
    refresh_token: oauth1ToRefreshToken(oauth1),
    expires_in: oauth2.expires_in,
    refresh_token_expires_in: oauth2.refresh_token_expires_in || null,
    token_type: oauth2.token_type,
    user_id: null, // Garmin doesn't expose a stable user id in the token response
  };
}

// ── CORS + response helpers ─────────────────────────────────────

function corsHeaders(req) {
  const origin = req.headers.get('origin') || '';
  const allowed = ALLOWED_ORIGINS.has(origin) ? origin : '';
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
  };
  if (allowed) headers['Access-Control-Allow-Origin'] = allowed;
  return headers;
}

function jsonResponse(status, body, req, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function errorResponse(status, message, req, extra = {}) {
  return jsonResponse(status, { error: message, ...extra }, req);
}

// ── Vercel serverless entry point ───────────────────────────────

export async function POST(req) {
  try {
    const payload = await req.json();
    if (!payload || typeof payload !== 'object') {
      return errorResponse(400, 'Payload must be an object.', req);
    }

    const action = payload.action;

    if (action === 'login') {
      const { email, password } = payload;
      if (!email || !password) {
        return errorResponse(400, 'Garmin login requires email and password.', req);
      }

      try {
        const result = await garminLogin(email, password);
        if (result.mfa_required) {
          return errorResponse(401, 'MFA required', req, {
            mfa_required: true,
            mfa_method: result.mfa_method,
          });
        }
        return jsonResponse(200, buildTokenResponse(result.oauth1, result.oauth2), req);
      } catch (err) {
        if (err.status === 401) {
          return errorResponse(401, 'Invalid Garmin credentials.', req);
        }
        console.error('Garmin login error:', err.message);
        return errorResponse(502, 'Garmin authentication service unavailable.', req);
      }
    }

    if (action === 'refresh') {
      const { refresh_token } = payload;
      if (!refresh_token) {
        return errorResponse(400, 'Garmin refresh requires refresh_token.', req);
      }

      try {
        const result = await garminRefresh(refresh_token);
        return jsonResponse(200, buildTokenResponse(result.oauth1, result.oauth2), req);
      } catch (err) {
        console.error('Garmin refresh error:', err.message);
        return errorResponse(502, 'Garmin token refresh failed.', req);
      }
    }

    return errorResponse(400, 'Unsupported action. Use "login" or "refresh".', req);
  } catch (err) {
    console.error('Garmin auth handler error:', err.message);
    return errorResponse(500, 'Internal server error.', req);
  }
}

export async function OPTIONS(req) {
  return new Response(null, {
    status: 204,
    headers: corsHeaders(req),
  });
}

export const config = {
  maxDuration: 60,
};