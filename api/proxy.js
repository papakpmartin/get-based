// Privacy-scoped compatibility proxy. A getbased-operated deployment accepts
// only the fixed product operations classified below. User-owned deployments
// retain the generic same-origin path for integrations they operate themselves.

import {
  PROXY_MAX_REQUEST_BYTES,
  PROXY_MAX_RESPONSE_BYTES,
  classifyHostedProxyRequest,
  isAllowedProxyCallerOrigin,
  isAllowedProxyUrl,
  isGetbasedOperatedRelayHost,
  normalizeProxyMethod,
  proxyCorsHeaders as corsHeaders,
  sanitizeProxyHeaders,
  validateOperatedOAuthPayload,
} from '../lib/proxy-policy.js';
import {
  PROXY_MAX_CREDENTIAL_RESPONSE_BYTES,
  capReadableStream,
  fetchWithValidatedRedirects,
  readRequestTextWithCap,
  readResponseTextWithCap,
} from '../lib/proxy-upstream.js';
import { errorCode } from '../lib/error-utils.js';
import { handlePostalGeocode } from './postal-geocode.js';
import { handleCamsRelay } from './cams-relay.js';

const HOSTED_PUBLIC_PAGE_MAX_BYTES = 2 * 1024 * 1024;
/** @type {Promise<typeof import('../lib/proxy-rate-limit.js')> | null} */
let proxyRateLimitModulePromise = null;

// The distributed limiter pulls in Vercel's Node-only Blob client. Keep that
// dependency outside the entrypoint's initialization path so preflight,
// rejected-origin, and method-probe responses remain available even if a
// deployment packages the optional storage transport incorrectly.
function loadProxyRateLimit() {
  proxyRateLimitModulePromise ||= import('../lib/proxy-rate-limit.js');
  return proxyRateLimitModulePromise;
}

export async function handler(req) {
  const operatedHost = isGetbasedOperatedRelayHost(req);
  // Treat Origin as a server-side browser boundary, not merely a response
  // decoration. It prevents another website from driving this credentialed
  // relay. Non-browser clients can forge Origin, so the rate limit below and
  // deployment-level firewall controls remain important defence in depth.
  if (req.method === 'OPTIONS') {
    if (!isAllowedProxyCallerOrigin(req)) {
      return new Response(null, { status: 403, headers: { 'Vary': 'Origin' } });
    }
    return new Response(null, {
      status: 204,
      headers: corsHeaders(req),
    });
  }

  if (!isAllowedProxyCallerOrigin(req)) {
    return new Response(JSON.stringify({ error: 'Origin not allowed.' }), {
      status: 403,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed. Use POST with {url, headers, body?, method?}' }), {
      status: 405,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let rateLimit;
  try {
    const { enforceProxyRateLimit } = await loadProxyRateLimit();
    rateLimit = await enforceProxyRateLimit(req, { allowInstanceFallback: !operatedHost });
  } catch {
    return new Response(JSON.stringify({
      error: 'Proxy rate limit is temporarily unavailable.',
    }), {
      status: 503,
      headers: {
        ...corsHeaders(req),
        'Content-Type': 'application/json',
        'Retry-After': '60',
      },
    });
  }
  if (rateLimit.unavailable) {
    return new Response(JSON.stringify({
      error: 'Proxy rate limit is not configured for this hosted deployment.',
    }), {
      status: 503,
      headers: {
        ...corsHeaders(req),
        'Content-Type': 'application/json',
        'Retry-After': String(rateLimit.retryAfterSeconds),
      },
    });
  }
  if (rateLimit.limited) {
    return new Response(JSON.stringify({
      error: 'Too many proxy requests. Try again later.',
      retryAfterSeconds: rateLimit.retryAfterSeconds,
    }), {
      status: 429,
      headers: {
        ...corsHeaders(req),
        'Content-Type': 'application/json',
        'Retry-After': String(rateLimit.retryAfterSeconds),
      },
    });
  }

  let payload;
  try {
    const rawBody = await readRequestTextWithCap(req, PROXY_MAX_REQUEST_BYTES);
    payload = JSON.parse(rawBody);
  } catch (error) {
    if (errorCode(error) === 'PROXY_REQUEST_TOO_LARGE') {
      return new Response(JSON.stringify({ error: 'Proxy request body too large' }), {
        status: 413,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return new Response(JSON.stringify({ error: 'Proxy payload must be an object' }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  const selectedOperations = [
    payload.wearable_runtime_config === true,
    Boolean(payload.oura_token_exchange),
    Boolean(payload.oura_token_refresh),
    Boolean(payload.withings_token_exchange),
    Boolean(payload.withings_token_refresh),
    Boolean(payload.ultrahuman_token_exchange),
    Boolean(payload.ultrahuman_token_refresh),
    Boolean(payload.whoop_token_exchange),
    Boolean(payload.whoop_token_refresh),
    Boolean(payload.polar_token_exchange),
    Boolean(payload.polar_token_refresh),
    Boolean(payload.google_health_token_exchange),
    Boolean(payload.google_health_token_refresh),
    Boolean(payload.garmin_credentials),
    Boolean(payload.garmin_token_refresh),
    payload.meteo === 'cams',
    payload.meteo === 'postal_geocode',
    Object.prototype.hasOwnProperty.call(payload, 'url'),
  ].filter(Boolean).length;
  if (selectedOperations !== 1) {
    return new Response(JSON.stringify({ error: 'Proxy request must select exactly one operation' }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  if (operatedHost && payload.meteo === 'postal_geocode') {
    return new Response(JSON.stringify({
      code: 'HOSTED_LOCATION_RELAY_DISABLED',
      error: 'The hosted app does not accept plaintext location relay requests.',
    }), {
      status: 403,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  const selfHostOnlyOperation = [
    'ultrahuman_token_exchange',
    'ultrahuman_token_refresh',
    'whoop_token_exchange',
    'whoop_token_refresh',
    'google_health_token_exchange',
    'google_health_token_refresh',
  ].find(field => payload[field]);
  if (operatedHost && selfHostOnlyOperation) {
    return new Response(JSON.stringify({
      code: 'SELF_HOST_ONLY_PROVIDER',
      error: 'This provider is available only on a user-controlled deployment configured with its own OAuth application.',
    }), {
      status: 403,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  const operatedOAuthError = operatedHost ? validateOperatedOAuthPayload(payload) : '';
  if (operatedOAuthError) {
    return new Response(JSON.stringify({
      code: 'HOSTED_OAUTH_REQUEST_BLOCKED',
      error: operatedOAuthError,
    }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  // ─── Self-host OAuth client_id overrides ───────────────────────
  // Surfaces *_CLIENT_ID env vars to the browser so self-hosters can run
  // their own OAuth apps without patching js/wearable-adapters.js. Google
  // Health is enabled only when this deployment explicitly opts in and
  // provides both credentials; only the boolean capability and public client
  // ID reach the browser.
  if (payload.wearable_runtime_config) {
    const env = (typeof process !== 'undefined' && process.env) ? process.env : {};
    const overrides = {};
    for (const [key, id] of [
      ['OURA_CLIENT_ID', 'oura'],
      ['WITHINGS_CLIENT_ID', 'withings'],
      ['ULTRAHUMAN_CLIENT_ID', 'ultrahuman'],
      ['POLAR_CLIENT_ID', 'polar'],
      ['WHOOP_CLIENT_ID', 'whoop'],
      ['FITBIT_CLIENT_ID', 'fitbit'],
      ['GOOGLE_HEALTH_CLIENT_ID', 'google_health'],
    ]) {
      if (operatedHost && ['ultrahuman', 'whoop', 'google_health'].includes(id)) continue;
      const v = env[key];
      if (typeof v === 'string' && v.trim()) overrides[id] = v.trim();
    }
    const hasEnv = key => typeof env[key] === 'string' && env[key].trim();
    const configured = {
      google_health: !operatedHost && env.GOOGLE_HEALTH_ENABLED === 'true'
        && Boolean(hasEnv('GOOGLE_HEALTH_CLIENT_ID') && hasEnv('GOOGLE_HEALTH_CLIENT_SECRET')),
      ultrahuman: !operatedHost && env.ULTRAHUMAN_ENABLED === 'true'
        && Boolean(hasEnv('ULTRAHUMAN_CLIENT_ID') && hasEnv('ULTRAHUMAN_CLIENT_SECRET')),
      whoop: !operatedHost && env.WHOOP_ENABLED === 'true'
        && Boolean(hasEnv('WHOOP_CLIENT_ID') && hasEnv('WHOOP_CLIENT_SECRET')),
    };
    return new Response(JSON.stringify({ overrides, configured }), {
      status: 200,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  // ─── Oura OAuth2 server-side flow ───────────────────────────────
  // Client-secret-bearing requests — secret never reaches the browser.
  // Single place in the codebase that reads OURA_CLIENT_SECRET.
  if (payload.oura_token_exchange || payload.oura_token_refresh) {
    return handleOuraTokenRequest(payload, req);
  }

  // ─── Withings OAuth2 server-side flow ───────────────────────────
  // Same pattern as Oura. Withings's token endpoint demands
  // `action=requesttoken` / `requesttoken2` in the form body alongside the
  // grant params; single place that reads WITHINGS_CLIENT_SECRET.
  if (payload.withings_token_exchange || payload.withings_token_refresh) {
    return handleWithingsTokenRequest(payload, req);
  }

  // ─── Ultrahuman OAuth2 server-side flow ─────────────────────────
  // Confidential client (has client_secret). Token endpoint at
  // partner.ultrahuman.com/api/partners/oauth/token.
  if (payload.ultrahuman_token_exchange || payload.ultrahuman_token_refresh) {
    return handleUltrahumanTokenRequest(payload, req);
  }

  // ─── WHOOP OAuth2 server-side flow ─────────────────────────────
  // WHOOP is a confidential client: the deployment secret is injected here
  // for authorization-code exchange and refresh.
  if (payload.whoop_token_exchange || payload.whoop_token_refresh) {
    return handleWhoopTokenRequest(payload, req);
  }

  // ─── Polar AccessLink OAuth2 server-side flow ───────────────────
  // Confidential client. Token endpoint at polarremote.com/v2/oauth2/token,
  // authentication via Basic auth (base64 clientId:clientSecret).
  if (payload.polar_token_exchange || payload.polar_token_refresh) {
    return handlePolarTokenRequest(payload, req);
  }

  // ─── Google Health OAuth2 server-side flow ─────────────────────
  // Google Health uses Google's confidential Web Server OAuth client. The
  // deployment's client secret is injected here and is never returned to the
  // browser or stored in profile data.
  if (payload.google_health_token_exchange || payload.google_health_token_refresh) {
    return handleGoogleHealthTokenRequest(payload, req);
  }

  // ─── Garmin Connect server-side auth flow ────────────────────────
  // Garmin's OAuth1 → OAuth2 exchange is driven by a Python serverless function
  // (api/garmin_auth.py) that uses the `garth` library. The JS proxy simply
  // forwards credential and refresh payloads so email/password never reach
  // the browser; generic connect/connectapi data requests pass through below.
  if (payload.garmin_credentials || payload.garmin_token_refresh) {
    return handleGarminAuthRequest(payload, req);
  }

  // ─── CAMS atmosphere relay (getbased-uvdata) ────────────────────
  // Browser fetches `{meteo: 'cams', latitude, longitude, time}`; we
  // forward to the maintainer-run getbased-uvdata instance with a
  // server-injected bearer so the token never reaches the client.
  // Self-hosters bypass this entirely via the `selfhost` Sun Data
  // Source mode (URL + bearer entered in Settings → Light & Sun).
  if (payload.meteo === 'cams') {
    return handleCamsRelay(payload, req, { operatedHost });
  }
  if (payload.meteo === 'postal_geocode') {
    return handlePostalGeocode(payload, req, { corsHeaders, proxyUpstreamErrorResponse });
  }

  const { url, headers, body, method: upstreamMethod } = payload;

  if (!url || !isAllowedProxyUrl(url)) {
    return new Response(JSON.stringify({ error: 'URL not allowed' }), {
      status: 403,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  const fetchMethod = normalizeProxyMethod(upstreamMethod);
  if (!fetchMethod) {
    return new Response(JSON.stringify({ error: 'Proxy method not allowed' }), {
      status: 405,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  const safeHeaders = sanitizeProxyHeaders(headers);
  if (!safeHeaders.ok) {
    return new Response(JSON.stringify({ error: safeHeaders.error }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }
  let hostedOperation = '';
  if (operatedHost) {
    const hostedRequest = classifyHostedProxyRequest({
      url,
      method: fetchMethod,
      headers: safeHeaders.headers,
      body,
      purpose: payload.proxy_purpose,
    });
    if (!hostedRequest.ok) {
      return new Response(JSON.stringify({
        code: 'HOSTED_PROXY_OPERATION_BLOCKED',
        error: hostedRequest.error,
      }), {
        status: 403,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    hostedOperation = hostedRequest.operation;
  }

  try {
    const reqHeaders = { ...safeHeaders.headers };
    const hasCT = Object.keys(reqHeaders).some(k => k.toLowerCase() === 'content-type');
    if (fetchMethod !== 'GET' && !hasCT) reqHeaders['Content-Type'] = 'application/json';
    const fetchOpts = {
      method: fetchMethod,
      headers: reqHeaders,
    };
    if (fetchMethod !== 'GET' && body) {
      fetchOpts.body = typeof body === 'string' ? body : JSON.stringify(body);
    }
    const upstreamRes = await fetchWithValidatedRedirects(url, fetchOpts, { signal: req.signal });

    // For non-streaming responses or errors, forward as-is
    const contentType = upstreamRes.headers.get('content-type') || '';
    const isStream = contentType.includes('text/event-stream') || contentType.includes('application/x-ndjson');

    if (hostedOperation === 'public-page'
        && !/^(?:text\/(?:html|plain)|application\/(?:xhtml\+xml|json))(?:;|$)/i.test(contentType)) {
      try { await upstreamRes.body?.cancel?.(); } catch {}
      return new Response(JSON.stringify({ error: 'Product URL did not return a readable public page' }), {
        status: 415,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }

    if (!isStream) {
      const responseBody = await readResponseTextWithCap(
        upstreamRes,
        hostedOperation === 'public-page' ? HOSTED_PUBLIC_PAGE_MAX_BYTES : PROXY_MAX_RESPONSE_BYTES,
      );
      return new Response(responseBody, {
        status: upstreamRes.status,
        headers: {
          ...corsHeaders(req),
          'Content-Type': contentType || 'application/json',
        },
      });
    }

    // Stream SSE response through
    return new Response(capReadableStream(upstreamRes.body, PROXY_MAX_RESPONSE_BYTES), {
      status: upstreamRes.status,
      headers: {
        ...corsHeaders(req),
        'Content-Type': contentType,
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    });
  } catch (e) {
    return proxyUpstreamErrorResponse(req, e);
  }
}

// Use Vercel's explicit Web-standard Node.js function contract. A bare
// default function is also the legacy (request, response) handler shape; when
// it returns a Web Response instead of ending the legacy response, the
// platform can leave the invocation open until timeout.
export default { fetch: handler };

function proxyUpstreamErrorResponse(req, error, fallback = 'Upstream request failed') {
  const code = error?.code;
  const dnsBlocked = code === 'PROXY_DNS_BLOCKED';
  const timedOut = code === 'PROXY_UPSTREAM_TIMEOUT';
  const knownMessages = new Map([
    ['PROXY_REDIRECT_BLOCKED', 'Proxy redirect target not allowed'],
    ['PROXY_REDIRECT_LIMIT', 'Proxy redirect limit exceeded'],
    ['PROXY_CROSS_ORIGIN_BODY_REDIRECT', 'Cross-origin proxy redirects with a request body are not allowed'],
    ['PROXY_RESPONSE_TOO_LARGE', 'Proxy response exceeds size cap'],
  ]);
  const message = dnsBlocked
    ? 'URL not allowed'
    : timedOut
      ? 'Proxy upstream timed out'
      : knownMessages.get(code) || fallback;
  return new Response(JSON.stringify({ error: message }), {
    status: dnsBlocked ? 403 : (timedOut ? 504 : 502),
    headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
  });
}

async function relayGuardedText(url, options, req, fallback) {
  try {
    const response = await fetchWithValidatedRedirects(url, options, { signal: req.signal });
    const body = await readResponseTextWithCap(
      response,
      PROXY_MAX_CREDENTIAL_RESPONSE_BYTES,
    );
    return new Response(body, {
      status: response.status,
      headers: {
        ...corsHeaders(req),
        'Content-Type': response.headers.get('content-type') || 'application/json',
      },
    });
  } catch (error) {
    return proxyUpstreamErrorResponse(req, error, fallback);
  }
}

// ─── Oura token handler ────────────────────────────────────────────
// Payloads:
//   { oura_token_exchange: { code, redirect_uri, client_id } }
//   { oura_token_refresh:  { refresh_token, client_id } }
// client_id is sent from the browser (public value) so the proxy stays
// provider-agnostic — the secret is the only thing kept server-side.
async function handleOuraTokenRequest(payload, req) {
  const secret = typeof process !== 'undefined' ? process.env?.OURA_CLIENT_SECRET : undefined;
  if (!secret) {
    return new Response(JSON.stringify({ error: 'OURA_CLIENT_SECRET not configured on this deployment' }), {
      status: 500, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form;
  if (payload.oura_token_exchange) {
    const { code, redirect_uri, client_id } = payload.oura_token_exchange;
    if (!code || !redirect_uri || !client_id) {
      return new Response(JSON.stringify({ error: 'oura_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'authorization_code',
      code, redirect_uri, client_id, client_secret: secret,
    });
  } else {
    const { refresh_token, client_id } = payload.oura_token_refresh;
    if (!refresh_token || !client_id) {
      return new Response(JSON.stringify({ error: 'oura_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token, client_id, client_secret: secret,
    });
  }

  return relayGuardedText('https://api.ouraring.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }, req, 'Oura token endpoint unavailable');
}

// ─── Withings token handler ────────────────────────────────────────
// Payloads:
//   { withings_token_exchange: { code, redirect_uri, client_id } }
//   { withings_token_refresh:  { refresh_token, client_id } }
// Withings's token endpoint is POST wbsapi.withings.net/v2/oauth2 with
// `action=requesttoken` in the body — same action for both the initial
// authorization-code exchange and refresh-token rotation (validated end-to-end
// in v1.22.0 → v1.31.0). The grant_type field distinguishes the two flows.
async function handleWithingsTokenRequest(payload, req) {
  const secret = typeof process !== 'undefined' ? process.env?.WITHINGS_CLIENT_SECRET : undefined;
  if (!secret) {
    return new Response(JSON.stringify({ error: 'WITHINGS_CLIENT_SECRET not configured on this deployment' }), {
      status: 500, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form;
  if (payload.withings_token_exchange) {
    const { code, redirect_uri, client_id } = payload.withings_token_exchange;
    if (!code || !redirect_uri || !client_id) {
      return new Response(JSON.stringify({ error: 'withings_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      action: 'requesttoken',
      grant_type: 'authorization_code',
      client_id, client_secret: secret,
      code, redirect_uri,
    });
  } else {
    const { refresh_token, client_id } = payload.withings_token_refresh;
    if (!refresh_token || !client_id) {
      return new Response(JSON.stringify({ error: 'withings_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      action: 'requesttoken',
      grant_type: 'refresh_token',
      client_id, client_secret: secret,
      refresh_token,
    });
  }

  return relayGuardedText('https://wbsapi.withings.net/v2/oauth2', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }, req, 'Withings token endpoint unavailable');
}

// ─── Ultrahuman token handler ──────────────────────────────────────
async function handleUltrahumanTokenRequest(payload, req) {
  const env = typeof process !== 'undefined' ? process.env || {} : {};
  const clientId = typeof env.ULTRAHUMAN_CLIENT_ID === 'string' ? env.ULTRAHUMAN_CLIENT_ID.trim() : '';
  const secret = env.ULTRAHUMAN_CLIENT_SECRET;
  if (env.ULTRAHUMAN_ENABLED !== 'true' || !clientId || typeof secret !== 'string' || !secret.trim()) {
    return new Response(JSON.stringify({ error: 'Ultrahuman is disabled on this deployment' }), {
      status: 503, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form;
  if (payload.ultrahuman_token_exchange) {
    const { code, redirect_uri, client_id: requestedClientId } = payload.ultrahuman_token_exchange;
    if (!code || !redirect_uri || !requestedClientId) {
      return new Response(JSON.stringify({ error: 'ultrahuman_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    if (requestedClientId !== clientId) {
      return new Response(JSON.stringify({ error: 'Ultrahuman client_id does not match this deployment' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId, client_secret: secret, code, redirect_uri,
    });
  } else {
    const { refresh_token, client_id: requestedClientId } = payload.ultrahuman_token_refresh;
    if (!refresh_token || !requestedClientId) {
      return new Response(JSON.stringify({ error: 'ultrahuman_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    if (requestedClientId !== clientId) {
      return new Response(JSON.stringify({ error: 'Ultrahuman client_id does not match this deployment' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: clientId, client_secret: secret, refresh_token,
    });
  }

  return relayGuardedText('https://partner.ultrahuman.com/api/partners/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }, req, 'Ultrahuman token endpoint unavailable');
}

// ─── WHOOP token handler ──────────────────────────────────────────
async function handleWhoopTokenRequest(payload, req) {
  const env = typeof process !== 'undefined' ? process.env || {} : {};
  const clientId = typeof env.WHOOP_CLIENT_ID === 'string' ? env.WHOOP_CLIENT_ID.trim() : '';
  const secret = env.WHOOP_CLIENT_SECRET;
  if (env.WHOOP_ENABLED !== 'true' || !clientId || typeof secret !== 'string' || !secret.trim()) {
    return new Response(JSON.stringify({ error: 'WHOOP is disabled on this deployment' }), {
      status: 503, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form;
  if (payload.whoop_token_exchange) {
    const { code, redirect_uri, client_id: requestedClientId } = payload.whoop_token_exchange;
    if (!code || !redirect_uri || !requestedClientId) {
      return new Response(JSON.stringify({ error: 'whoop_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    if (requestedClientId !== clientId) {
      return new Response(JSON.stringify({ error: 'WHOOP client_id does not match this deployment' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri,
      client_id: clientId, client_secret: secret,
    });
  } else {
    const { refresh_token, client_id: requestedClientId } = payload.whoop_token_refresh;
    if (!refresh_token || !requestedClientId) {
      return new Response(JSON.stringify({ error: 'whoop_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    if (requestedClientId !== clientId) {
      return new Response(JSON.stringify({ error: 'WHOOP client_id does not match this deployment' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'refresh_token', refresh_token,
      client_id: clientId, client_secret: secret, scope: 'offline',
    });
  }

  return relayGuardedText('https://api.prod.whoop.com/oauth/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }, req, 'WHOOP token endpoint unavailable');
}

// ─── Polar token handler ───────────────────────────────────────────
// Polar AccessLink requires HTTP Basic auth (base64 of client_id:client_secret)
// on every token call. Single place that reads POLAR_CLIENT_SECRET.
async function handlePolarTokenRequest(payload, req) {
  const secret = typeof process !== 'undefined' ? process.env?.POLAR_CLIENT_SECRET : undefined;
  if (!secret) {
    return new Response(JSON.stringify({ error: 'POLAR_CLIENT_SECRET not configured on this deployment' }), {
      status: 500, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form, clientId;
  if (payload.polar_token_exchange) {
    const { code, redirect_uri, client_id } = payload.polar_token_exchange;
    if (!code || !redirect_uri || !client_id) {
      return new Response(JSON.stringify({ error: 'polar_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    clientId = client_id;
    form = new URLSearchParams({
      grant_type: 'authorization_code',
      code, redirect_uri,
    });
  } else {
    const { refresh_token, client_id } = payload.polar_token_refresh;
    if (!refresh_token || !client_id) {
      return new Response(JSON.stringify({ error: 'polar_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    clientId = client_id;
    form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token,
    });
  }

  const basicAuth = 'Basic ' + btoa(`${clientId}:${secret}`);
  return relayGuardedText('https://polarremote.com/v2/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json;charset=UTF-8',
      'Authorization': basicAuth,
    },
    body: form.toString(),
  }, req, 'Polar token endpoint unavailable');
}

// ─── Google Health token handler ─────────────────────────────────
// Payloads:
//   { google_health_token_exchange: { code, redirect_uri, client_id } }
//   { google_health_token_refresh:  { refresh_token, client_id } }
async function handleGoogleHealthTokenRequest(payload, req) {
  const env = typeof process !== 'undefined' ? process.env : {};
  const secret = env?.GOOGLE_HEALTH_CLIENT_SECRET;
  const clientId = env?.GOOGLE_HEALTH_CLIENT_ID;
  if (env?.GOOGLE_HEALTH_ENABLED !== 'true' || !secret || !clientId) {
    return new Response(JSON.stringify({ error: 'Google Health is disabled on this deployment' }), {
      status: 503, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  let form;
  if (payload.google_health_token_exchange) {
    const { code, redirect_uri, client_id } = payload.google_health_token_exchange;
    if (!code || !redirect_uri || !client_id) {
      return new Response(JSON.stringify({ error: 'google_health_token_exchange requires code, redirect_uri, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'authorization_code',
      code, redirect_uri, client_id, client_secret: secret,
    });
  } else {
    const { refresh_token, client_id } = payload.google_health_token_refresh;
    if (!refresh_token || !client_id) {
      return new Response(JSON.stringify({ error: 'google_health_token_refresh requires refresh_token, client_id' }), {
        status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
      });
    }
    form = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token, client_id, client_secret: secret,
    });
  }

  return relayGuardedText('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  }, req, 'Google OAuth token endpoint unavailable');
}

// ─── Garmin auth (inlined — no separate function) ────────────────
// Ports garth library's OAuth1 → OAuth2 exchange directly into the proxy
// to avoid Vercel deployment protection blocking internal function calls.
// Flow: SSO login → service ticket → OAuth1 token (HMAC-SHA1) → OAuth2 exchange.

import crypto from 'node:crypto';

const GARMIN_CLIENT_ID = 'GCM_ANDROID_DARK';
const GARMIN_OAUTH_CONSUMER_URL = 'https://thegarth.s3.amazonaws.com/oauth_consumer.json';
const GARMIN_DOMAIN = 'garmin.com';
const GARMIN_SSO_UA =
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) ' +
  'AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';
const GARMIN_OAUTH_UA = 'com.garmin.android.apps.connectmobile';

let _garminConsumer = null;
async function getGarminConsumer() {
  if (_garminConsumer) return _garminConsumer;
  const res = await fetch(GARMIN_OAUTH_CONSUMER_URL);
  if (!res.ok) throw new Error(`Failed to fetch Garmin OAuth consumer: ${res.status}`);
  _garminConsumer = await res.json();
  return _garminConsumer;
}

class GarminCookieJar {
  constructor() { this.map = new Map(); }
  capture(headers) {
    if (!headers) return;
    const arr = Array.isArray(headers) ? headers : [headers];
    for (const raw of arr) {
      if (!raw) continue;
      const part = raw.split(';')[0].trim();
      const eq = part.indexOf('=');
      if (eq > 0) this.map.set(part.slice(0, eq).trim(), part.slice(eq + 1).trim());
    }
  }
  header() {
    return this.map.size ? Array.from(this.map, ([k, v]) => `${k}=${v}`).join('; ') : undefined;
  }
}

function garminPercentEncode(str) {
  return encodeURIComponent(str)
    .replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function signGarminOAuth1({ method, url, consumerKey, consumerSecret, tokenKey, tokenSecret }) {
  const params = {
    oauth_consumer_key: consumerKey,
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp: String(Math.floor(Date.now() / 1000)),
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_version: '1.0',
  };
  if (tokenKey) params.oauth_token = tokenKey;

  const encoded = Object.entries(params)
    .map(([k, v]) => [garminPercentEncode(String(k)), garminPercentEncode(String(v))])
    .sort(([a1, a2], [b1, b2]) => (a1 < b1 ? -1 : a1 > b1 ? 1 : a2 < b2 ? -1 : a2 > b2 ? 1 : 0));
  const paramString = encoded.map(([k, v]) => `${k}=${v}`).join('&');
  const baseUrl = url.split('#')[0].split('?')[0];
  const signatureBase = [method.toUpperCase(), garminPercentEncode(baseUrl), garminPercentEncode(paramString)].join('&');
  const signingKey = `${garminPercentEncode(consumerSecret)}&${garminPercentEncode(tokenSecret || '')}`;
  const signature = crypto.createHmac('sha1', signingKey).update(signatureBase).digest('base64');
  const authParams = { ...params, oauth_signature: signature };
  return 'OAuth ' + Object.entries(authParams).map(([k, v]) => `${garminPercentEncode(k)}="${garminPercentEncode(String(v))}"`).join(',');
}

async function garminFetch(url, options, cookies, extraHeaders = {}) {
  const cookieHeader = cookies.header();
  const headers = { ...extraHeaders };
  if (cookieHeader) headers.Cookie = cookieHeader;
  const res = await fetch(url, {
    ...options,
    headers: { ...headers, ...(options?.headers || {}) },
    redirect: 'manual',
  });
  const setCookie = res.headers.getsetcookie?.();
  if (setCookie) cookies.capture(setCookie);
  else { const sc = res.headers.get('set-cookie'); if (sc) cookies.capture(sc); }
  return res;
}

function oauth1ToRefreshToken(oauth1) {
  return Buffer.from(JSON.stringify({
    oauth_token: oauth1.oauth_token,
    oauth_token_secret: oauth1.oauth_token_secret,
  })).toString('base64');
}

function refreshTokenToOAuth1(refreshToken) {
  return JSON.parse(Buffer.from(refreshToken, 'base64').toString('utf-8'));
}

async function garminLogin(email, password) {
  const cookies = new GarminCookieJar();
  console.log('[garmin] step 0: fetching OAuth consumer...');
  const consumer = await getGarminConsumer();
  console.log('[garmin] step 0: got consumer key:', consumer?.consumer_key?.slice(0, 8) + '...');
  const serviceUrl = `https://mobile.integration.${GARMIN_DOMAIN}/gcm/android`;

  // Step 1: GET SSO sign-in page (sets cookies)
  console.log('[garmin] step 1: GET SSO sign-in page...');
  const ssoUrl = new URL(`https://sso.${GARMIN_DOMAIN}/mobile/sso/en/sign-in`);
  ssoUrl.searchParams.set('clientId', GARMIN_CLIENT_ID);
  const ssoRes = await garminFetch(ssoUrl.href, { method: 'GET' }, cookies, {
    'User-Agent': GARMIN_SSO_UA,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Site': 'none',
  });
  console.log('[garmin] step 1: SSO page status:', ssoRes.status, 'cookies:', cookies.map.size);

  // Step 2: POST credentials to SSO login API
  console.log('[garmin] step 2: POST credentials to SSO login...');
  const loginUrl = new URL(`https://sso.${GARMIN_DOMAIN}/mobile/api/login`);
  loginUrl.searchParams.set('clientId', GARMIN_CLIENT_ID);
  loginUrl.searchParams.set('locale', 'en-US');
  loginUrl.searchParams.set('service', serviceUrl);

  const loginRes = await garminFetch(loginUrl.href, {
    method: 'POST',
    headers: {
      'User-Agent': GARMIN_SSO_UA,
      'Content-Type': 'application/json',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: JSON.stringify({ username: email, password, rememberMe: false, captchaToken: '' }),
  }, cookies);
  console.log('[garmin] step 2: login response status:', loginRes.status, 'cookies:', cookies.map.size);

  const loginText = await loginRes.text();
  let loginBody;
  try { loginBody = JSON.parse(loginText); } catch { loginBody = {}; }
  console.log('[garmin] step 2: response type:', loginBody?.responseStatus?.type, 'has ticket:', !!loginBody?.serviceTicketId, 'status:', loginRes.status, 'bodyLen:', loginText.length, 'bodyPreview:', loginText.slice(0, 200));
  const respType = loginBody?.responseStatus?.type;

  if (respType === 'SUCCESSFUL') {
    const ticket = loginBody.serviceTicketId;
    // Best-effort: GET embed page for Cloudflare LB cookie
    try {
      const embedUrl = new URL(`https://sso.${GARMIN_DOMAIN}/portal/sso/embed`);
      await garminFetch(embedUrl.href, { method: 'GET' }, cookies, {
        'User-Agent': GARMIN_SSO_UA,
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        Referer: `https://sso.${GARMIN_DOMAIN}/`,
      });
    } catch { /* best-effort */ }

    // Step 3: Get OAuth1 token via service ticket
    const oauthBaseUrl = `https://connectapi.${GARMIN_DOMAIN}/oauth-service/oauth/`;
    const preauthUrl = `${oauthBaseUrl}preauthorized?ticket=${encodeURIComponent(ticket)}&login-url=${encodeURIComponent(serviceUrl)}&accepts-mfa-tokens=true`;
    const authHeader1 = signGarminOAuth1({
      method: 'GET', url: preauthUrl,
      consumerKey: consumer.consumer_key, consumerSecret: consumer.consumer_secret,
    });
    const oauth1Res = await garminFetch(preauthUrl, {
      method: 'GET',
      headers: { 'User-Agent': GARMIN_OAUTH_UA, Authorization: authHeader1 },
    }, cookies);
    if (!oauth1Res.ok) {
      const text = await oauth1Res.text().catch(() => '');
      const err = new Error(`Garmin OAuth1 token failed: ${oauth1Res.status} ${text.slice(0, 200)}`);
      err.garminStep = 'oauth1';
      throw err;
    }
    const oauth1Params = new URLSearchParams(await oauth1Res.text());
    const oauth1 = {
      oauth_token: oauth1Params.get('oauth_token'),
      oauth_token_secret: oauth1Params.get('oauth_token_secret'),
      mfa_token: oauth1Params.get('mfa_token') || null,
    };

    // Step 4: Exchange OAuth1 for OAuth2
    const exchangeUrl = `${oauthBaseUrl}exchange/user/2.0`;
    const formData = new URLSearchParams();
    formData.set('audience', 'GARMIN_CONNECT_MOBILE_ANDROID_DI');
    if (oauth1.mfa_token) formData.set('mfa_token', oauth1.mfa_token);
    const authHeader2 = signGarminOAuth1({
      method: 'POST', url: exchangeUrl,
      consumerKey: consumer.consumer_key, consumerSecret: consumer.consumer_secret,
      tokenKey: oauth1.oauth_token, tokenSecret: oauth1.oauth_token_secret,
    });
    const exchangeRes = await garminFetch(exchangeUrl, {
      method: 'POST',
      headers: {
        'User-Agent': GARMIN_OAUTH_UA,
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: authHeader2,
      },
      body: formData.toString(),
    }, cookies);
    if (!exchangeRes.ok) {
      const text = await exchangeRes.text().catch(() => '');
      const err = new Error(`Garmin OAuth2 exchange failed: ${exchangeRes.status} ${text.slice(0, 200)}`);
      err.garminStep = 'oauth2';
      throw err;
    }
    const oauth2 = await exchangeRes.json();
    return { oauth1, oauth2 };
  }

  if (respType === 'MFA_REQUIRED') {
    const mfaInfo = loginBody?.customerMfaInfo || {};
    console.log('[garmin] MFA required, method:', mfaInfo.mfaLastMethodUsed || 'email');
    return {
      mfa_required: true,
      mfa_method: mfaInfo.mfaLastMethodUsed || 'email',
      session: Buffer.from(JSON.stringify({
        cookies: Array.from(cookies.map.entries()),
        login_params: {
          clientId: GARMIN_CLIENT_ID,
          locale: 'en-US',
          service: serviceUrl,
        },
      })).toString('base64'),
    };
  }

  if (loginRes.status === 401 || respType === 'INVALID_CREDENTIALS' || respType === 'INVALID_USERNAME_PASSWORD') {
    console.log('[garmin] invalid credentials');
    const err = new Error('Invalid Garmin credentials.');
    err.status = 401;
    err.garminStep = 'sso_login';
    throw err;
  }

  const detail = loginBody?.responseStatus?.message || respType || 'unknown';
  console.error('[garmin] SSO error:', detail, 'full body:', JSON.stringify(loginBody).slice(0, 500));
  const err = new Error(`Garmin SSO error: ${detail} (body: ${JSON.stringify(loginBody).slice(0, 300)})`);
  err.status = 502;
  err.garminStep = 'sso_login';
  throw err;
}

async function garminRefreshToken(refreshToken) {
  const oauth1 = refreshTokenToOAuth1(refreshToken);
  const consumer = await getGarminConsumer();
  const cookies = new GarminCookieJar();
  const oauthBaseUrl = `https://connectapi.${GARMIN_DOMAIN}/oauth-service/oauth/`;
  const exchangeUrl = `${oauthBaseUrl}exchange/user/2.0`;
  const authHeader = signGarminOAuth1({
    method: 'POST', url: exchangeUrl,
    consumerKey: consumer.consumer_key, consumerSecret: consumer.consumer_secret,
    tokenKey: oauth1.oauth_token, tokenSecret: oauth1.oauth_token_secret,
  });
  const res = await garminFetch(exchangeUrl, {
    method: 'POST',
    headers: {
      'User-Agent': GARMIN_OAUTH_UA,
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: authHeader,
    },
  }, cookies);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Garmin token refresh failed: ${res.status} ${text}`);
  }
  return await res.json();
}

async function garminCompleteMfa(sessionState, mfaCode) {
  const state = JSON.parse(Buffer.from(sessionState, 'base64').toString('utf-8'));
  const cookies = new GarminCookieJar();
  cookies.map = new Map(state.cookies);
  const loginParams = state.login_params;
  const consumer = await getGarminConsumer();

  // POST MFA code to SSO verifyCode endpoint
  const mfaUrl = new URL(`https://sso.${GARMIN_DOMAIN}/mobile/api/mfa/verifyCode`);
  for (const [k, v] of Object.entries(loginParams)) mfaUrl.searchParams.set(k, v);

  const mfaRes = await garminFetch(mfaUrl.href, {
    method: 'POST',
    headers: {
      'User-Agent': GARMIN_SSO_UA,
      'Content-Type': 'application/json',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
    },
    body: JSON.stringify({
      mfaMethod: state.mfa_method || 'email',
      mfaVerificationCode: mfaCode,
      rememberMyBrowser: false,
      reconsentList: [],
      mfaSetup: false,
    }),
  }, cookies);

  const mfaBody = await mfaRes.json().catch(() => ({}));
  const respType = mfaBody?.responseStatus?.type;

  if (respType !== 'SUCCESSFUL') {
    const detail = mfaBody?.responseStatus?.message || respType || 'unknown';
    const err = new Error(`Garmin MFA verification failed: ${detail}`);
    err.status = 401;
    throw err;
  }

  const ticket = mfaBody.serviceTicketId;
  const serviceUrl = loginParams.service;

  // Best-effort: GET embed page for Cloudflare LB cookie
  try {
    const embedUrl = new URL(`https://sso.${GARMIN_DOMAIN}/portal/sso/embed`);
    await garminFetch(embedUrl.href, { method: 'GET' }, cookies, {
      'User-Agent': GARMIN_SSO_UA,
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      Referer: `https://sso.${GARMIN_DOMAIN}/`,
    });
  } catch { /* best-effort */ }

  // Step 3: Get OAuth1 token via service ticket
  const oauthBaseUrl = `https://connectapi.${GARMIN_DOMAIN}/oauth-service/oauth/`;
  const preauthUrl = `${oauthBaseUrl}preauthorized?ticket=${encodeURIComponent(ticket)}&login-url=${encodeURIComponent(serviceUrl)}&accepts-mfa-tokens=true`;
  const authHeader1 = signGarminOAuth1({
    method: 'GET', url: preauthUrl,
    consumerKey: consumer.consumer_key, consumerSecret: consumer.consumer_secret,
  });
  const oauth1Res = await garminFetch(preauthUrl, {
    method: 'GET',
    headers: { 'User-Agent': GARMIN_OAUTH_UA, Authorization: authHeader1 },
  }, cookies);
  if (!oauth1Res.ok) {
    const text = await oauth1Res.text().catch(() => '');
    throw new Error(`Garmin OAuth1 token failed: ${oauth1Res.status} ${text}`);
  }
  const oauth1Params = new URLSearchParams(await oauth1Res.text());
  const oauth1 = {
    oauth_token: oauth1Params.get('oauth_token'),
    oauth_token_secret: oauth1Params.get('oauth_token_secret'),
    mfa_token: oauth1Params.get('mfa_token') || null,
  };

  // Step 4: Exchange OAuth1 for OAuth2
  const exchangeUrl = `${oauthBaseUrl}exchange/user/2.0`;
  const formData = new URLSearchParams();
  formData.set('audience', 'GARMIN_CONNECT_MOBILE_ANDROID_DI');
  if (oauth1.mfa_token) formData.set('mfa_token', oauth1.mfa_token);
  const authHeader2 = signGarminOAuth1({
    method: 'POST', url: exchangeUrl,
    consumerKey: consumer.consumer_key, consumerSecret: consumer.consumer_secret,
    tokenKey: oauth1.oauth_token, tokenSecret: oauth1.oauth_token_secret,
  });
  const exchangeRes = await garminFetch(exchangeUrl, {
    method: 'POST',
    headers: {
      'User-Agent': GARMIN_OAUTH_UA,
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: authHeader2,
    },
    body: formData.toString(),
  }, cookies);
  if (!exchangeRes.ok) {
    const text = await exchangeRes.text().catch(() => '');
    throw new Error(`Garmin OAuth2 exchange failed: ${exchangeRes.status} ${text}`);
  }
  const oauth2 = await exchangeRes.json();
  return { oauth1, oauth2 };
}

async function handleGarminAuthRequest(payload, req) {
  // Three action types: login, mfa_verify, refresh
  const action = payload.garmin_credentials ? 'login'
    : payload.garmin_mfa ? 'mfa_verify'
    : 'refresh';
  const input = payload.garmin_credentials || payload.garmin_mfa || payload.garmin_token_refresh;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return new Response(JSON.stringify({ error: `garmin_${action === 'login' ? 'credentials' : 'token_refresh'} requires an object payload` }), {
      status: 400,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json' },
    });
  }

  // Validate required fields per action
  if (action === 'login') {
    if (!input.email || !input.password)
      return new Response(JSON.stringify({ error: 'garmin_credentials requires email and password' }), { status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' } });
  } else if (action === 'mfa_verify') {
    if (!input.session || !input.code)
      return new Response(JSON.stringify({ error: 'garmin_mfa requires session and code' }), { status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' } });
  } else {
    if (!input.refresh_token)
      return new Response(JSON.stringify({ error: 'garmin_token_refresh requires refresh_token' }), { status: 400, headers: { ...corsHeaders(req), 'Content-Type': 'application/json' } });
  }

  try {
    if (action === 'login') {
      const result = await garminLogin(input.email, input.password);
      if (result.mfa_required) {
        return new Response(JSON.stringify({
          error: 'MFA required',
          mfa_required: true,
          mfa_method: result.mfa_method,
          session: result.session,
        }), {
          status: 401,
          headers: { ...corsHeaders(req), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
        });
      }
      const { oauth1, oauth2 } = result;
      return new Response(JSON.stringify({
        access_token: oauth2.access_token,
        refresh_token: oauth1ToRefreshToken(oauth1),
        expires_in: oauth2.expires_in,
        refresh_token_expires_in: oauth2.refresh_token_expires_in || null,
        token_type: oauth2.token_type,
      }), {
        status: 200,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    } else if (action === 'mfa_verify') {
      const result = await garminCompleteMfa(input.session, input.code);
      const { oauth1, oauth2 } = result;
      return new Response(JSON.stringify({
        access_token: oauth2.access_token,
        refresh_token: oauth1ToRefreshToken(oauth1),
        expires_in: oauth2.expires_in,
        refresh_token_expires_in: oauth2.refresh_token_expires_in || null,
        token_type: oauth2.token_type,
      }), {
        status: 200,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    } else {
      const oauth2 = await garminRefreshToken(input.refresh_token);
      return new Response(JSON.stringify({
        access_token: oauth2.access_token,
        refresh_token: input.refresh_token,
        expires_in: oauth2.expires_in,
        refresh_token_expires_in: oauth2.refresh_token_expires_in || null,
        token_type: oauth2.token_type,
      }), {
        status: 200,
        headers: { ...corsHeaders(req), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
      });
    }
  } catch (error) {
    const status = error.status || 502;
    const isAuth = status === 401;
    const message = isAuth ? 'Invalid Garmin credentials or MFA code.' : 'Garmin authentication service unavailable.';
    console.error('[garmin_auth] ERROR:', error.message, 'status:', status, 'stack:', error.stack?.split('\n').slice(0, 3).join(' | '));
    // Include debug detail in response so we can see what Garmin returned
    // without needing Vercel dashboard access
    return new Response(JSON.stringify({
      error: message,
      debug: {
        step: error.garminStep || 'unknown',
        detail: error.message,
        status,
      },
    }), {
      status,
      headers: { ...corsHeaders(req), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });
  }
}
