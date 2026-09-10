// @ts-check
// wearables-garmin.js — Garmin Connect data layer
//
// BETA. Garmin Connect has no public CORS-enabled REST API; the internal
// endpoints at connect.garmin.com and connectapi.garmin.com require a
// cloud-scraper-friendly session and are therefore accessed through the
// deployment's /api/proxy. The browser only stores an opaque session token
// and refresh token (see wearables-garmin-auth.js); all real Garmin traffic
// happens server-side.
//
// The proxy accepts requests with { url, method, headers, body } where
// headers carry the session token as `Authorization: Bearer <token>`. On a
// 401/403 the caller triggers garmin_token_refresh via wearables-garmin-auth.js.
//
// Canonical mapping:
//   hrv_rmssd       ← HRV summary lastNightAvg (ms)
//   rhr             ← user summary restingHeartRate (bpm)
//   sleep_score     ← sleep data sleep score
//   readiness_score ← training readiness score
//   steps           ← user summary totalSteps
//   stress_high_min ← all-day stress high minutes
//   spo2_avg        ← SpO2 average percentage
//   body_temp_delta ← body battery related temp (if available)
//   hr_day          ← heart rates average (bpm)
//   sleep_total_min ← sleep data total sleep seconds → minutes
//   sleep_deep_min  ← deep sleep seconds → minutes
//   sleep_light_min ← light sleep seconds → minutes
//   sleep_rem_min   ← REM sleep seconds → minutes
//   sleep_awake_min ← awake seconds → minutes

import { getErrorMessage, getErrorStatus } from './caught-error.js';
import { getProxyApiUrl } from './proxy-runtime.js';
import { isDebugMode } from './utils.js';

const GARMIN_API      = 'https://connect.garmin.com';
const GARMIN_CONNECT_API = 'https://connectapi.garmin.com';
const PROXY_URL       = getProxyApiUrl();

// Cloudflare-friendly default headers. Garmin blocks many non-browser user
// agents; these are hints the proxy can apply, not hard requirements. The
// actual session cookie/CSRF handling happens server-side.
const DEFAULT_GARMIN_HEADERS = {
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'en-US,en;q=0.9',
  'Referer': 'https://connect.garmin.com/',
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
  'NK': 'NT',
  'Authorization': '',
};

// ─────────────────────────────────────────────────────────
// Transport
// ─────────────────────────────────────────────────────────

async function garminRequest({ base = GARMIN_API, path, accessToken, method = 'GET', params = null, body = null, extraHeaders = {} }) {
  const qs = params ? '?' + new URLSearchParams(params).toString() : '';
  const url = `${base}/${path.replace(/^\//, '')}${qs}`;
  const headers = { ...DEFAULT_GARMIN_HEADERS, ...extraHeaders };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const payload = { url, method, headers };
  if (body != null) payload.body = body;

  const res = await fetch(PROXY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let err;
    try { err = await res.json(); } catch { err = { error: res.statusText }; }
    const msg = err?.message || err?.error || err?.detail || res.statusText || 'Garmin request failed';
    /** @type {Error & { status?: number }} */
    const e = new Error(msg);
    e.status = res.status;
    throw e;
  }
  // Some Garmin endpoints return empty bodies for 204/no-data days.
  const text = await res.text();
  if (!text.trim()) return null;
  try { return JSON.parse(text); } catch {
    return { raw: text };
  }
}

function garminGET(path, accessToken, params = null, opts = {}) {
  return garminRequest({ path, accessToken, method: 'GET', params, ...opts });
}

// ─────────────────────────────────────────────────────────
// Account info
// ─────────────────────────────────────────────────────────

export async function fetchGarminPersonalInfo(accessToken) {
  try {
    // /userprofile-service/userprofile — basic profile with email when present.
    const info = await garminGET('userprofile-service/userprofile', accessToken, null, { base: GARMIN_CONNECT_API });
    return {
      ok: true,
      account: {
        email: info?.emailAddress || info?.email || null,
        firstName: info?.firstName || info?.first_name || null,
        lastName: info?.lastName || info?.last_name || null,
        displayName: info?.displayName || null,
      },
    };
  } catch (e) {
    return { ok: false, error: getErrorMessage(e), status: getErrorStatus(e) };
  }
}

// ─────────────────────────────────────────────────────────
// Range fetch → canonical rows
// ─────────────────────────────────────────────────────────

// Garmin endpoints per the garmin-pulse skill. Paths below are relative to
// connect.garmin.com unless noted as connectapi.garmin.com. The proxy adds
// whatever auth/session/CSRF state the server-side implementation needs.
//
// All date arguments are YYYY-MM-DD. Server-side proxy translates if a given
// endpoint expects ISO or calendarDate shapes.
const GARMIN_ENDPOINTS = {
  userSummary: (date) => ({ path: `usersummary-service/userSummary/${date}` }),
  heartRates:  (date) => ({ path: `usersummary-service/userSummaryHeartRates/${date}` }),
  bodyBattery: (start, end) => ({ path: `bodyservice/bodyBattery/${start}/${end}`, base: GARMIN_CONNECT_API }),
  hrv:         (date) => ({ path: `hrv-service/hrv/${date}`, base: GARMIN_CONNECT_API }),
  spo2:        (date) => ({ path: `spo2-service/spo2/${date}`, base: GARMIN_CONNECT_API }),
  sleep:       (date) => ({ path: `wellness-service/wellness/dailySleep/user/${date}`, base: GARMIN_CONNECT_API }),
  stress:      (date) => ({ path: `wellness-service/wellness/dailyStress/user/${date}`, base: GARMIN_CONNECT_API }),
  readiness:   (date) => ({ path: `training-readiness-service/readiness/${date}`, base: GARMIN_CONNECT_API }),
  respiration: (date) => ({ path: `respiration-service/respiration/${date}`, base: GARMIN_CONNECT_API }),
  activities:  (start, end) => ({ path: `activitylist-service/activities/search/activities?startDate=${start}&endDate=${end}&start=0&limit=100` }),
};

function secToMin(v) {
  return typeof v === 'number' && isFinite(v) && v >= 0 ? Math.round(v / 60) : null;
}

export async function fetchGarminDailyRange(accessToken, startDate, endDate) {
  // Walk each day independently. Garmin endpoints are date-granular and small
  // enough that parallel-per-day is simpler than chunking for a 90-day window.
  // Limit concurrency gently to avoid tripping rate limits.
  const days = [];
  const cursor = new Date(startDate + 'T00:00:00Z');
  const end = new Date(endDate + 'T00:00:00Z');
  while (cursor <= end) {
    days.push(cursor.toISOString().slice(0, 10));
    cursor.setUTCDate(cursor.getUTCDate() + 1);
  }

  const CONCURRENCY = 4;
  /** @type {Map<string, any>} */
  const rawByDay = new Map();
  for (let i = 0; i < days.length; i += CONCURRENCY) {
    const batch = days.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(async (date) => {
      const [summary, heart, hrv, spo2, sleep, stress, readiness, respiration] = await Promise.all([
        garminGET(GARMIN_ENDPOINTS.userSummary(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.userSummary(date).base || GARMIN_API }).catch(e => { logDebug('userSummary', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.heartRates(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.heartRates(date).base || GARMIN_API }).catch(e => { logDebug('heartRates', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.hrv(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.hrv(date).base || GARMIN_API }).catch(e => { logDebug('hrv', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.spo2(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.spo2(date).base || GARMIN_API }).catch(e => { logDebug('spo2', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.sleep(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.sleep(date).base || GARMIN_API }).catch(e => { logDebug('sleep', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.stress(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.stress(date).base || GARMIN_API }).catch(e => { logDebug('stress', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.readiness(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.readiness(date).base || GARMIN_API }).catch(e => { logDebug('readiness', date, e); return null; }),
        garminGET(GARMIN_ENDPOINTS.respiration(date).path, accessToken, null, { base: GARMIN_ENDPOINTS.respiration(date).base || GARMIN_API }).catch(e => { logDebug('respiration', date, e); return null; }),
      ]);
      rawByDay.set(date, { summary, heart, hrv, spo2, sleep, stress, readiness, respiration });
    }));
  }

  // Body battery and activities span ranges — fetch once per requested window.
  const [bodyBattery, activities] = await Promise.all([
    garminGET(GARMIN_ENDPOINTS.bodyBattery(startDate, endDate).path, accessToken, null, { base: GARMIN_ENDPOINTS.bodyBattery(startDate, endDate).base || GARMIN_API }).catch(e => { logDebug('bodyBattery', `${startDate}..${endDate}`, e); return null; }),
    garminGET(GARMIN_ENDPOINTS.activities(startDate, endDate).path, accessToken, null, { base: GARMIN_ENDPOINTS.activities(startDate, endDate).base || GARMIN_API }).catch(e => { logDebug('activities', `${startDate}..${endDate}`, e); return null; }),
  ]);

  /** @type {Map<string, object>} */
  const bodyBatteryByDay = new Map();
  for (const entry of (bodyBattery || [])) {
    const date = entry?.date || entry?.calendarDate;
    if (!date) continue;
    if (!bodyBatteryByDay.has(date) || (entry?.charged != null)) bodyBatteryByDay.set(date, entry);
  }

  /** @type {Map<string, object>} */
  const byDate = new Map();
  function ensureRow(day) {
    if (!byDate.has(day)) {
      byDate.set(day, {
        source: 'garmin', date: day,
        hrv_rmssd: null, rhr: null,
        hrv_day: null, hr_day: null,
        sleep_score: null, readiness_score: null,
        activity_score: null, steps: null,
        strain: null,
        stress_high_min: null, resilience_level: null, cardio_age: null,
        spo2_avg: null, body_temp_delta: null, glucose_avg: null,
        sleep_total_min: null, sleep_deep_min: null, sleep_light_min: null,
        sleep_rem_min: null, sleep_awake_min: null,
      });
    }
    return byDate.get(day);
  }

  for (const [date, raw] of rawByDay) {
    const row = ensureRow(date);

    // User summary: steps, resting HR, active minutes, floors, distance, calories.
    const s = raw.summary || {};
    if (typeof s.totalSteps === 'number') row.steps = s.totalSteps;
    if (typeof s.restingHeartRate === 'number') row.rhr = s.restingHeartRate;
    // Average HR across the full day, if present.
    if (typeof s.averageHR === 'number') row.hr_day = s.averageHR;

    // Heart rates endpoint gives min/max/avg and a dedicated resting value.
    const h = raw.heart || {};
    const resting = h.restingHeartRate ?? h.restingHR;
    if (typeof resting === 'number') row.rhr = resting;
    if (typeof h.average === 'number') row.hr_day = h.average;
    else if (typeof h.averageHR === 'number') row.hr_day = h.averageHR;

    // HRV summary: lastNightAvg is the overnight sleep-window rMSSD.
    const hrv = raw.hrv || {};
    const hrvValue = hrv.lastNightAvg ?? hrv.lastNightAverage ?? hrv.weeklyAvg;
    if (typeof hrvValue === 'number') row.hrv_rmssd = hrvValue;

    // SpO2 average percentage.
    const spo2 = raw.spo2 || {};
    const spo2Value = spo2.averageSpO2 ?? spo2.avgSpO2 ?? spo2.spo2Average;
    if (typeof spo2Value === 'number') row.spo2_avg = spo2Value;

    // Sleep: score + architecture in seconds.
    const sleep = raw.sleep || {};
    const sleepSummary = sleep.sleepSummary || sleep.sleep || sleep.dailySleepDTO || sleep;
    if (typeof sleepSummary.sleepScore === 'number') row.sleep_score = sleepSummary.sleepScore;
    else if (typeof sleepSummary.score === 'number') row.sleep_score = sleepSummary.score;

    const stages = sleepSummary.sleepStages || sleepSummary.stages || {};
    row.sleep_total_min = secToMin(sleepSummary.sleepTimeInBed || sleepSummary.sleepDurationInSeconds || sleepSummary.durationInSeconds);
    row.sleep_deep_min  = secToMin(stages.deepSleepSeconds || stages.deep);
    row.sleep_light_min = secToMin(stages.lightSleepSeconds || stages.light);
    row.sleep_rem_min   = secToMin(stages.remSleepSeconds || stages.rem);
    row.sleep_awake_min = secToMin(stages.awakeSleepSeconds || stages.awake || sleepSummary.awakeDurationInSeconds);

    // Stress: high minutes.
    const stress = raw.stress || {};
    const highMin = stress.highStressDurationInSeconds ?? stress.highStressSeconds;
    if (typeof highMin === 'number') row.stress_high_min = Math.round(highMin / 60);
    else if (typeof stress.highStressMinutes === 'number') row.stress_high_min = stress.highStressMinutes;

    // Training readiness score.
    const readiness = raw.readiness || {};
    const readinessScore = readiness.readinessScore ?? readiness.score ?? readiness.readinessLevel;
    if (typeof readinessScore === 'number') row.readiness_score = readinessScore;

    // Respiration average can populate a future canonical; currently unused.
    void raw.respiration;

    // Body battery related temp delta, if present.
    const bb = bodyBatteryByDay.get(date) || {};
    const tempDelta = bb.bodyBatteryDelta ?? bb.temperatureDelta ?? bb.tempDelta;
    if (typeof tempDelta === 'number') row.body_temp_delta = tempDelta;
  }

  // Activity list can fill in missing daily averages or steps when the user
  // summary is sparse (Garmin occasionally omits zero-activity days).
  const activityDays = new Map();
  for (const a of (activities || [])) {
    const date = a?.startTimeLocal?.slice(0, 10) || a?.startTime?.slice(0, 10) || a?.date;
    if (!date) continue;
    if (!activityDays.has(date)) activityDays.set(date, []);
    activityDays.get(date).push(a);
  }
  for (const [date, acts] of activityDays) {
    const row = ensureRow(date);
    if (row.steps == null) {
      const steps = acts.reduce((sum, a) => sum + (typeof a.steps === 'number' ? a.steps : 0), 0);
      if (steps > 0) row.steps = steps;
    }
    if (row.hr_day == null) {
      const avgs = acts.map(a => typeof a.averageHR === 'number' ? a.averageHR : null).filter(v => v != null);
      if (avgs.length) row.hr_day = Math.round(avgs.reduce((a, b) => a + b, 0) / avgs.length * 10) / 10;
    }
  }

  const rows = Array.from(byDate.values()).sort((a, b) => a.date.localeCompare(b.date));
  // Drop rows that ended up completely empty.
  return rows.filter(r => {
    const { source, date, ...metrics } = r;
    return Object.values(metrics).some(v => v != null);
  });
}

function logDebug(where, when, err) {
  if (isDebugMode?.()) console.warn(`[garmin] ${where} ${when} failed:`, err?.message || err);
}
