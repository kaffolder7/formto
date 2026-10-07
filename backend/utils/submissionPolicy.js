import sql from "./db.js";
import { validateSubmissionData } from "./validation.js";
import { evaluateHoneypotPayload } from "../middleware/rateLimit.js";
import { getRequestIp } from "../middleware/rateLimit.js";
import {
  hashCredential,
  validCredential,
  verifyTurnstile,
  normalizeOrigin,
  readiness,
  reject,
  HONEYPOT,
  TOKEN_FIELD,
  validateFieldsPayload,
} from "./submissionSecurity.js";

// Fixed-minute buckets are shared by all instances and survive restarts.
export async function consumeRate(key, max = 10, database = sql) {
  const [bucket] = await database`
    INSERT INTO submission_rate_limits (key, window_start, count)
    VALUES (${hashCredential(key)}, date_trunc('minute', NOW()), 1)
    ON CONFLICT (key) DO UPDATE SET
      count = CASE WHEN submission_rate_limits.window_start = date_trunc('minute', NOW())
        THEN submission_rate_limits.count + 1 ELSE 1 END,
      window_start = date_trunc('minute', NOW())
    RETURNING count, GREATEST(1, CEIL(EXTRACT(EPOCH FROM window_start + INTERVAL '1 minute' - NOW())))::int AS retry
  `;
  if (bucket.count > max)
    reject(
      429,
      "rate_limited",
      "Too many attempts. Please wait a moment.",
      bucket.retry,
    );
}

export function allowPublicOrigin(form, request, reply) {
  let origin;
  try {
    origin = normalizeOrigin(request.headers.origin);
  } catch {
    reject(
      403,
      "origin_denied",
      "This website is not allowed to submit to this form",
    );
  }
  if (!form.allowed_origins.includes(origin))
    reject(
      403,
      "origin_denied",
      "This website is not allowed to submit to this form",
    );
  reply
    .header("Access-Control-Allow-Origin", origin)
    .header("Vary", "Origin")
    .header("Access-Control-Expose-Headers", "Retry-After");
  return origin;
}

export async function authorizeSubmission(
  form,
  request,
  reply,
  verifier = verifyTurnstile,
) {
  const ip = getRequestIp(request);
  let origin = null;
  let originError;
  // Recognized websites must be able to read retry/validation errors. Invalid
  // origins still count as attempts, without receiving permission to read replies.
  if (form.submission_mode === "public") {
    try { origin = allowPublicOrigin(form, request, reply); }
    catch (error) { originError = error; }
  } else if (form.submission_mode === "legacy") {
    reply.header("Access-Control-Allow-Origin", "*");
  }
  if (form.submission_mode !== "private") {
    await consumeRate(`public:${ip}`);
    await consumeRate(`public:${form.id}:${ip}`);
  }
  if (originError) throw originError;
  if (!form.active || readiness(form))
    reject(422, "form_inactive", "This form is not accepting submissions");
  if (form.close_at && new Date(form.close_at) < new Date())
    reject(422, "form_closed", "This form is closed");
  if (form.submission_mode === "private") {
    if (
      !validCredential(request.headers.authorization, form.submission_key_hash)
    ) {
      await consumeRate(`private-failure:${ip}`);
      reject(
        401,
        "invalid_submission_key",
        "A valid submission key is required",
      );
    }
    await consumeRate(`private:${form.id}:${form.submission_key_hash}`);
  } else {
    if (form.submission_mode === "public")
      await verifier(form, request.body?.[TOKEN_FIELD], origin, ip);
  }
  if (request.body?.[HONEYPOT]) return null;
  if (form.submission_mode === "legacy") {
    let raw = request.body || {};
    if (typeof raw === "string") {
      try {
        raw = JSON.parse(raw);
      } catch {
        raw = {};
      }
    }
    const { blocked, cleanData } = evaluateHoneypotPayload(raw);
    if (blocked) return null;
    delete cleanData._formto_js;
    delete cleanData[HONEYPOT];
    delete cleanData[TOKEN_FIELD];
    const validation = validateSubmissionData(cleanData);
    if (!validation.valid) reject(400, "invalid_fields", validation.error);
    return cleanData;
  }
  return validateFieldsPayload(request.body, form.fields);
}

export function hasNotifications(form) {
  return !!(
    (form.notify_email &&
      (form.notification_email || form.owner_notify_email)) ||
    (form.notify_telegram &&
      form.owner_telegram_bot_token &&
      form.owner_telegram_chat_id) ||
    (form.notify_slack && form.owner_slack_webhook_url) ||
    form.webhook_url ||
    form.slack_webhook_url ||
    form.discord_webhook_url
  );
}

export async function saveWithQuota(form, data, metadata, database = sql) {
  return database.begin(async (tx) => {
    const [current] =
      await tx`SELECT * FROM forms WHERE id = ${form.id} FOR UPDATE`;
    if (
      !current ||
      current.security_revision !== form.security_revision ||
      !current.active ||
      readiness(current)
    ) {
      reject(
        409,
        "settings_changed",
        "Form settings changed. Reload the form and try again.",
      );
    }
    if (current.close_at && new Date(current.close_at) < new Date())
      reject(422, "form_closed", "This form is closed");
    const [clock] =
      await tx`SELECT (NOW() AT TIME ZONE 'UTC')::date::text AS day,
      CEIL(EXTRACT(EPOCH FROM ((date_trunc('day', NOW() AT TIME ZONE 'UTC') + INTERVAL '1 day') AT TIME ZONE 'UTC') - NOW()))::int AS retry`;
    await tx`INSERT INTO form_daily_usage (form_id, day) VALUES (${form.id}, ${clock.day}) ON CONFLICT DO NOTHING`;
    const [usage] =
      await tx`SELECT * FROM form_daily_usage WHERE form_id = ${form.id} AND day = ${clock.day} FOR UPDATE`;
    const legacy = current.submission_mode === "legacy";
    if (!legacy && usage.submissions >= current.daily_submission_limit)
      reject(
        429,
        "daily_quota_reached",
        "This form has reached its daily submission limit",
        clock.retry,
      );
    const requested = hasNotifications(form);
    const notify =
      requested &&
      (legacy || usage.notifications < current.daily_notification_limit);
    const status = !requested
      ? "not_requested"
      : notify
        ? "reserved"
        : "suppressed_quota";
    const [submission] = await tx`
      INSERT INTO submissions (form_id, form_endpoint, data, metadata, notification_status)
      VALUES (${form.id}, ${form.endpoint}, ${tx.json(data)}, ${tx.json(metadata)}, ${status}) RETURNING *`;
    await tx`UPDATE form_daily_usage SET submissions = submissions + 1, notifications = notifications + ${notify ? 1 : 0}
      WHERE form_id = ${form.id} AND day = ${clock.day}`;
    await tx`SELECT increment_submission_count(${form.id})`;
    return { submission, notify };
  });
}
