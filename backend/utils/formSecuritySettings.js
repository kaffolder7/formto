import {
  DEFAULT_FIELDS,
  validateFields,
  normalizeOrigin,
  hostedOrigin,
  encryptSecret,
  readiness,
} from "./submissionSecurity.js";

export const SECURITY_COLUMNS = [
  "submission_mode",
  "security_configured",
  "security_revision",
  "allowed_origins",
  "hosted_enabled",
  "turnstile_site_key",
  "turnstile_secret_encrypted",
  "submission_key_hash",
  "submission_key_prefix",
  "submission_key_created_at",
  "fields",
  "daily_submission_limit",
  "daily_notification_limit",
];
export const SECURITY_INPUTS = [
  "submission_mode",
  "allowed_origins",
  "hosted_enabled",
  "turnstile_site_key",
  "turnstile_secret",
  "fields",
  "daily_submission_limit",
  "daily_notification_limit",
];

export function securityUpdates(body, existing = {}) {
  const updates = {};
  const creating = !existing.id;
  if ("active" in body && typeof body.active !== "boolean")
    throw new Error("Active must be true or false");
  if (existing.submission_mode === "legacy") {
    const changed = SECURITY_INPUTS.some((key) => Object.hasOwn(body, key));
    if (!body.upgrade_security) {
      if (changed)
        throw new Error(
          "Explicitly upgrade security before changing security settings",
        );
      return updates;
    }
    if (
      body.upgrade_security !== true ||
      !["public", "private"].includes(body.submission_mode)
    )
      throw new Error("Choose a security mode to upgrade");
    // One-way opt-in. Save configuration first; activate separately once integration is ready.
    if (body.active === true)
      throw new Error(
        "Deactivate the form when upgrading security, then activate after setup",
      );
    updates.active = false;
  } else if (Object.hasOwn(body, "upgrade_security"))
    throw new Error("This form already uses the new security modes");
  for (const key of SECURITY_INPUTS)
    if (Object.hasOwn(body, key)) updates[key] = body[key];
  if (creating)
    Object.assign(updates, {
      submission_mode: body.submission_mode ?? "public",
      fields: body.fields ?? DEFAULT_FIELDS,
      allowed_origins: body.allowed_origins ?? [],
      hosted_enabled: body.hosted_enabled ?? false,
      daily_submission_limit: body.daily_submission_limit ?? 500,
      daily_notification_limit: body.daily_notification_limit ?? 100,
    });
  if (
    "submission_mode" in updates &&
    !["public", "private"].includes(updates.submission_mode)
  )
    throw new Error("Choose public or private submissions");
  if (
    "hosted_enabled" in updates &&
    typeof updates.hosted_enabled !== "boolean"
  )
    throw new Error("Invalid hosted form setting");
  if ("fields" in updates) updates.fields = validateFields(updates.fields);
  for (const [key, minimum] of [
    ["daily_submission_limit", 1],
    ["daily_notification_limit", 0],
  ]) {
    if (
      key in updates &&
      (!Number.isInteger(updates[key]) ||
        updates[key] < minimum ||
        updates[key] > 1000000)
    )
      throw new Error(`${key} must be between ${minimum} and 1000000`);
  }
  if ("allowed_origins" in updates) {
    if (
      !Array.isArray(updates.allowed_origins) ||
      updates.allowed_origins.length > 100
    )
      throw new Error("Enter at most 100 allowed origins");
    updates.allowed_origins = [
      ...new Set(updates.allowed_origins.map(normalizeOrigin)),
    ];
  }
  if ("turnstile_site_key" in updates) {
    if (
      typeof updates.turnstile_site_key !== "string" ||
      updates.turnstile_site_key.length > 256 ||
      !/^[A-Za-z0-9_-]*$/.test(updates.turnstile_site_key)
    )
      throw new Error("Invalid Turnstile site key");
    updates.turnstile_site_key = updates.turnstile_site_key || null;
  }
  if ("turnstile_secret" in updates) {
    const secret = updates.turnstile_secret;
    if (
      secret !== null &&
      (typeof secret !== "string" || !secret.trim() || secret.length > 1024)
    )
      throw new Error(
        "Enter a Turnstile secret or omit it to keep the saved value",
      );
    updates.turnstile_secret_encrypted =
      secret === null ? null : encryptSecret(secret.trim());
    delete updates.turnstile_secret;
  }
  if (
    updates.submission_mode &&
    updates.submission_mode !== existing.submission_mode
  ) {
    Object.assign(updates, {
      submission_key_hash: null,
      submission_key_prefix: null,
      submission_key_created_at: null,
    });
  }
  const combined = { ...existing, ...updates };
  if (combined.submission_mode === "private") updates.hosted_enabled = false;
  else if (combined.hosted_enabled)
    updates.allowed_origins = [
      ...new Set([...(combined.allowed_origins || []), hostedOrigin()]),
    ];
  // Saving a security configuration is the explicit review step; activation is separate.
  if (creating || SECURITY_INPUTS.some((key) => Object.hasOwn(body, key)))
    updates.security_configured = true;
  if (body.active === true) {
    const issue = readiness({ ...combined, ...updates });
    if (issue) throw new Error(issue);
  }
  if (existing.active && readiness({ ...combined, ...updates }))
    updates.active = false;
  return updates;
}
