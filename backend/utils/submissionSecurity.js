import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import validator from "validator";

export const HONEYPOT = "_formto_honeypot";
export const TOKEN_FIELD = "cf-turnstile-response";
export const DEFAULT_FIELDS = [
  { name: "name", label: "Name", type: "text", required: true, maxLength: 200 },
  {
    name: "email",
    label: "Email",
    type: "email",
    required: true,
    maxLength: 254,
  },
  {
    name: "message",
    label: "Message",
    type: "textarea",
    required: true,
    maxLength: 10000,
  },
];

export class SubmissionError extends Error {
  constructor(status, code, message, retryAfter) {
    super(message);
    Object.assign(this, { status, code, retryAfter });
  }
}
export const reject = (status, code, message, retryAfter) => {
  throw new SubmissionError(status, code, message, retryAfter);
};

export function encryptionKey() {
  const key = process.env.SETTINGS_ENCRYPTION_KEY || "";
  if (key.length < 32 || /change.?me|example|replace.?me/i.test(key)) {
    throw new Error(
      "SETTINGS_ENCRYPTION_KEY must be a private random value of at least 32 characters",
    );
  }
  return createHash("sha256").update(key).digest();
}
export function encryptSecret(secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const data = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  return [
    "v1",
    iv.toString("base64url"),
    cipher.getAuthTag().toString("base64url"),
    data.toString("base64url"),
  ].join(".");
}
export function decryptSecret(value) {
  const [version, iv, tag, data] = (value || "").split(".");
  if (version !== "v1" || !iv || !tag || !data)
    throw new Error("Invalid encrypted settings");
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(data, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}
export const hashCredential = (value) =>
  createHash("sha256").update(value).digest("hex");
export function newCredential() {
  const token = `ft_${randomBytes(32).toString("base64url")}`;
  return { token, hash: hashCredential(token), prefix: token.slice(0, 11) };
}
export function validCredential(header, hash) {
  if (
    !hash ||
    typeof header !== "string" ||
    !/^Bearer ft_[A-Za-z0-9_-]{43}$/.test(header)
  )
    return false;
  const actual = Buffer.from(hashCredential(header.slice(7)), "hex");
  const expected = Buffer.from(hash, "hex");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
// Cloudflare permits at most 32 action characters. The full UUID fits without hyphens.
export const turnstileAction = (form) => form.id.replaceAll("-", "");

export function normalizeOrigin(value) {
  if (
    typeof value !== "string" ||
    !/^https?:\/\/[^/?#]+\/?$/.test(value.trim()) ||
    value.includes("*")
  )
    throw new Error("Use an exact HTTPS origin without a path");
  const url = new URL(value);
  const local =
    process.env.NODE_ENV !== "production" &&
    ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:"))
    throw new Error("Allowed websites must use HTTPS");
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new Error("Enter an origin without a path, query, or credentials");
  return url.origin;
}
export function hostedOrigin() {
  return normalizeOrigin(process.env.PUBLIC_ORIGIN || "");
}

export function validateFields(fields) {
  if (!Array.isArray(fields) || !fields.length || fields.length > 50)
    throw new Error("Define between 1 and 50 fields");
  const names = new Set();
  const types = new Set([
    "text",
    "textarea",
    "email",
    "tel",
    "number",
    "checkbox",
    "select",
    "radio",
    "date",
    "url",
  ]);
  return fields.map((field) => {
    if (!field || typeof field !== "object" || Array.isArray(field))
      throw new Error("Invalid field definition");
    const { name, type } = field;
    if (
      typeof name !== "string" ||
      !/^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/.test(name) ||
      ["__proto__", "constructor", "prototype", TOKEN_FIELD].includes(name) ||
      names.has(name)
    )
      throw new Error(
        "Field names must be unique and cannot use reserved names",
      );
    names.add(name);
    if (!types.has(type))
      throw new Error("Unsupported field type; file uploads are unavailable");
    if (
      typeof field.label !== "string" ||
      !field.label.trim() ||
      field.label.length > 120
    )
      throw new Error("Field labels must be 1–120 characters");
    const maxLength = field.maxLength ?? (type === "textarea" ? 10000 : 500);
    if (!Number.isInteger(maxLength) || maxLength < 1 || maxLength > 10000)
      throw new Error("Field length must be between 1 and 10000");
    const result = {
      name,
      label: field.label.trim(),
      type,
      required: !!field.required,
      maxLength,
    };
    if (["select", "radio"].includes(type)) {
      if (
        !Array.isArray(field.options) ||
        !field.options.length ||
        field.options.length > 50
      )
        throw new Error("Select and radio fields need 1–50 choices");
      result.options = field.options.map((option) => {
        const value = typeof option === "string" ? option : option?.value;
        const label = typeof option === "string" ? option : option?.label;
        if (
          typeof value !== "string" ||
          !value ||
          value.length > 120 ||
          typeof label !== "string" ||
          !label ||
          label.length > 120
        )
          throw new Error("Invalid field choice");
        return { value, label };
      });
    }
    return result;
  });
}

export function validateFieldsPayload(raw, fields) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw))
    reject(
      400,
      "invalid_fields",
      "Submit an object containing the configured fields",
    );
  const reserved = new Set([HONEYPOT, TOKEN_FIELD]);
  const allowed = new Set(fields.map((f) => f.name));
  for (const key of Object.keys(raw)) {
    if (!reserved.has(key) && !allowed.has(key))
      reject(400, "invalid_fields", `Unexpected field: ${key.slice(0, 100)}`);
  }
  const data = {};
  for (const field of fields) {
    const value = Object.hasOwn(raw, field.name) ? raw[field.name] : undefined;
    const fail = (message) =>
      reject(400, "invalid_fields", `${field.label}: ${message}`);
    if (
      value !== undefined &&
      value !== null &&
      !["string", "number", "boolean"].includes(typeof value)
    )
      fail("use a single value");
    if (field.type === "checkbox") {
      if (
        ![undefined, null, "", false, true, "on", "true", "false"].includes(
          value,
        )
      )
        fail("invalid checkbox value");
      const checked = [true, "on", "true"].includes(value);
      if (field.required && !checked) fail("required");
      data[field.name] = checked;
      continue;
    }
    if (value === undefined || value === null || String(value).trim() === "") {
      if (field.required) fail("required");
      continue;
    }
    const text = String(value).trim();
    if (text.length > field.maxLength)
      fail(`maximum ${field.maxLength} characters`);
    if (field.type === "email" && !validator.isEmail(text))
      fail("enter a valid email address");
    if (
      field.type === "url" &&
      !validator.isURL(text, {
        protocols: ["http", "https"],
        require_protocol: true,
      })
    )
      fail("enter an HTTP or HTTPS URL");
    if (field.type === "number" && !/^-?(?:\d+\.?\d*|\.\d+)$/.test(text))
      fail("enter a number");
    if (field.type === "number" && !Number.isFinite(Number(text)))
      fail("number is out of range");
    if (
      field.type === "date" &&
      (!/^\d{4}-\d{2}-\d{2}$/.test(text) ||
        !validator.isDate(text, { format: "YYYY-MM-DD", strictMode: true }))
    )
      fail("enter a valid date");
    if (
      ["select", "radio"].includes(field.type) &&
      !field.options.some((option) => option.value === text)
    )
      fail("choose an allowed value");
    data[field.name] = field.type === "number" ? Number(text) : text;
  }
  return data;
}

export function readiness(form) {
  if (form.submission_mode === "legacy") return null;
  if (!form.security_configured)
    return "Review and save security settings before activation";
  if (!form.fields?.length) return "Define the allowed fields";
  if (form.submission_mode === "private")
    return form.submission_key_hash ? null : "Generate a submission key";
  if (!form.allowed_origins?.length) return "Add at least one allowed website";
  if (!form.turnstile_site_key || !form.turnstile_secret_encrypted)
    return "Configure Turnstile";
  return null;
}

export function publicForm(form) {
  if (!form) return form;
  const { turnstile_secret_encrypted, submission_key_hash, ...safe } = form;
  return {
    ...safe,
    turnstile_secret_configured: !!turnstile_secret_encrypted,
    submission_key_configured: !!submission_key_hash,
    security_issue: readiness(form),
    turnstile_action: turnstileAction(form),
  };
}

export async function verifyTurnstile(
  form,
  token,
  origin,
  ip,
  fetcher = fetch,
) {
  if (typeof token !== "string" || !token || token.length > 2048)
    reject(
      403,
      "challenge_required",
      "Complete the verification and submit again",
    );
  let result;
  try {
    const response = await fetcher(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        signal: AbortSignal.timeout(8000),
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          secret: decryptSecret(form.turnstile_secret_encrypted),
          response: token,
          remoteip: ip,
        }),
      },
    );
    if (!response.ok) throw new Error("Verification unavailable");
    result = await response.json();
    if (!result || typeof result.success !== "boolean")
      throw new Error("Invalid verification response");
  } catch {
    reject(
      503,
      "verification_unavailable",
      "Verification is temporarily unavailable. Please try again.",
      10,
    );
  }
  if (
    !result.success ||
    result.hostname !== new URL(origin).hostname ||
    result.action !== turnstileAction(form)
  ) {
    reject(
      403,
      "challenge_invalid",
      "Verification failed or expired. Please verify again.",
    );
  }
}
