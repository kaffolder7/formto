import test from "node:test";
import assert from "node:assert/strict";
import {
  normalizeOrigin,
  validateFields,
  validateFieldsPayload,
  encryptSecret,
  decryptSecret,
  newCredential,
  validCredential,
  DEFAULT_FIELDS,
} from "../utils/submissionSecurity.js";
test("production origins are exact HTTPS origins", () => {
  process.env.NODE_ENV = "production";
  assert.equal(
    normalizeOrigin("https://EXAMPLE.com:443/"),
    "https://example.com",
  );
  for (const origin of [
    "http://example.com",
    "http://localhost:5174",
    "https://example.com/path/../",
    "https://example.com?x=1",
    "https://example.com#fragment",
    "null",
    "https://*.example.com",
  ])
    assert.throws(() => normalizeOrigin(origin));
  delete process.env.NODE_ENV;
});
test("typed field rules reject nested data, choices, invalid dates and oversize values", () => {
  const fields = validateFields([
    { name: "quantity", label: "Quantity", type: "number", required: true },
    { name: "consent", label: "Consent", type: "checkbox", required: true },
    {
      name: "choice",
      label: "Choice",
      type: "select",
      options: ["one", "two"],
    },
    { name: "date", label: "Date", type: "date" },
  ]);
  assert.deepEqual(
    validateFieldsPayload(
      { quantity: "2.5", consent: "on", choice: "one", date: "2026-10-07" },
      fields,
    ),
    { quantity: 2.5, consent: true, choice: "one", date: "2026-10-07" },
  );
  for (const payload of [
    { quantity: "bad", consent: true },
    { quantity: 2, consent: false },
    { quantity: 2, consent: true, choice: "other" },
    { quantity: 2, consent: true, date: "2026-02-31" },
    { quantity: { nested: 2 }, consent: true },
  ])
    assert.throws(() => validateFieldsPayload(payload, fields));
  assert.throws(() =>
    validateFieldsPayload(
      { name: "x".repeat(201), email: "test@example.com", message: "Hi" },
      DEFAULT_FIELDS,
    ),
  );
  assert.throws(() =>
    validateFields([{ label: "Missing name", type: "text" }]),
  );
});
test("settings encryption detects tampering and credentials are opaque", () => {
  process.env.SETTINGS_ENCRYPTION_KEY = "012345678901234567890123456789012345";
  const value = encryptSecret("sensitive-setting");
  assert.equal(decryptSecret(value), "sensitive-setting");
  const parts = value.split(".");
  parts[2] = Buffer.alloc(16).toString("base64url");
  assert.throws(() => decryptSecret(parts.join(".")));
  const key = newCredential();
  assert.equal(validCredential(`Bearer ${key.token}`, key.hash), true);
  assert.equal(validCredential("Bearer incorrect", key.hash), false);
  assert.notEqual(key.token, key.hash);
});
