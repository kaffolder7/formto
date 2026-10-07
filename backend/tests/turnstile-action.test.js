import test from "node:test";
import assert from "node:assert/strict";
import { turnstileAction, publicForm, encryptSecret, verifyTurnstile } from "../utils/submissionSecurity.js";
import { renderHostedForm } from "../utils/hostedForm.js";

test("real UUIDs produce a Cloudflare-valid action in API responses and hosted markup", () => {
  const form = { id: "d9d39bed-c631-46e9-9151-a11bda3fc966", name: "Contact", endpoint: "contact", submission_mode: "public", fields: [], turnstile_site_key: "public-key" };
  const action = turnstileAction(form);
  assert.equal(action, "d9d39bedc63146e99151a11bda3fc966");
  assert.match(action, /^[a-zA-Z0-9_-]{1,32}$/);
  assert.equal(publicForm(form).turnstile_action, action);
  assert.ok(renderHostedForm(form).includes(`data-action="${action}"`));
  assert.notEqual(turnstileAction({ ...form, id: "d9d39bed-c631-46e9-9151-a11bda3fc967" }), action);
});

test("verification accepts the shortened action and rejects another form's action", async () => {
  process.env.SETTINGS_ENCRYPTION_KEY = "turnstile-action-test-key-0123456789";
  const form = { id: "d9d39bed-c631-46e9-9151-a11bda3fc966", turnstile_secret_encrypted: encryptSecret("test-secret") };
  const verifier = action => async () => ({ ok: true, json: async () => ({ success: true, hostname: "housewatch.digital", action }) });
  await verifyTurnstile(form, "test-token", "https://housewatch.digital", "127.0.0.1", verifier(turnstileAction(form)));
  await assert.rejects(verifyTurnstile(form, "test-token", "https://housewatch.digital", "127.0.0.1", verifier("d9d39bedc63146e99151a11bda3fc967")), { code: "challenge_invalid" });
});
