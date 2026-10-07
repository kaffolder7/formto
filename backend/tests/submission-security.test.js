import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
const databaseUrl = process.env.TEST_DATABASE_URL;
test("submission security integration", { skip: !databaseUrl }, async (t) => {
  assert.match(new URL(databaseUrl).pathname, /test/);
  process.env.DATABASE_URL = databaseUrl;
  process.env.JWT_SECRET = "local-security-test-only";
  process.env.SETTINGS_ENCRYPTION_KEY = "012345678901234567890123456789012345";
  process.env.PUBLIC_ORIGIN = "https://forms.example.com";
  const { default: sql, dbHelpers } = await import("../utils/db.js");
  const { migrate } = await import("../utils/migrations.js");
  const security = await import("../utils/submissionSecurity.js");
  const { consumeRate, saveWithQuota } = await import(
    "../utils/submissionPolicy.js"
  );
  const { default: Fastify } = await import("fastify");
  const { default: formbody } = await import("@fastify/formbody");
  const { default: forms } = await import("../routes/forms.js");
  const { default: publicRoutes } = await import("../routes/public.js");
  const { authMiddleware } = await import("../middleware/auth.js");
  const { signToken } = await import("../utils/auth.js");
  const { emailHelpers } = await import("../utils/mailer.js");
  await Promise.all([migrate(), migrate()]);
  const [owner] =
    await sql`INSERT INTO users (username,password_hash) VALUES (${`security-${randomUUID()}`},'unused') RETURNING id`;
  const auth = {
    authorization: `Bearer ${await signToken({ userId: owner.id })}`,
  };
  let sent = 0;
  const originalSend = emailHelpers.sendSubmissionNotification;
  emailHelpers.sendSubmissionNotification = async () => {
    sent++;
  };
  const tokens = new Set();
  let challengeCalls = 0;
  let verificationBehavior = "normal";
  const verifier = (form, token, origin, ip) =>
    security.verifyTurnstile(form, token, origin, ip, async (_url, options) => {
      challengeCalls++;
      assert.equal(JSON.parse(options.body).secret, "test-turnstile-secret");
      if (verificationBehavior === "outage") throw new Error("offline");
      const duplicate = tokens.has(token);
      tokens.add(token);
      return {
        ok: true,
        json: async () => ({
          success: !duplicate && token !== "expired",
          hostname:
            verificationBehavior === "wrong-host"
              ? "attacker.example"
              : new URL(origin).hostname,
          action:
            verificationBehavior === "wrong-action"
              ? "different-form"
              : security.turnstileAction(form),
        }),
      };
    });
  const app = Fastify();
  await app.register(formbody);
  app.decorate("auth", authMiddleware);
  app.decorate("rateLimitSensitive", async () => {});
  await app.register(forms, { prefix: "/api/forms" });
  await app.register(publicRoutes, { verifyTurnstile: verifier });
  t.after(async () => {
    emailHelpers.sendSubmissionNotification = originalSend;
    await app.close();
    await sql`DELETE FROM users WHERE id=${owner.id}`;
    await sql.end();
  });
  const create = async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/forms",
      headers: auth,
      payload: { name: "Security test", endpoint: `test-${randomUUID()}` },
    });
    assert.equal(response.statusCode, 201, response.body);
    return response.json().form;
  };
  const update = (form, payload) =>
    app.inject({
      method: "PUT",
      url: `/api/forms/${form.id}`,
      headers: auth,
      payload,
    });
  const get = (form) =>
    app.inject({ url: `/api/forms/${form.id}`, headers: auth });
  const generate = (form) =>
    app.inject({
      method: "POST",
      url: `/api/forms/${form.id}/submission-key`,
      headers: auth,
    });
  const payload = {
    name: "Visitor",
    email: "visitor@example.com",
    message: "Hello",
  };
  const ipPrefix = `192.${Math.floor(Math.random() * 200) + 1}.${Math.floor(Math.random() * 250) + 1}`;
  let ipSequence = 1;
  const submit = (form, options = {}) =>
    app.inject({
      method: "POST",
      url: `/f/${form.endpoint}`,
      remoteAddress: `${ipPrefix}.${(ipSequence++ % 250) + 1}`,
      headers: { origin: "https://site.example", ...options.headers },
      payload: {
        ...payload,
        "cf-turnstile-response": randomUUID(),
        ...options.payload,
      },
    });
  const privateForm = async (limits = {}) => {
    const form = await create();
    assert.equal(
      (await update(form, { submission_mode: "private", ...limits }))
        .statusCode,
      200,
    );
    const key = (await generate(form)).json().token;
    assert.equal((await update(form, { active: true })).statusCode, 200);
    return { form, key };
  };
  const count = async (form) =>
    (
      await sql`SELECT COUNT(*)::int AS n FROM submissions WHERE form_id=${form.id}`
    )[0].n;
  await t.test(
    "new forms require configuration, owner access and valid origins",
    async () => {
      const form = await create();
      assert.equal(form.active, false);
      assert.ok(form.security_issue);
      assert.equal((await submit(form)).statusCode, 403);
      assert.equal((await update(form, { active: true })).statusCode, 400);
      assert.equal(
        (await app.inject({ url: `/api/forms/${form.id}` })).statusCode,
        401,
      );
      for (const origin of [
        "https://*.example.com",
        "https://site.example/contact",
        "https://user:pass@site.example",
        "null",
      ])
        assert.equal(
          (await update(form, { allowed_origins: [origin] })).statusCode,
          400,
        );
    },
  );
  await t.test(
    "legacy integrations survive edits; upgrade is explicit and irreversible",
    async () => {
      const form = await create();
      await sql`UPDATE forms SET submission_mode='legacy', active=true, hosted_enabled=true, security_configured=false,
      daily_submission_limit=1,daily_notification_limit=0 WHERE id=${form.id}`;
      const before = challengeCalls;
      for (let n = 0; n < 2; n++) {
        const r = await app.inject({
          method: "POST",
          url: `/f/${form.endpoint}`,
          remoteAddress: `198.51.100.${n + 1}`,
          payload: { custom: "old payload", _formto_js: "1" },
        });
        assert.equal(r.statusCode, 200, r.body);
        assert.equal(r.headers["access-control-allow-origin"], "*");
      }
      assert.equal(challengeCalls, before);
      assert.equal(await count(form), 2);
      assert.equal(
        (
          await app.inject({
            method: "OPTIONS",
            url: `/f/${form.endpoint}`,
            headers: { origin: "https://old.example" },
          })
        ).statusCode,
        204,
      );
      const page = await app.inject({ url: `/f/${form.endpoint}` });
      assert.equal(page.statusCode, 200);
      assert.ok(!page.body.includes("cf-turnstile"));
      assert.equal(
        (await update(form, { name: "Still live", notify_email: false }))
          .statusCode,
        200,
      );
      assert.equal((await get(form)).json().form.active, true);
      assert.equal(
        (await update(form, { submission_mode: "public" })).statusCode,
        400,
      );
      assert.equal(
        (
          await update(form, {
            upgrade_security: true,
            submission_mode: "private",
            active: true,
          })
        ).statusCode,
        400,
      );
      assert.equal(
        (
          await update(form, {
            upgrade_security: true,
            submission_mode: "private",
            active: false,
          })
        ).statusCode,
        200,
      );
      assert.equal((await get(form)).json().form.active, false);
      assert.equal(
        (await update(form, { submission_mode: "legacy" })).statusCode,
        400,
      );
      assert.equal((await submit(form)).statusCode, 422);
      assert.equal((await update(form, { active: true })).statusCode, 400);
      await generate(form);
      assert.equal((await update(form, { active: true })).statusCode, 200);
      const createLegacy = await app.inject({
        method: "POST",
        url: "/api/forms",
        headers: auth,
        payload: {
          name: "Forbidden",
          endpoint: `test-${randomUUID()}`,
          submission_mode: "legacy",
        },
      });
      assert.equal(createLegacy.statusCode, 400);
    },
  );
  await t.test('malformed submission requests return safe errors before writing', async () => {
    const form = await create();
    const response = await app.inject({method:'POST',url:`/f/${form.endpoint}`,headers:{'content-type':'application/json'},payload:'{"secret":"do-not-log"'});
    assert.equal(response.statusCode,400);
    assert.equal(response.json().error,'invalid_request');
    assert.ok(!response.body.includes('do-not-log'));
    assert.equal(await count(form),0);
  });
  const browserForm = await create();
  await t.test(
    "public settings persist as objects without returning secrets",
    async () => {
      const response = await update(browserForm, {
        allowed_origins: ["https://site.example"],
        turnstile_site_key: "test-site-key",
        turnstile_secret: "test-turnstile-secret",
        hosted_enabled: true,
        active: true,
      });
      assert.equal(response.statusCode, 200, response.body);
      const stored = (await get(browserForm)).json().form;
      assert.deepEqual(stored.allowed_origins, [
        "https://site.example",
        "https://forms.example.com",
      ]);
      assert.equal(stored.turnstile_secret_configured, true);
      assert.ok(!JSON.stringify(stored).includes("test-turnstile-secret"));
      assert.ok(!Object.hasOwn(stored, "turnstile_secret_encrypted"));
      const [row] = await sql`SELECT * FROM forms WHERE id=${browserForm.id}`;
      assert.notEqual(row.turnstile_secret_encrypted, "test-turnstile-secret");
      assert.equal(
        security.decryptSecret(row.turnstile_secret_encrypted),
        "test-turnstile-secret",
      );
      assert.equal(
        (await update(browserForm, { name: "Rename only" })).statusCode,
        200,
      );
      assert.equal(
        (await get(browserForm)).json().form.turnstile_secret_configured,
        true,
      );
    },
  );
  await t.test(
    "origin and challenge failures cause no writes or notifications",
    async () => {
      const before = challengeCalls;
      for (const origin of ["https://evil.example", "null", ""])
        assert.equal(
          (await submit(browserForm, { headers: { origin } })).statusCode,
          403,
        );
      assert.equal(challengeCalls, before);
      assert.equal(
        (
          await app.inject({
            method: "POST",
            url: `/f/${browserForm.endpoint}`,
            payload,
          })
        ).statusCode,
        403,
      );
      assert.equal(
        (
          await submit(browserForm, {
            payload: { "cf-turnstile-response": "" },
          })
        ).statusCode,
        403,
      );
      for (const behavior of ["wrong-host", "wrong-action", "outage"]) {
        verificationBehavior = behavior;
        assert.equal(
          (await submit(browserForm)).statusCode,
          behavior === "outage" ? 503 : 403,
        );
      }
      verificationBehavior = "normal";
      assert.equal(
        (
          await submit(browserForm, {
            payload: { "cf-turnstile-response": "expired" },
          })
        ).statusCode,
        403,
      );
      assert.equal(await count(browserForm), 0);
      assert.equal(sent, 0);
    },
  );
  await t.test(
    "valid tokens are single use and security fields are stripped",
    async () => {
      const token = randomUUID();
      assert.equal(
        (
          await submit(browserForm, {
            payload: { "cf-turnstile-response": token },
          })
        ).statusCode,
        200,
      );
      assert.equal(
        (
          await submit(browserForm, {
            payload: { "cf-turnstile-response": token },
          })
        ).statusCode,
        403,
      );
      const [row] =
        await sql`SELECT data FROM submissions WHERE form_id=${browserForm.id}`;
      assert.deepEqual(row.data, payload);
    },
  );
  await t.test(
    "preflight, hosted and form-encoded requests use the same policy",
    async () => {
      const preflight = await app.inject({
        method: "OPTIONS",
        url: `/f/${browserForm.endpoint}`,
        headers: { origin: "https://site.example" },
      });
      assert.equal(preflight.statusCode, 204);
      assert.equal(
        preflight.headers["access-control-allow-origin"],
        "https://site.example",
      );
      assert.equal(
        (
          await app.inject({
            method: "OPTIONS",
            url: `/f/${browserForm.endpoint}`,
            headers: { origin: "https://evil.example" },
          })
        ).statusCode,
        403,
      );
      const html = await app.inject({ url: `/f/${browserForm.endpoint}` });
      assert.equal(html.statusCode, 200);
      assert.match(html.body, /cf-turnstile/);
      assert.ok(!html.body.includes("test-turnstile-secret"));
      const response = await app.inject({
        method: "POST",
        url: `/f/${browserForm.endpoint}`,
        headers: {
          origin: "https://forms.example.com",
          "content-type": "application/x-www-form-urlencoded",
        },
        payload: new URLSearchParams({
          ...payload,
          "cf-turnstile-response": randomUUID(),
        }).toString(),
      });
      assert.equal(response.statusCode, 200, response.body);
    },
  );
  await t.test(
    "field rules and honeypots reject or discard without storing",
    async () => {
      const before = await count(browserForm);
      assert.equal(
        (await submit(browserForm, { payload: { unexpected: "no" } }))
          .statusCode,
        400,
      );
      assert.equal(
        (await submit(browserForm, { payload: { email: "invalid" } }))
          .statusCode,
        400,
      );
      assert.equal(
        (await submit(browserForm, { payload: { name: "" } })).statusCode,
        400,
      );
      assert.equal(
        (await submit(browserForm, { payload: { _formto_honeypot: "bot" } }))
          .statusCode,
        200,
      );
      assert.equal(await count(browserForm), before);
      for (const name of [
        "constructor",
        "cf-turnstile-response",
        "_formto_honeypot",
      ])
        assert.equal(
          (
            await update(browserForm, {
              fields: [{ name, label: "Bad", type: "text" }],
            })
          ).statusCode,
          400,
        );
      assert.equal(
        (
          await update(browserForm, {
            fields: [{ name: "file", label: "File", type: "file" }],
          })
        ).statusCode,
        400,
      );
      assert.equal(
        (
          await update(browserForm, {
            fields: [
              ...security.DEFAULT_FIELDS,
              {
                name: "website",
                label: "Website",
                type: "url",
                required: false,
                maxLength: 200,
              },
            ],
          })
        ).statusCode,
        200,
      );
      assert.equal(
        (
          await submit(browserForm, {
            payload: { website: "https://example.com" },
          })
        ).statusCode,
        200,
      );
    },
  );
  await t.test(
    "private credentials are form-scoped, rotatable and revocable",
    async () => {
      const { form, key } = await privateForm();
      const other = await privateForm();
      assert.equal(
        (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
          .statusCode,
        200,
      );
      assert.equal(
        (
          await submit(other.form, {
            headers: { authorization: `Bearer ${key}` },
          })
        ).statusCode,
        401,
      );
      assert.equal(
        (await submit(form, { headers: { authorization: auth.authorization } }))
          .statusCode,
        401,
      );
      assert.equal(
        (await app.inject({ url: `/f/${form.endpoint}` })).statusCode,
        404,
      );
      assert.equal((await get(form)).body.includes(key), false);
      const replacement = (await generate(form)).json().token;
      assert.equal(
        (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
          .statusCode,
        401,
      );
      assert.equal(
        (
          await submit(form, {
            headers: { authorization: `Bearer ${replacement}` },
          })
        ).statusCode,
        200,
      );
      assert.equal(
        (
          await app.inject({
            method: "DELETE",
            url: `/api/forms/${form.id}/submission-key`,
            headers: auth,
          })
        ).statusCode,
        200,
      );
      assert.equal((await get(form)).json().form.active, false);
      assert.equal((await update(form, { active: true })).statusCode, 400);
    },
  );
  await t.test(
    "switching modes invalidates keys without bypassing Turnstile",
    async () => {
      const { form, key } = await privateForm();
      assert.equal(
        (
          await update(form, {
            submission_mode: "public",
            allowed_origins: ["https://site.example"],
            turnstile_site_key: "test-site-key",
            turnstile_secret: "test-turnstile-secret",
          })
        ).statusCode,
        200,
      );
      assert.equal(
        (await get(form)).json().form.submission_key_configured,
        false,
      );
      assert.equal(
        (
          await submit(form, {
            headers: { authorization: `Bearer ${key}` },
            payload: { "cf-turnstile-response": "" },
          })
        ).statusCode,
        403,
      );
      await update(form, { submission_mode: "private" });
      assert.equal((await update(form, { active: true })).statusCode, 400);
    },
  );
  await t.test(
    "daily quotas are atomic and notification suppression preserves submissions",
    async () => {
      const { form, key } = await privateForm({
        daily_submission_limit: 5,
        daily_notification_limit: 2,
      });
      assert.equal(
        (
          await update(form, {
            notify_email: true,
            notification_email: "recipient@example.com",
          })
        ).statusCode,
        200,
      );
      const before = sent;
      const results = await Promise.all(
        Array.from({ length: 8 }, () =>
          submit(form, { headers: { authorization: `Bearer ${key}` } }),
        ),
      );
      assert.equal(
        results.filter((r) => r.statusCode === 200).length,
        5,
        results.map((r) => r.body).join("\n"),
      );
      assert.equal(results.filter((r) => r.statusCode === 429).length, 3);
      assert.equal(sent - before, 2);
      const [usage] =
        await sql`SELECT * FROM form_daily_usage WHERE form_id=${form.id}`;
      assert.equal(usage.submissions, 5);
      assert.equal(usage.notifications, 2);
      const rows =
        await sql`SELECT notification_status FROM submissions WHERE form_id=${form.id}`;
      assert.equal(
        rows.filter((r) => r.notification_status === "suppressed_quota").length,
        3,
      );
      await sql`DELETE FROM submissions WHERE form_id=${form.id}`;
      assert.equal(
        (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
          .statusCode,
        429,
      );
      await sql`UPDATE form_daily_usage SET day=day-1 WHERE form_id=${form.id}`;
      assert.equal(
        (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
          .statusCode,
        200,
      );
    },
  );
  await t.test(
    "attempt limits survive new database connections and reset after expiry",
    async () => {
      const key = `restart-${randomUUID()}`;
      await sql.begin(async tx => {
        for (let i = 0; i < 10; i++) await consumeRate(key, 10, tx);
      });
      const { default: postgres } = await import("postgres");
      const otherPool = postgres(databaseUrl);
      try {
        await otherPool.begin(async tx => {
          const [saved] = await tx`SELECT count FROM submission_rate_limits WHERE key=${security.hashCredential(key)}`;
          assert.equal(saved.count, 10);
          // Keep the persisted count in this transaction's minute so a real
          // wall-clock rollover cannot invalidate the persistence assertion.
          await tx`UPDATE submission_rate_limits SET window_start=date_trunc('minute',NOW()) WHERE key=${security.hashCredential(key)}`;
          await assert.rejects(() => consumeRate(key, 10, tx), e => e.status === 429);
          await tx`UPDATE submission_rate_limits SET window_start=NOW()-INTERVAL '2 minutes' WHERE key=${security.hashCredential(key)}`;
          await consumeRate(key, 10, tx);
        });
      } finally { await otherPool.end(); }
    },
  );
  await t.test(
    "public attempts share IP limits across forms; private failures are limited",
    async () => {
      const first = await create();
      const second = await create();
      const ip = `${ipPrefix}.252`;
      for (let i = 0; i < 10; i++)
        assert.equal(
          (
            await app.inject({
              method: "POST",
              url: `/f/${i % 2 ? first.endpoint : second.endpoint}`,
              remoteAddress: ip,
              payload: {},
            })
          ).statusCode,
          403,
        );
      const limited = await app.inject({
        method: "POST",
        url: `/f/${first.endpoint}`,
        remoteAddress: ip,
        payload: {},
      });
      assert.equal(limited.statusCode, 429);
      assert.ok(Number(limited.headers["retry-after"]) > 0);
      const { form } = await privateForm();
      for (let i = 0; i < 10; i++)
        assert.equal(
          (
            await app.inject({
              method: "POST",
              url: `/f/${form.endpoint}`,
              remoteAddress: ip,
              payload: {},
            })
          ).statusCode,
          401,
        );
      assert.equal(
        (
          await app.inject({
            method: "POST",
            url: `/f/${form.endpoint}`,
            remoteAddress: ip,
            payload: {},
          })
        ).statusCode,
        429,
      );
      assert.equal(await count(form), 0);
    },
  );
  await t.test(
    "failed delivery consumes its reservation and another owner cannot manage keys",
    async () => {
      const { form, key } = await privateForm({ daily_notification_limit: 1 });
      await update(form, {
        notify_email: true,
        notification_email: "recipient@example.com",
      });
      const original = emailHelpers.sendSubmissionNotification;
      emailHelpers.sendSubmissionNotification = async () => {
        throw new Error("local simulated SMTP failure");
      };
      try {
        assert.equal(
          (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
            .statusCode,
          200,
        );
        assert.equal(
          (await submit(form, { headers: { authorization: `Bearer ${key}` } }))
            .statusCode,
          200,
        );
        const [usage] =
          await sql`SELECT notifications FROM form_daily_usage WHERE form_id=${form.id}`;
        assert.equal(usage.notifications, 1);
        const [row] =
          await sql`SELECT COUNT(*)::int AS n FROM submissions WHERE form_id=${form.id} AND notification_status='suppressed_quota'`;
        assert.equal(row.n, 1);
      } finally {
        emailHelpers.sendSubmissionNotification = original;
      }
      const stranger = {
        authorization: `Bearer ${await signToken({ userId: randomUUID() })}`,
      };
      for (const method of ["POST", "DELETE"])
        assert.equal(
          (
            await app.inject({
              method,
              url: `/api/forms/${form.id}/submission-key`,
              headers: stranger,
            })
          ).statusCode,
          404,
        );
      assert.equal(
        (
          await app.inject({
            method: "PUT",
            url: `/api/forms/${form.id}`,
            headers: stranger,
            payload: { active: false },
          })
        ).statusCode,
        404,
      );
    },
  );
  await t.test(
    "rotation prevents an already-verified request from being stored",
    async () => {
      const { form } = await privateForm();
      const snapshot = await dbHelpers.getFormByEndpoint(form.endpoint);
      await generate(form);
      await assert.rejects(
        () => saveWithQuota(snapshot, payload, {}),
        (e) => e.status === 409,
      );
      assert.equal(await count(form), 0);
    },
  );
});
