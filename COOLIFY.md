# Deploy FormTo with Coolify

Use a Git-based application with the **Docker Compose** build pack. This keeps
the deployment definition in your fork and lets Coolify build the app from it.

1. Add the repository to your chosen project, environment, and server.
2. Select the branch containing these files. Set the base directory to `/` and
   Docker Compose Location to `/docker-compose.coolify.yml`.
3. Load the Compose file. Leave **Raw Compose Deployment** off so Coolify can
   generate secrets and proxy labels.
4. Assign an HTTPS domain to the `caddy` service, using container port **80**.
   Keep the other services' domain fields empty. Use the generated domain or
   point your own domain's DNS at the server.
5. Check that `SERVICE_URL_CADDY` matches the public origin, including `https://`
   and without a trailing slash or `:80`. The backend uses it for dashboard CORS.
6. Deploy, then open the domain and immediately complete the first-run account
   wizard. Until that account exists, anyone who reaches the wizard can claim it.

Use this Compose file **on its own**, not as an override of `docker-compose.yml`.
No `formto.env` file is needed. Coolify terminates TLS and forwards HTTP to Caddy,
which routes `/api/*`, `/f/*`, and `/health` to the backend and other paths to the
frontend. There are no published host ports, fixed container names, or external
networks. PostgreSQL is accessible only over Docker networking. Small Dockerfiles
package Caddy's config and PostgreSQL's initialization SQL into their images, so
no repository bind mounts or "Preserve repository" option are needed.

## Generated variables

| Variable | Purpose |
| --- | --- |
| `SERVICE_URL_CADDY` | Public URL and allowed dashboard origin |
| `SERVICE_PASSWORD_POSTGRES` | Shared password for PostgreSQL and the backend |
| `SERVICE_PASSWORD_64_JWT` | 64-character signing secret |
| `SERVICE_PASSWORD_64_SETTINGS` | Persistent encryption key for Turnstile secrets |

Coolify stores generated values and reuses them on redeployment. Do not replace
the database password after initialization without also changing it inside
PostgreSQL. Changing the JWT secret invalidates existing login tokens.

SMTP is optional. Configure notifications in **Account > Notifications**, or set
the `SMTP_*` and `FROM_EMAIL` variables in Coolify for an instance-wide fallback.
Use a sender accepted by your SMTP provider. `LOG_LEVEL` and `MAX_FILE_SIZE_MB`
are also configurable. Upstream's OSS upload storage adapter is a no-op; changing
the file-size limit does not enable persistent file attachments.

## Storage and updates

The `postgres_data` named volume holds all accounts, forms, and submissions.
Back it up with `pg_dump` and test restoration before upgrades. Never delete the
volume to fix a deployment failure.

Fresh volumes initialize from `001_init.sql`. Backend startup applies versioned
upgrades transactionally to both fresh and existing databases. Back up before
upgrading and read the submission-security rollout notes below.

Each service has a health check. `/health` checks backend database connectivity;
the frontend check verifies the static app. After deployment, also check
`/api/auth/setup-status` and the dashboard in a browser to verify routing.

See [Coolify's Compose documentation](https://coolify.io/docs/applications/builds/docker-compose)
for generated variables, domains, and Git deployment behavior.

## Submission security upgrade

Existing forms retain their activation state, endpoints, hosted pages, and anonymous
submission behavior in **Legacy security** mode. Accounts and stored submissions
are preserved. Prominent warnings identify this mode in the dashboard and settings.
Only the migration can assign legacy mode: new forms cannot select it, and upgraded
forms cannot return to it. Legacy forms keep their previous payload validation and
honeypot behavior, with persistent per-IP rate limits and improved proxy handling.
Origin restrictions, Turnstile, field schemas, and daily quotas do not apply until
upgrade. Legacy daily usage is tracked so usage before an upgrade is not refunded.

For each legacy form, open **Submission security → Set up security upgrade**.
Saving with `upgrade_security: true` and a public/private mode explicitly opts in
and pauses the form. Configure security, review its field names against your existing
integration, update that integration, then activate. Cancel before saving to keep
legacy behavior. Ordinary edits to notification/basic settings do not upgrade forms.
For a coordinated cutover, prepare the website/server changes before opting in.
New forms always start inactive and require security setup.

Before deploying, back up PostgreSQL. Reload the Compose definition so Coolify
creates `SERVICE_PASSWORD_64_SETTINGS`, the dedicated encryption key for
Turnstile secrets. Keep this value stable across deployments and preserve it
alongside your database backup. Changing or losing it requires re-entering every
Turnstile secret. It is separate from the JWT and SMTP credentials.

The backend runs versioned migrations before opening its HTTP listener. Migrations
are transactional, recorded with checksums, and serialized with a PostgreSQL
advisory lock. Startup fails if migration or encryption-key validation fails.
Initialization SQL still bootstraps fresh PostgreSQL volumes; backend migrations
also handle upgrades to existing volumes. Never recreate the volume to upgrade.
Do not edit an applied migration. Add a new version instead.

If rolling back application code, deactivate submission endpoints first. Older
code does not enforce the new protection settings. Restore the matching database
backup when a full rollback is required; do not drop new columns from a live DB.

### Public forms

1. In Cloudflare, create a Turnstile widget and register the hostnames where the
   form will appear. Cloudflare hostname registration and FormTo's allowed-origin
   list are separate controls.
2. In FormTo, select **Public website**, enter exact allowed HTTPS origins, and
   enter the widget's site key and secret. The secret is write-only and encrypted.
   An origin includes scheme, hostname, and optional port, but no path or wildcard.
3. Review allowed fields and limits, then save. Turnstile verification is mandatory.
   Tokens must match the requesting hostname and the form-specific action shown
   in the integration example. Missing/null origins and verification outages fail
   closed. The widget resets after each attempt so a fresh token can be obtained.
4. Optionally enable the hosted page. FormTo adds `PUBLIC_ORIGIN`, supplied by
   `SERVICE_URL_CADDY`, to the allowlist. Add that hostname to the Turnstile widget.
5. Activate the form and use its generated HTML, JavaScript, or React example.

In local development only, HTTP origins on localhost or loopback are permitted.
Use Cloudflare's documented test widgets only in development. The settings UI
must never expose the secret, and the browser snippets contain only the site key.

### Private integrations

Select **Private server integration**, save, and generate a submission key. Copy
it immediately into your website backend's secret environment. Send it as
`Authorization: Bearer <key>` when POSTing JSON to the form endpoint. Keys are
scoped to one form, stored as hashes, and cannot be retrieved later. Rotation
immediately invalidates the old key; revocation also deactivates the form.
Changing modes revokes the key. Private forms have no hosted page or public fallback.
Your website backend must handle its own visitor spam/bot protection. Never put
a private submission key or an account JWT in a browser integration.

### Proxy trust and Cloudflare

`TRUSTED_PROXY_CIDRS` identifies the reverse proxies whose forwarded address chain
Fastify may trust. The Coolify defaults cover private Docker networks; narrow them
to your actual proxy networks when possible. Backend/PostgreSQL ports must remain
unpublished. Other containers on a trusted network are inside this trust boundary.
Do not enable Traefik's `forwardedHeaders.insecure` option.

`TRUST_CLOUDFLARE` defaults to `false`. For a proxied Cloudflare hostname, enable it
only after verifying the chain. The app honors `CF-Connecting-IP` only when the
nearest non-local peer, resolved by Fastify, is in Cloudflare's published proxy
networks. Direct-origin clients cannot authorize that header just by supplying it.
If the chain is not trusted correctly, limits may group requests by proxy address.
Never fix that by trusting every incoming forwarded header.

Verification at deployment: compare logged client IPs through Cloudflare and via
the direct origin; a forged `X-Forwarded-For` or `CF-Connecting-IP` must not change
the identity of a direct-origin request. Verify actual gateway configuration before
trusting forwarding from additional proxies. The test suite models sanitized
Traefik ingress plus an inner proxy using real local HTTP connections; it does not
change or certify your shared production proxy configuration.

Cloudflare IP ranges are pinned in `backend/utils/clientIp.js`; review them against
https://www.cloudflare.com/ips/ when changing the proxy setup. This PR does not alter
shared-server firewall, Traefik, or Cloudflare account settings.

### Limits and storage

Public attempts have persistent limits of 10/minute per client IP across forms
and per form/IP. Private attempts have a 10/minute limit per credential, with a
separate 10/minute/IP failure limit. These fixed-minute counters live in PostgreSQL;
expired rate-limit records are cleaned every five minutes. A boundary burst can
span adjacent minute windows. The existing global 200/minute/IP edge-in-app limit
remains an additional in-memory safeguard.

For new and explicitly upgraded forms, daily defaults are 500 accepted submissions and 100 notification events per form,
resetting at midnight UTC. Settings support 1–1,000,000 accepted submissions and
0–1,000,000 notification events per day. Each accepted event may fan out to the
configured email, messaging, and webhook channels. Reserved attempts count even
when delivery fails; the quota is not a delivery guarantee or retry queue.

Once the notification quota is reached, submissions continue to be stored up to
the submission quota and are labeled `suppressed_quota`. Suppressed notifications
are not replayed automatically. Archiving/deleting submissions does not refund
quota. Counter reservation and submission insertion share one transaction.

Allowed field definitions are persisted and enforced server-side. Unexpected
fields, invalid choices/types, and oversized values are rejected. File uploads
remain unavailable. The dedicated `_formto_honeypot` and `cf-turnstile-response`
fields are stripped before storage; ordinary fields such as `website` are allowed
when configured.

### Validation

Use a disposable PostgreSQL database whose name contains `test`. The integration
suite mocks external verification/delivery and never sends real notification mail.

```sh
cd backend
npm ci
TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55439/formto_security_test node --test tests/*.test.js
cd ../frontend
npm ci
npm test
npm run build
```

The migration tests create and drop temporary databases, so their local test user
needs `CREATEDB`. Never point this suite at production. The settings encryption
key used in tests is a dummy value and must not be copied into deployment.
