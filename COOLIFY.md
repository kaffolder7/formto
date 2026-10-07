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
networks. PostgreSQL is accessible only over Docker networking.

## Generated variables

| Variable | Purpose |
| --- | --- |
| `SERVICE_URL_CADDY` | Public URL and allowed dashboard origin |
| `SERVICE_PASSWORD_POSTGRES` | Shared password for PostgreSQL and the backend |
| `SERVICE_PASSWORD_64_JWT` | 64-character signing secret |

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

The SQL files in `backend/migrations` initialize a **fresh** database through
PostgreSQL's `docker-entrypoint-initdb.d`. They do not automatically run against
an existing volume on each deploy. Review future upstream schema changes and
apply any required migrations deliberately after taking a backup.

Each service has a health check. `/health` checks backend database connectivity;
the frontend check verifies the static app. After deployment, also check
`/api/auth/setup-status` and the dashboard in a browser to verify routing.

See [Coolify's Compose documentation](https://coolify.io/docs/applications/builds/docker-compose)
for generated variables, domains, and Git deployment behavior.
