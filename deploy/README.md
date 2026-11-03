# Production deployment

Target: `https://auth.vefacaglar.com` on `187.126.24.87`.
The workflow builds a Linux amd64 image. This directory assumes an existing
Docker host, PostgreSQL database, and Caddy reverse proxy. It does not install
them or change DNS. Use Docker Compose 2.30+ (raw environment files).

## CI/CD

`.github/workflows/ci.yml` runs on pull requests, pushes to `main`, and manual
dispatches. It checks formatting, builds, vets, runs race-enabled tests and the
real OIDC client smoke test. It then builds the container and tests the actual
production Compose configuration against a disposable PostgreSQL database,
including repeated migrations, disabled demo seeding, discovery, and JWKS.

Successful `main` runs publish `ghcr.io/vefacaglar/authserver-go:<commit-sha>`.
Deployment uses the immutable image digest. Pull requests never publish or deploy.
Automatic SSH deployment remains disabled until the repository variable
`AUTH_DEPLOY_ENABLED` is set to `true`.

## Configuration through GitHub

No application files or environment files need to be created manually on the
server. CD creates `~/authserver`, uploads the release and environment, logs into
GHCR with the temporary job token, migrates, starts the service and checks health.
It removes temporary uploads and registry credentials afterwards.

In repository **Settings → Secrets and variables → Actions**, add these secrets
(or scope them to the GitHub environment named `production`):

| Secret | Value |
| --- | --- |
| `VPS_HOST` | `187.126.24.87` |
| `VPS_USER` | Existing SSH deployment user with Docker access |
| `VPS_PORT` | Optional SSH port; defaults to `22` |
| `VPS_PASSWORD` | Existing SSH password; no new server-side key installation needed |
| `VPS_SSH_KEY` | Alternative to the password: private key already authorized for this user; takes precedence when set |
| `VPS_KNOWN_HOSTS` | Verified SSH host-key entry; use `[host]:port` for a nonstandard port |
| `AUTH_DB_DSN` | Production PostgreSQL connection string reachable from the VPS |
| `AUTH_ADMIN_TOKEN` | Production admin token |
| `AUTH_SMTP_HOST`, `AUTH_SMTP_PORT`, `AUTH_SMTP_USERNAME`, `AUTH_SMTP_PASSWORD`, `AUTH_SMTP_FROM` | Optional mail settings, each as a separate secret |
| `AUTH_ENV` | Optional complete runtime env file for additional settings or as an alternative to individual secrets |

The simplest setup is to add `AUTH_DB_DSN` and `AUTH_ADMIN_TOKEN` separately,
using only the value in each secret (no `NAME=` prefix). `AUTH_ENV` is not required
when those two secrets exist. Optional SMTP secrets work the same way.

For a complete env file instead, start `AUTH_ENV` with the contents of
`authserver.env.example`, replacing sample values with production values. For example:

```dotenv
AUTH_DB_DSN=postgres://USER:PASSWORD@DB_HOST:5432/DB_NAME?sslmode=require
AUTH_ADMIN_TOKEN=YOUR_EXISTING_ADMIN_TOKEN
AUTH_SMTP_HOST=YOUR_SMTP_HOST
AUTH_SMTP_PORT=587
AUTH_SMTP_USERNAME=YOUR_SMTP_USERNAME
AUTH_SMTP_PASSWORD=YOUR_SMTP_PASSWORD
AUTH_SMTP_FROM=YOUR_SENDER_ADDRESS
```

Include other runtime settings, such as custom paths and token lifetimes, in the
same secret. Use raw `NAME=value` lines: no `export`, shell substitutions or
surrounding quotes. Literal spaces, dollar signs and quotes are preserved, not
executed. `AUTH_DB_DSN` and `AUTH_ADMIN_TOKEN` are required; duplicate or malformed
entries are rejected without printing their contents. Nonempty individual secrets
override matching entries in `AUTH_ENV`; unset individual secrets preserve the
bundled value. Individual secrets must be single-line values. The Compose file still
fixes the production issuer, listening address and security flags (HTTPS on,
seeding/anonymous admin/email-body logging off); these cannot be weakened by the
runtime file.

Add these **repository Actions variables**:

| Variable | Value |
| --- | --- |
| `AUTH_DEPLOY_ENABLED` | `true` to deploy after successful main-branch CI |
| `AUTH_DOCKER_NETWORK` | Existing network shared with the reverse proxy; default `databases_default` |
| `AUTH_BIND_PORT` | Optional loopback port; default `5175` |

Push to `main` or select **Actions → CI and deploy → Run workflow → main**.
Updating a secret alone does not start a deployment; run the workflow to apply it.
Every deploy replaces the complete runtime file, so removing a setting from
GitHub also removes it on the server, unless it remains set in the optional
`AUTH_ENV` file. Files have owner-only permissions.
GitHub is the source of truth; manual server edits would be replaced next time.

No separate registry PAT or server-side `docker login` is needed. The deploy job
has `packages: read` and passes its short-lived `GITHUB_TOKEN` over SSH stdin to a
temporary Docker credential directory. The package must allow this repository to
read it (automatic for packages published by this repository's workflow).

## Existing infrastructure

The host must already provide Docker, Compose 2.30+, `flock`, authorized SSH
access and the configured Docker network. The PostgreSQL DSN must be reachable
from that host. This workflow does not provision a fresh VPS, create a database,
modify another service's proxy configuration, or manage DNS.

`auth.vefacaglar.com` must resolve to `187.126.24.87`, with ports 80/443 reaching
Caddy. The existing proxy must route to `authserver:5175` on the shared network,
or `127.0.0.1:5175` when Caddy runs directly on the host. See `Caddyfile.example`
for the route and forwarding-header configuration. A CDN needs an explicit
trusted-proxy setup. Once that infrastructure is in place, routine deployments
and all runtime configuration changes are handled from GitHub alone.

## Migration from Render

Back up the production database first. Either retain the current database with
a DSN reachable from the VPS, or restore the complete backup into the destination
database during a planned write freeze. Preserve users, clients, scopes, sessions,
refresh tokens, signing keys and `data_protection_keys`. Do not point the new
server at an empty database expecting existing accounts to appear. With demo
seeding disabled, a genuinely new database needs explicit scope/client setup.

Save the existing runtime settings, including SMTP and any custom lifetimes or
paths, in the GitHub `AUTH_ENV` secret. Production migrations now honor `AUTH_SEED=false`; this does not remove
demo accounts that already exist in the source database.

Configure relying applications to use `https://auth.vefacaglar.com` as the issuer
and verify their registered redirect URIs. An issuer change invalidates old JWTs
for clients expecting the new issuer; cookies from the old domain do not transfer.
Plan for users to sign in again. Test a real login, token refresh and password
reset before disabling the Render service. CI's public endpoint checks do not
replace this cutover check.

## Recovery

`deploy.sh` serializes deployments, pulls the requested digest, migrates, and
waits for the JWKS endpoint (which reads persisted signing keys). A failed
migration restores the previous environment and leaves the running service
untouched. A failed container health check restores the previous environment,
healthy image and Compose file if one exists. First deploys
have no previous image. Public HTTPS checks run after this local health gate;
DNS/proxy failures fail the workflow but do not trigger an image rollback.

Successful deploys record `.current-image`, `.previous-image` and
`.last-good-compose.yml`. To recover from a later application regression without
SSH, revert the faulty application change in GitHub and deploy `main` again. For
configuration regressions, restore the previous `AUTH_ENV` secret or repository
variables and select **Run workflow**. Schema changes must remain backward
compatible: image/configuration rollback does not reverse a database migration
or restore database data.

References: [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images),
[Compose environment files](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/).
