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

## Server preparation

Create `~/authserver` under the SSH deployment user's home. That user needs
Docker access and the `flock` command. Copy these files from `deploy/`:

```sh
mkdir -p ~/authserver
chmod 700 ~/authserver
cp compose.yml deploy.sh ~/authserver/
cp .env.example ~/authserver/.env
cp authserver.env.example ~/authserver/authserver.env
chmod 600 ~/authserver/.env ~/authserver/authserver.env
```

Set `AUTH_DOCKER_NETWORK` in `~/authserver/.env` to the **existing** network shared
with Caddy (and PostgreSQL, if hosted locally). `databases_default` is only an
example. Port 5175 binds to loopback; use `AUTH_BIND_PORT` if it is occupied.

Put the production `AUTH_DB_DSN`, `AUTH_ADMIN_TOKEN`, and current SMTP settings in
`~/authserver/authserver.env`. This is a raw env file: no shell substitutions or
surrounding quotes. These secrets stay on the server; CI does not upload them.
The Compose file enforces HTTPS, disables anonymous admin access, email-body
logging, startup migrations, and demo seeding. Migrations run as a separate step.

For a private GHCR package, log in on the server **as the deployment user** using
a GitHub token with `read:packages` access to this package:

```sh
printf '%s' "$GHCR_READ_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

Add the block in `Caddyfile.example` to the existing Caddy configuration, validate
and reload it, and point the domain's A record to `187.126.24.87`. Remove a stale
AAAA record unless IPv6 also reaches this server. Ports 80/443 must reach Caddy.
The proxy example overwrites forwarded client IP headers; start with DNS-only
resolution. A CDN needs its own trusted-proxy configuration.

## GitHub configuration

In repository **Settings → Secrets and variables → Actions**, add these secrets
(or scope them to a GitHub environment named `production`):

| Secret | Value |
| --- | --- |
| `VPS_HOST` | `187.126.24.87` |
| `VPS_USER` | SSH deployment user |
| `VPS_PORT` | SSH port, optional; defaults to `22` |
| `VPS_SSH_KEY` | Dedicated deployment private key; authorize its public key on the server |
| `VPS_KNOWN_HOSTS` | Verified SSH host-key entry; include `[host]:port` for a nonstandard port |

Verify the host-key fingerprint through the server console before saving the
known-hosts entry. The workflow enforces strict SSH host-key checking.
`GITHUB_TOKEN` is supplied automatically and publishes the image; no registry
write credential needs to be stored on the server.

Once the server, database, DNS and proxy are ready, set the **repository Actions
variable** `AUTH_DEPLOY_ENABLED=true`. Push to `main` or manually run **CI and
deploy** on `main`. Keep this variable unset during preparation: CI and image
publishing still run, but SSH deployment is skipped.

## Migration from Render

Back up the production database first. Either retain the current database with
a DSN reachable from the VPS, or restore the complete backup into the destination
database during a planned write freeze. Preserve users, clients, scopes, sessions,
refresh tokens, signing keys and `data_protection_keys`. Do not point the new
server at an empty database expecting existing accounts to appear. With demo
seeding disabled, a genuinely new database needs explicit scope/client setup.

Copy the existing runtime settings, including SMTP and any custom lifetimes or
paths. Production migrations now honor `AUTH_SEED=false`; this does not remove
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
migration leaves the running service untouched. A failed container health check
restores the previous healthy image and Compose file if one exists. First deploys
have no previous image. Public HTTPS checks run after this local health gate;
DNS/proxy failures fail the workflow but do not trigger an image rollback.

Successful deploys record `.current-image`, `.previous-image` and
`.last-good-compose.yml`. To roll back the image after a later regression:

```sh
cd ~/authserver
AUTH_IMAGE=$(cat .previous-image) docker compose --env-file .env -f compose.yml up -d --wait --wait-timeout 120 authserver
```

Check compatibility with the current Compose file first; retain previous release
files separately for configuration rollbacks. After a manual rollback, update
`.current-image` to the restored digest. Image rollback does **not** reverse schema
migrations or restore database data; schema changes must remain backward compatible.

References: [GitHub image publishing](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images),
[Compose environment files](https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/).
