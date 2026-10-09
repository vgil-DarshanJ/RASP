# Production deployment

One server, one HTTPS host name, Docker. `docker-compose.prod.yml` runs:

| Service | What it does |
|---|---|
| `proxy` | Caddy: obtains and renews the TLS certificate, serves the dashboard (static export of the FE repository) and forwards `/v1/*` and `/healthz` to the backend. Security headers (HSTS, nosniff, frame denial). Only ports 80 and 443 are published. |
| `backend` | The API, built from source (no stale `dist/`), as a non-root user. Applies pending migrations at start. Refuses to start with missing or placeholder secrets (`npm run check:config` checks a `.env`). |
| `postgres`, `redis` | Data and counters, on Docker volumes, not reachable from outside. |
| `backup` | One `pg_dump` a day into `deploy/backups/`, older dumps deleted after `BACKUP_KEEP_DAYS`. |

## First start

1. A Linux server with Docker and Compose, ports 80 and 443 open, and a DNS
   record for your host name pointing at it.
2. Put both repositories side by side on the server, as on the development
   machine: `.../BE` (this one) and `.../FE`.
3. `cp deploy/production.env.example deploy/production.env` and fill it in.
   Generate the secrets on the server (`openssl rand -hex 32` for
   `CREDENTIAL_ENCRYPTION_KEY`, `openssl rand -base64 48` for the others).
   `deploy/production.env` is git-ignored; keep a copy of
   `CREDENTIAL_ENCRYPTION_KEY` in your password manager — without it no
   issued credential can be verified, also not from a backup.
4. Optional malware list: `deploy/reputation/list.json` (see
   `reputation/README.md`) and `REPUTATION_SIGNING_KEY`.
5. Start:
   ```
   docker compose -f deploy/docker-compose.prod.yml --env-file deploy/production.env up -d --build
   ```
6. Check `https://<DOMAIN>/healthz` → `{"ok":true,...}`, then register the
   first account on `https://<DOMAIN>/register`.
7. Issue a credential: it carries `https://<DOMAIN>/v1/events`, which the
   release build of the app accepts (HTTPS only).

## Operations

- Update: `git pull` in both repositories, then the same `up -d --build`.
- Logs: `docker compose -f deploy/docker-compose.prod.yml logs -f backend proxy`.
- Monitoring: point an uptime check at `https://<DOMAIN>/healthz` (it
  checks PostgreSQL and Redis; 503 when either is down).
- Restore a backup into a stopped stack:
  `docker compose ... exec -T postgres pg_restore -U rasp -d rasp_shield --clean < deploy/backups/<file>.dump`
- Copy `deploy/backups/` off the server regularly (another machine or object
  storage); backups on the same disk do not survive a lost server.
- Retention periods are in `production.env` (`RETENTION_*`); the backend
  deletes past-period data once a day.
