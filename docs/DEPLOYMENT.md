# Deployment — dudenest-backend

**Status**: Production
**Last Updated**: 2026-05-21 (s313 prevention guards added)

---

## Overview

`dudenest-backend` is deployed to NETOL Docker Swarm cluster (managers: node001/005/006/007) via a single GitHub Actions workflow. There is **no manual deploy path** for production — see [Operator safety rules](#operator-safety-rules) below.

```
push to main / workflow_dispatch
  └─ GitHub-hosted runner: go test + docker buildx + GHCR push
  └─ self-hosted runner (label: netol-swarm): envsubst + docker stack deploy + smoke test
     └─ Traefik routes api.dudenest.com → dudenest-backend_server
```

## Required GitHub Secrets

The deploy workflow reads these from `secrets.DUDENEST_*` (set in repo Settings → Secrets → Actions):

| Secret | Maps to env var in container | Used in |
|--------|------------------------------|---------|
| `DUDENEST_DB_URL` | `DB_URL` | (reserved — not yet used) |
| `DUDENEST_REDIS_URL` | `REDIS_URL` | (reserved) |
| `DUDENEST_REDIS_PASSWORD` | `REDIS_PASSWORD` | redis service |
| `DUDENEST_JWT_SECRET` | `JWT_SECRET` | `internal/auth/jwt.go` — sign/verify JWT |
| `DUDENEST_HEADSCALE_API_URL` | `HEADSCALE_API_URL` | (reserved) |
| `DUDENEST_HEADSCALE_API_KEY` | `HEADSCALE_API_KEY` | (reserved) |
| `DUDENEST_GOOGLE_CLIENT_ID` | `GOOGLE_CLIENT_ID` | `internal/auth/oauth.go` — Google Sign-In |
| `DUDENEST_GOOGLE_CLIENT_SECRET` | `GOOGLE_CLIENT_SECRET` | OAuth code exchange |
| `DUDENEST_GITHUB_CLIENT_ID` | `GITHUB_CLIENT_ID` | optional — GitHub Sign-In |
| `DUDENEST_GITHUB_CLIENT_SECRET` | `GITHUB_CLIENT_SECRET` | optional |
| `DUDENEST_APPLE_CLIENT_ID` | `APPLE_CLIENT_ID` | optional |
| workflow env | `DEMO_ENABLED=true` | enables `/auth/demo` for public demo login |
| workflow env | `DEMO_USER_ID=google:106774657231866582065` | demo user bound to `relay-demo` |
| workflow env | `DEMO_USER_EMAIL=dudenest.demo@gmail.com` | demo user email |
| `RESEND_API_KEY` | `RESEND_API_KEY` | `internal/email/resend.go` — relay mnemonic email |
| `BACKUP_URL` | `BACKUP_URL` | `cmd/server/main.go` — proxy `/api/v1/relays` to `dudenest-backup` |

The workflow `Deploy stack to Docker Swarm` step exposes each as an env var, then `envsubst < docker/backend/docker-stack.yml` interpolates `${VAR}` placeholders into a temp file before `docker stack deploy`.

## Fail-fast on missing env (s313 guard)

`cmd/server/main.go` calls `requireEnv()` at startup with the **minimum production set**:

```go
func main() {
    requireEnv("JWT_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "BACKUP_URL")
    // ... rest of startup
}

func requireEnv(keys ...string) {
    var missing []string
    for _, k := range keys {
        if os.Getenv(k) == "" { missing = append(missing, k) }
    }
    if len(missing) > 0 {
        log.Fatalf("FATAL: required env vars missing: %s — refusing to start with partial config (s313 guard)", strings.Join(missing, ", "))
    }
}
```

**Effect**: container that starts without these env vars calls `log.Fatalf` (exit 1) → Swarm `restart_policy: on-failure max_attempts: 3` retries → after 3 fails task is marked failed → `update_config: failure_action: rollback` reverts to previous good spec.

**Why these 4 specifically**:
- `JWT_SECRET` — without it `auth.ValidateJWT` falls back to `"dev-secret-change-in-prod"` → no Flutter session works.
- `GOOGLE_CLIENT_ID` / `_SECRET` — Google is the only operating Sign-In provider; without these every login attempt returns 503.
- `BACKUP_URL` — `makeBackupProxy` requires this; without it `/api/v1/relays` returns 503 → Flutter can't load relay list → user sees broken UI.

Other env vars (`RESEND_API_KEY`, `GITHUB_*`, `APPLE_*`) are **optional** — the code logs a warning and disables that feature. They are not in `requireEnv`.

### Why not just `os.Exit(1)` everywhere?

The guard is centralized to make adding/removing required vars a one-line change. `log.Fatalf` ensures structured logging output for forensics (`journalctl -u docker` captures container stderr).

## Post-deploy smoke test (s313 guard)

The `Build and Deploy` workflow runs a smoke test **after** `Verify deployment` (which only checks replica count):

```yaml
- name: Smoke test — OAuth endpoint must redirect (s313 prevention)
  run: |
    set +e
    for i in 1 2 3 4 5 6; do
      CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
        "https://api.dudenest.com/auth/google?return_url=https%3A%2F%2Fdudenest.com%2F")
      echo "  attempt $i/6 — HTTP $CODE"
      [ "$CODE" = "302" ] && { echo "✅ /auth/google redirects (env vars present)"; exit 0; }
      sleep 10
    done
    echo "❌ /auth/google did not return 302 after 60s — env vars likely missing on backend service."
    exit 1
```

**What it actually verifies**: the public OAuth start endpoint reads `os.Getenv("GOOGLE_CLIENT_ID")` and returns 302 (redirect to Google) iff it's non-empty. A 302 from the public URL proves:

1. Cloudflare → HAProxy ns2 → Traefik → container routing works end-to-end
2. Traefik has the right container to route to (`com.docker.stack.namespace=dudenest-backend` label + traefik labels match)
3. The container actually reads the env var in runtime (not just present in spec — e.g., catches case where Swarm spec has env but container was started before the env was added)
4. The handler chain (`corsMiddleware → mux → startGoogle`) runs without panic

**What it does NOT verify**: `GOOGLE_CLIENT_SECRET` validity (Google rejects at callback, not at start), `JWT_SECRET` consistency with Flutter, `BACKUP_URL` reachability, redis/DB connections, full OAuth flow with real Google token exchange.

**Budget**: 60s (6 retries × 10s) — Swarm rolling update with `order: start-first, parallelism: 1, delay: 10s` typically converges in 20-30s; first success exits immediately.

**Failure behavior**: workflow exits 1 (red badge, GitHub notification). Does NOT auto-rollback at this layer — `update_config: failure_action: rollback` already handles that during convergence. Smoke test fail at this point means "container is up but app is broken" — operator alert, not auto-recovery, because root cause needs investigation (e.g., env var typo in workflow, wrong secret value).

## Operator safety rules

**🔴 Never do this in production**:

```bash
# Manually editing /tmp/*.yml on a Swarm manager:
vim /tmp/backend-stack.yml          # ❌
docker stack deploy -c /tmp/... dudenest-backend  # ❌ NUKES env vars

# Force-redeploying with hand-written YAML:
docker stack rm dudenest-backend && docker stack deploy -c minimal.yml dudenest-backend  # ❌

# Skipping CI for "quick test":
ssh root@<node> "docker service update --env-rm GOOGLE_CLIENT_ID dudenest-backend_server"  # ❌
```

**Why**: `docker stack deploy` is **declarative**. The deployed spec replaces the running spec wholesale. Missing fields in the YAML (`environment:`, `secrets:`, `env_file:`) become **null** in the new spec → all env vars are wiped. See `~/.AI/dudenest-application/session-2026-05-21-prod-incident-oauth.md` for the 2026-05-20 incident where this exact pattern took down OAuth for 24 hours.

**✅ Always do this instead**:

```bash
# Test traefik routing without touching prod:
# Use a separate stack name (won't conflict with prod):
vim /tmp/routing-experiment.yml
docker stack deploy -c /tmp/routing-experiment.yml routing-experiment
# ... test ...
docker stack rm routing-experiment

# Force redeploy backend (rebuild from main):
gh workflow run "Build and Deploy" --repo dudenest/dudenest-backend --ref main

# Test a code change before merging to main:
git checkout -b feat/test-thing
git push -u origin feat/test-thing
gh workflow run "Build and Deploy" --repo dudenest/dudenest-backend --ref feat/test-thing
# Deploy goes through full envsubst + smoke test on the feature branch
```

## Rollback

If smoke test fails (or you notice prod is broken):

```bash
# 1. Identify the previous working image SHA
gh run list --workflow "Build and Deploy" --limit 5
# Note the headSha of the last successful run BEFORE the bad one

# 2. Re-run that specific run (re-deploys old SHA):
gh run rerun <RUN_ID>

# Alternatively, revert the offending commit + push:
git revert <BAD_SHA>
git push origin main
# Triggers fresh deploy of the reverted state
```

Swarm's own `rollback_config` only auto-rollbacks during the convergence window of a single deploy — it won't help if the deploy "succeeded" but the app is logically broken (e.g., wrong secret value). That's what the smoke test catches.

## Verification (manual)

```bash
# OAuth start endpoint must redirect to Google:
curl -sI "https://api.dudenest.com/auth/google?return_url=https%3A%2F%2Fdudenest.com%2F" | head -3
# Expected: HTTP/2 302 + location: https://accounts.google.com/o/oauth2/v2/auth?...

# Health check (no env vars needed):
curl -s "https://api.dudenest.com/health"
# Expected: {"status":"ok",...}

# Env vars are present in spec (forensic):
ssh root@10.51.1.221 'docker service inspect dudenest-backend_server \
  --format "{{range .Spec.TaskTemplate.ContainerSpec.Env}}{{println .}}{{end}}"' | grep -c GOOGLE
# Expected: 2 (CLIENT_ID and CLIENT_SECRET)
```

## Files

- `cmd/server/main.go` — `main()` + `requireEnv()` + handlers
- `.github/workflows/deploy.yml` — Build, push, deploy, verify, smoke test
- `docker/backend/docker-stack.yml` — Swarm compose template (read by envsubst at deploy time)
- `docker/backend/.env.example` — local dev env template (NOT used in production deploy)

## References

- Incident report: `~/.AI/dudenest-application/session-2026-05-21-prod-incident-oauth.md`
- Operator runbook: `~/.AI/dudenest-application/INCIDENT-RUNBOOK.md`
- Per-user relay routing: `~/.AI/dudenest-application/RELAY-URL-ROUTING.md`
