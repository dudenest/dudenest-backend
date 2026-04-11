# dudenest-backend

![Version](https://img.shields.io/badge/Version-v0.4.1-blue) ![Last Update](https://img.shields.io/badge/Update-2026--04--12-lightgrey)

![Status](https://img.shields.io/badge/Status-Pre--Alpha-orange) ![Language](https://img.shields.io/badge/Language-Go-00ADD8) ![License](https://img.shields.io/badge/License-Apache%202.0-green) ![Infra](https://img.shields.io/badge/Infra-NETOL%20Docker%20Swarm-blue)

**The SaaS backend for Dudenest — metadata, auth, signaling. Zero file content.**

The Dudenest Backend is the central coordination layer. It handles user authentication, file metadata (filenames, dates, thumbnails references), Relay signaling via Headscale, and the optional Relay rental marketplace. **It never stores, processes, or sees any file content or encryption keys.**

## What Backend Does (and Does NOT)

### ✅ DOES
- User authentication (email/password, Google OAuth, Apple Sign-in)
- File metadata storage (name, date, GPS, tags, thumbnail ID, block count)
- Relay registration and signaling (Headscale coordination)
- Storage account registry (which cloud accounts does user have, NOT tokens)
- Relay rental marketplace (users renting spare Relay capacity)
- Push notifications (new uploads, sync complete)
- Search index (metadata-only: date, location, tags, faces)

### ❌ NEVER DOES
- Store file content (blocks)
- Store encryption keys
- Store cloud provider tokens (those stay on Relay)
- See decrypted file data

## Architecture

```
Internet
    │
    ▼
NETOL HAProxy (ns2) — TLS + Coraza WAF
    │
    ▼
Traefik (Docker Swarm)
    │
    ▼
dudenest-backend (this service)
    ├── PostgreSQL (metadata DB)
    ├── Redis (sessions, cache, rate limiting)
    └── Headscale (WireGuard coordination)
```

**Deployment**: NETOL Docker Swarm (existing infrastructure)
**Domain**: api.dudenest.com (planned)
**Headscale**: headscale.netol.io (existing, shared with NETOL)

## API — Implemented

### Health
```
GET /health   → {"status":"ok","uptime":"...","service":"dudenest-backend"}
```

### Auth (OAuth2 redirect flow)
```
GET /auth/google                   → redirect to Google OAuth
GET /auth/github                   → redirect to GitHub OAuth
GET /auth/apple                    → redirect to Apple OAuth
GET /auth/callback/google          → exchange code → issue JWT → redirect to app
GET /auth/callback/github          → exchange code → issue JWT → redirect to app
```

OAuth callback redirects to `$APP_URL?token=JWT&user=base64(JSON)`.

JWT: HS256, 30-day expiry, payload: `{sub, email, name, avatar, provider, iat, exp}`.

### Not implemented yet
```
/api/v1/*    → 501 Not Implemented
```

## Environment Variables

| Variable | Required | Example | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | yes | `changeme-32chars` | HS256 signing key |
| `APP_URL` | yes | `https://dudenest.com` | Where to redirect after auth |
| `GOOGLE_CLIENT_ID` | OAuth | `123.apps.googleusercontent.com` | Google OAuth app |
| `GOOGLE_CLIENT_SECRET` | OAuth | `GOCSPX-...` | Google OAuth secret |
| `GITHUB_CLIENT_ID` | OAuth | `Ov23liXxx` | GitHub OAuth app |
| `GITHUB_CLIENT_SECRET` | OAuth | `...` | GitHub OAuth secret |
| `APPLE_CLIENT_ID` | OAuth | `com.dudenest.web` | Apple Service ID |
| `PORT` | no | `8080` | HTTP port (default: 8080) |

## OAuth App Setup

### Google
1. GCP Console → APIs & Services → Credentials → Create OAuth 2.0 Client
2. Application type: Web application
3. Authorized redirect URI: `https://api.dudenest.com/auth/callback/google`
4. Set `GOOGLE_CLIENT_ID` + `GOOGLE_CLIENT_SECRET` in GitHub Secrets

### GitHub
1. GitHub → Settings → Developer settings → OAuth Apps → New OAuth App
2. Homepage URL: `https://dudenest.com`
3. Authorization callback URL: `https://api.dudenest.com/auth/callback/github`
4. Set `GITHUB_CLIENT_ID` + `GITHUB_CLIENT_SECRET` in GitHub Secrets

### Apple
Full implementation requires `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY` + POST callback (Apple sends `form_post`). See `internal/auth/oauth.go`.

## Project Structure

```
cmd/server/         # Entry point
internal/
├── auth/           # JWT, OAuth2 flows
├── metadata/       # File metadata CRUD
├── signaling/      # Relay <> App signaling (Headscale)
├── accounts/       # Storage account registry
├── relay_rental/   # Relay marketplace
├── billing/        # Stripe payments
├── notifications/  # Push notifications
├── storage/        # Thumbnail storage (metadata only)
├── search/         # Full-text search
└── admin/          # Admin API
pkg/
├── middleware/     # Auth, rate limiting, logging
├── database/       # PostgreSQL wrapper
├── cache/          # Redis wrapper
└── types/          # Shared types
migrations/         # SQL migrations (golang-migrate)
docs/
├── architecture/   # System design documents
├── api/            # OpenAPI spec
└── database/       # Schema documentation
```

## Running Locally

```bash
git clone https://github.com/dudenest/dudenest-backend.git
cd dudenest-backend

# Dependencies
docker compose up -d postgres redis

# Run
cp .env.example .env
go run cmd/server/main.go
```

## Deployment

Deployed via NETOL Docker Swarm. See `dudenest-infra` (private) for Ansible playbooks.

```bash
# Via NETOL CI/CD (GitLab pipeline → Docker Swarm)
git push origin main
# Triggers: build → test → deploy to Swarm
```

## Database

PostgreSQL with migrations via `golang-migrate`:

```bash
migrate -path migrations/ -database $DATABASE_URL up
```

## License

Apache License 2.0

---

**Author**: Dariusz Porczyński
**Organization**: https://github.com/dudenest

## Changelog

### v0.4.1 — 2026-04-12 — Release Sync
- 📦 **Ecosystem Sync**: Unified versioning across all components.
- 🚀 **GitHub Release**: First official release for backend.

### v0.4.0 — 2026-04-11 — Security & Auth
- 🔐 **Shared JWT Secret**: Enabled JWT signature sharing for Relay validation.
- 🔑 **Backend-as-Auth-Server**: Centralized token issuing for federated Relay access.
