# dudenest-backend

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

## API Overview

### Authentication
```
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/oauth/google
POST /api/v1/auth/oauth/apple
```

### Files (Metadata)
```
GET    /api/v1/files           # List files (paginated, date range)
GET    /api/v1/files/:id       # Get file metadata
POST   /api/v1/files           # Register new file (from Relay)
PUT    /api/v1/files/:id       # Update metadata (tags, albums)
DELETE /api/v1/files/:id       # Delete file record
GET    /api/v1/files/timeline  # Timeline view (grouped by date)
GET    /api/v1/files/search    # Search by date/location/tag/face
```

### Relay
```
POST   /api/v1/relay/register      # Register new Relay
GET    /api/v1/relay/status        # Get relay status
GET    /api/v1/relay/headscale-key # Get Headscale auth key for Relay
DELETE /api/v1/relay/:id           # Unregister Relay
```

### Storage Accounts
```
GET    /api/v1/storage/accounts    # List user's cloud accounts (no tokens)
POST   /api/v1/storage/accounts    # Add new storage account
DELETE /api/v1/storage/accounts/:id
GET    /api/v1/storage/capacity    # Total available capacity
```

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
