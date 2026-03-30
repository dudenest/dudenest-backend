# Headscale Integration — Dudenest Relay Tunneling

**Author**: Dariusz Porczyński
**Date**: 2026-03-30
**Status**: Design document (pre-implementation)

---

## Overview

Dudenest uses the existing **NETOL Headscale instance** as the WireGuard coordination server (control plane). This allows Relay nodes installed at user homes to establish secure tunnels with the Dudenest app — without requiring any port forwarding or public IP address on the user's router.

## Existing Headscale Infrastructure (NETOL)

Headscale was deployed on NETOL Docker Swarm in December 2025:

```
┌─────────────────────────────────────────────────────────┐
│                    NETOL Infrastructure                  │
│                                                         │
│  Internet → HAProxy ns2 (206.189.31.117)                │
│      │                                                  │
│      ├── :443 → Coraza WAF → Traefik → Headscale API   │
│      │         URL: https://headscale.netol.io          │
│      │                                                  │
│      └── :50443 → TCP passthrough → Headscale gRPC     │
│                   (WireGuard clients, no WAF)           │
│                                                         │
│  Headscale replicas: 3/3 (node003, canada-ovh, sydney) │
│  Database: CockroachDB (3-node cluster)                 │
│  Admin UI: https://headscale-ui.netol.io (Headplane)   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Key facts from NETOL sessions (2025-12-21 to 2026-03-11):**
- Headscale 0.23.0 deployed on Docker Swarm (GlusterFS persistent volumes)
- CockroachDB as database backend (3-node HA cluster)
- HAProxy handles TLS termination + Coraza WAF for HTTP/API traffic
- gRPC port 50443 has direct TCP passthrough (required for WireGuard handshakes)
- Headplane (admin UI) deployed at headscale-ui.netol.io

## Dudenest-Specific Configuration

### Dedicated Namespace

Dudenest Relay nodes use a dedicated Headscale namespace to isolate them from other NETOL VPN users:

```bash
headscale namespaces create dudenest-relays
# Lists namespace: headscale namespaces list
```

### How Relay Registration Works

```
User onboards new Relay
       │
       ▼
Dudenest Backend API: POST /api/v1/relay/register
       │
       ▼
Backend calls Headscale API:
  POST https://headscale.netol.io/api/v1/preauthkey
  { namespace: "dudenest-relays", ephemeral: false, reusable: false }
       │
       ▼
Backend returns pre-auth key to Relay
       │
       ▼
Relay runs: tailscale up --login-server=https://headscale.netol.io --authkey=<key>
       │
       ▼
Relay is now registered in Headscale namespace "dudenest-relays"
       │
       ▼
Dudenest App connects to Relay via WireGuard mesh
```

### Relay ↔ App Connection

The Dudenest App connects to the user's Relay through the WireGuard mesh managed by Headscale:

```
Dudenest App (mobile/desktop)
       │
       │ WireGuard (via Headscale coordination)
       │
       ▼
User's Relay (Raspberry Pi at home)
       │
       │ Direct HTTP (within WireGuard mesh)
       │
       ▼
Relay API (port 8088 — not exposed publicly)
```

**NAT Traversal**: Headscale coordinates WireGuard hole-punching. If direct P2P fails, traffic falls back through DERP relays (configured in Headscale: tailscale.com/derp/map).

## ACL Policy (HuJSON)

Headscale ACL isolates Dudenest Relay nodes:

```json
{
  "groups": {
    "group:dudenest-relays": ["tag:dudenest-relay"],
    "group:netol-admins": ["porczynski@netol.io"]
  },
  "tagOwners": {
    "tag:dudenest-relay": ["group:netol-admins"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:dudenest-relay"],
      "dst": ["tag:dudenest-relay:*"]
    }
  ]
}
```

## Backend API Requirements

The Dudenest Backend needs a Headscale API key to:
1. Create pre-auth keys for new Relay registrations
2. List registered Relay nodes for a user
3. Delete nodes when Relay is deregistered

```bash
# Generate Headscale API key (on NETOL admin)
headscale apikeys create --expiration 3650d
# Store as: HEADSCALE_API_KEY in backend secrets (Ansible Vault)
```

## Connection Diagram: Full E2E Flow

```
User's Phone (Dudenest App)
  │
  │ [1] HTTPS → api.dudenest.com (HAProxy ns2 → Traefik → Backend)
  │     "Give me list of files"
  │     Backend returns: file metadata + relay_node_id
  │
  │ [2] WireGuard (Headscale-managed mesh)
  │     App connects to Relay via WireGuard IP (100.x.x.x)
  │
  ▼
User's Relay (Raspberry Pi at home)
  │
  │ [3] HTTPS → Google Drive, MEGA, OneDrive
  │     Download encrypted blocks
  │
  │ [4] Decrypt + reconstruct file locally
  │
  │ [5] Stream decrypted file → App via WireGuard tunnel
  ▼
User sees their photo/video
```

## References

- NETOL Headscale deployment sessions: `~/.AI/netol-infrastructure/session-2025-12-21-headscale-*.md`
- Headscale architecture analysis: `~/.AI/netol-infrastructure/HEADSCALE-ARCHITECTURE-ANALYSIS.md`
- Headscale user guide: `~/.AI/netol-infrastructure/HEADSCALE-USER-GUIDE.md`
- Headscale admin: https://headscale-ui.netol.io (ZeroTier-restricted access)

---

**Author**: Dariusz Porczyński
