---
slug: "local-ctf/bahtera-3108-2025/supermokh"
event: "bahtera-3108-2025"
title: "SuperMokh"
summary: "Bahtera 3108 2025 web writeup for SuperMokh, escalating a guest session to admin by modifying and replacing a JWT authentication token."
date: 2025-08-30
tags:
  - ctf
  - bahtera-3108
  - web-exploitation
  - jwt
  - authentication
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
---

# Challenge Overview

- **Challenge:** SuperMokh
- **Category:** Web
- **Points:** 100
- **Historical challenge URL:** `https://supermokh.bahterasiber.my/`

> Di padang hijau berlari laju, SuperMokh gol tiada terhenti, Walau zaman sudah berlalu, Adakah anda peminat sejati?

![SuperMokh login page](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/login-page.png)

Viewing the page source reveals a Base64-encoded comment.

![Base64 value in the page source](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/source-code-hint.png)

## Log In as Guest

Decoding that value reveals the credentials:

![Decoded guest credentials](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/base64-credentials.png)

```text
Username: guest
Password: Selangor1972_1987
```

![Logging in as guest](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/guest-login.png)

The guest account can reach the flag view but receives an access-denied message because only `SuperMokh` is permitted.

![Guest access denied](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/access-denied.png)

![Authentication token in the browser](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/auth-token.png)

## Modify the JWT

Open the authentication token in [jwt.io](https://www.jwt.io/). Decode it, then change the username and role to the following values:

```json
{
  "username": "SuperMokh",
  "role": "admin",
  "iat": 1756887574,
  "exp": 1756891174
}
```

![JWT decoder](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/jwt-decoder.png)

Encode the modified payload to obtain a replacement token.

![JWT encoder](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/jwt-encoder.png)

The challenge artifact records this new `auth_token`:

```text
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IlN1cGVyTW9raCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc1Njg4NzU3NCwiZXhwIjoxNzU2ODkxMTc0fQ.lAPknTrocwVblWezD1TmCsgnAiIyxR26ltyszZmXx4I
```

Replace the browser's existing token with this value, refresh the page, and return to the protected view to display the flag.

![SuperMokh flag page](/images/writeups/local-ctf/bahtera-3108-2025/supermokh/flag-page.png)

## Flag

```text
3108{m0kht4r_d4h4r1_l3g3nd_n3v3r_d13s}
```
