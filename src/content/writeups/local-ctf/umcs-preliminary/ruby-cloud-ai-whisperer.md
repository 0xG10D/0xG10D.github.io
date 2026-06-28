---
title: "Cloud AI Whisperer"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Cloud AI Whisperer with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Cloud AI Whisperer
**Category:** Forensics / Misc
**Points:** 250
**Flag Format:** `UMCS{}`
**Provided File:** `cloud_debug.log`

The challenge provides a debug log from an AWS Lambda AI inference job. The objective is to inspect the log file and recover a hidden secret accidentally leaked by an engineer in the debug output.

The final goal is to extract and decode the sensitive value from the log to recover the flag.

---

# Initial Analysis

We are given a single file:

```bash
cloud_debug.log
```

First, identify the file type:

```bash
file cloud_debug.log
```

Expected output:

```text
cloud_debug.log: ASCII text
```

Since it is a plain text log file, we can inspect it directly:

```bash
cat cloud_debug.log
```

Relevant log content:

```text
[2026-04-23 08:01:08] DEBUG - Internal system config snapshot:
[2026-04-23 08:01:08] DEBUG - >> deploy_env=production
[2026-04-23 08:01:08] DEBUG - >> model_version=2.4.1
[2026-04-23 08:01:08] DEBUG - >> auth_token=[REDACTED_TOKEN]
[2026-04-23 08:01:08] DEBUG - >> encoding=base64
```

The suspicious value is:

```text
auth_token=[REDACTED_TOKEN]
```

The next line explicitly states:

```text
encoding=base64
```

This is a strong hint that the leaked token is Base64-encoded.

---

# Vulnerability / Weakness Identification

The weakness is **sensitive information disclosure through debug logging**.

The Lambda job prints an internal configuration snapshot to the debug log. This snapshot includes an `auth_token`, which should never be exposed in plaintext logs, even if encoded.

The important leaked fields are:

```text
auth_token=[REDACTED_TOKEN]
encoding=base64
```

Base64 is not encryption. It is only an encoding scheme. Anyone with access to the log can decode the value.

---

# Exploitation Strategy

The solving strategy is simple:

1. Open the log file.

2. Search for suspicious values such as `token`, `auth`, `secret`, `flag`, or `UMCS`.

3. Identify the leaked `auth_token`.

4. Observe that the log says the token is encoded using Base64.

5. Decode the Base64 string.

6. Extract the `UMCS{...}` flag from the decoded result.


The leaked value is:

```text
VU1DU3tjbDB1ZF80SV93aDFzcDNyM3J9
```

Decoding it as Base64 gives the flag.

---

# Proof of Concept

A quick manual solve can be done with Linux command-line tools.

Search for suspicious keywords:

```bash
grep -i "token\|secret\|flag\|encoding\|UMCS" cloud_debug.log
```

Expected output:

```text
[2026-04-23 08:01:08] DEBUG - >> auth_token=[REDACTED_TOKEN]
[2026-04-23 08:01:08] DEBUG - >> encoding=base64
```

Decode the token:

```bash
echo 'VU1DU3tjbDB1ZF80SV93aDFzcDNyM3J9' | base64 -d
```

Expected output:

```text
UMCS{cl0ud_4I_wh1sp3r3r}
```

---

# Full Python Solver

```python
#!/usr/bin/env python3
import base64
import re
import sys
from pathlib import Path


def extract_auth_token(log_data: str) -> str:
    """
    Extract the auth_token value from the log file.
    Expected format:
        auth_token=[REDACTED_TOKEN]
    """
    match = re.search(r"auth_token=([A-Za-z0-9+/=]+)", log_data)

    if not match:
        raise ValueError("Could not find auth_token in the log file.")

    return match.group(1)


def decode_base64_token(token: str) -> str:
    """
    Decode the Base64 token into a readable string.
    """
    try:
        decoded_bytes = base64.b64decode(token, validate=True)
        return decoded_bytes.decode("utf-8", errors="replace")
    except Exception as error:
        raise ValueError(f"Failed to decode Base64 token: {error}")


def extract_flag(decoded_text: str) -> str:
    """
    Extract the UMCS{} flag from the decoded text.
    """
    match = re.search(r"UMCS\{[^}]+\}", decoded_text)

    if not match:
        raise ValueError("Decoded text did not contain a UMCS{} flag.")

    return match.group(0)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <log_file>")
        sys.exit(1)

    log_path = Path(sys.argv[1])

    if not log_path.is_file():
        print(f"Error: File not found: {log_path}")
        sys.exit(1)

    log_data = log_path.read_text(errors="replace")

    token = extract_auth_token(log_data)
    print(f"[+] Extracted auth_token: {token}")

    decoded_text = decode_base64_token(token)
    print(f"[+] Decoded token: {decoded_text}")

    flag = extract_flag(decoded_text)
    print(f"[+] Flag: {flag}")


if __name__ == "__main__":
    main()
```

---

# Walkthrough

Save the solver as:

```bash
solve.py
```

Run it against the provided log file:

```bash
python3 solve.py cloud_debug.log
```

Expected output:

```text
[+] Extracted auth_token: VU1DU3tjbDB1ZF80SV93aDFzcDNyM3J9
[+] Decoded token: UMCS{cl0ud_4I_wh1sp3r3r}
[+] Flag: UMCS{cl0ud_4I_wh1sp3r3r}
```

No external Python dependencies are required. The script only uses standard Python libraries:

```python
base64
re
sys
pathlib
```

Troubleshooting notes:

If the script says:

```text
Could not find auth_token in the log file.
```

then confirm the correct file path was provided.

If the script says:

```text
Failed to decode Base64 token
```

then the extracted token may contain extra characters, whitespace, or may not be valid Base64.

---

# Flag

The decoded flag is:

```text
UMCS{cl0ud_4I_wh1sp3r3r}
```

---

# Conclusion

The challenge demonstrates a common cloud security mistake: leaking sensitive data through debug logs.

The Lambda inference job printed an internal configuration snapshot, including an `auth_token`. Although the token was Base64-encoded, Base64 provides no confidentiality. Once the token was discovered in the log, decoding it immediately revealed the flag.

Key lesson:

Debug logs must never expose secrets, tokens, credentials, API keys, or internal configuration values. Sensitive values should be redacted before logging, especially in production cloud environments.
