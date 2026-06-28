---
title: "Noisy Penguins"
summary: "UMCS Preliminary umcs preliminary, web, forensics writeup covering Noisy Penguins with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - web
  - forensics
  - reverse-engineering
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Noisy_Penguins
**Category:** Forensics / Steganography
**Points:** 300
**Flag Format:** `UMCS{...}`
**Provided File:** `Noisy_Penguins.mkv`
**Reference:** The challenge references a “Noot Noot Translator,” which translates normal language into “Noot Noot” style text. This supports the penguin/Pingu theme but is not the actual decoding mechanism used to recover the flag. ([Anything Translate](https://anythingtranslate.com/translators/noot-noot-translator/ "Noot Noot Translator | Free & AI-Powered"))

The goal of the challenge is to inspect the provided MKV video file and recover the hidden flag. The visible hint says:

```text
“Noot noot! Noot Pingu. noot noot hide-and-seek noot Pingu friend, noot!”
```

This suggests that something is being hidden in a noisy or penguin-themed media file.

---

# Initial Analysis

We start by checking the uploaded file type:

```bash
file Noisy_Penguins.mkv
```

Expected output:

```text
Noisy_Penguins.mkv: Matroska data
```

The file is an **MKV / Matroska** container. MKV files can contain multiple streams such as video, audio, subtitles, metadata, and attachments.

A normal first step in a multimedia forensics challenge is to inspect the container:

```bash
ffprobe Noisy_Penguins.mkv
```

However, the important observation is not only the video/audio stream. The file contains a hidden attachment. Using FFmpeg’s attachment extraction feature, we can dump embedded files from the MKV container:

```bash
ffmpeg -dump_attachment:t "" -i Noisy_Penguins.mkv
```

This extracts an embedded file:

```text
PINGU.mp4
```

At this point, the challenge becomes a layered forensics task:

```text
Noisy_Penguins.mkv
        |
        v
embedded attachment: PINGU.mp4
        |
        v
subtitle stream
        |
        v
Base64 fragments
        |
        v
flag
```

---

# Vulnerability / Weakness Identification

There is no traditional memory corruption or web vulnerability in this challenge.

The weakness is that the flag data is hidden using **container-level steganography**:

1. The original file is an MKV container.

2. The MKV contains an attached file named `PINGU.mp4`.

3. The attached MP4 contains subtitle text.

4. The subtitle text contains Base64-looking fragments.

5. Some Base64 fragments are decoys.

6. The correct fragments must be joined and decoded.


The challenge title, **Noisy_Penguins**, and the “noot noot” text attempt to distract the solver toward sound/audio analysis or the external translator. The actual flag is hidden in a nested media attachment and then encoded as Base64.

---

# Exploitation Strategy

The cleanest solving strategy is:

1. Identify the file as an MKV container.

2. Extract embedded attachments from the MKV.

3. Locate the extracted `PINGU.mp4`.

4. Inspect the MP4 for subtitle streams.

5. Extract the subtitle stream into `.srt` format.

6. Read the subtitle text.

7. Identify Base64 fragments.

8. Remove fake/decoy chunks.

9. Concatenate the useful Base64 fragments.

10. Decode the final string to recover the flag.


The useful subtitle chunks are:

```text
VU1DU3thc2
MxMV9wM25H
dTFuX24wMHR9
```

When joined:

```text
VU1DU3thc2MxMV9wM25HdTFuX24wMHR9
```

Base64-decoding this gives:

```text
UMCS{asc11_p3nGu1n_n00t}
```

---

# Proof of Concept

Create a working directory:

```bash
mkdir noisy_penguins_work
cd noisy_penguins_work
```

Copy the challenge file into the working directory:

```bash
cp ../Noisy_Penguins.mkv .
```

Extract attachments from the MKV:

```bash
ffmpeg -dump_attachment:t "" -i Noisy_Penguins.mkv
```

Expected extracted file:

```text
PINGU.mp4
```

Check the extracted file:

```bash
file PINGU.mp4
```

Expected output:

```text
PINGU.mp4: ISO Media, MP4 Base Media
```

Extract the subtitle stream from `PINGU.mp4`:

```bash
ffmpeg -i PINGU.mp4 -map 0:s:0 subs.srt
```

Read the subtitles:

```bash
cat subs.srt
```

The subtitle file contains Base64-like chunks:

```text
VU1DU3thc2
RkFLRV9GbEFn
MxMV9wM25H
dTFuX24wMHR9
TmV2ZXJHb25uYUdpdmVZb3VVcA==
```

Decode the obvious decoys:

```bash
echo 'RkFLRV9GbEFn' | base64 -d
```

Output:

```text
FAKE_FlAg
```

Another decoy:

```bash
echo 'TmV2ZXJHb25uYUdpdmVZb3VVcA==' | base64 -d
```

Output:

```text
NeverGonnaGiveYouUp
```

Therefore, remove the decoy chunks and join the remaining useful Base64 fragments:

```bash
echo -n 'VU1DU3thc2MxMV9wM25HdTFuX24wMHR9' | base64 -d
```

Expected output:

```text
UMCS{asc11_p3nGu1n_n00t}
```

---

# Full Python Solver

Save the following script as `solve_noisy_penguins.py`:

```python
#!/usr/bin/env python3
import argparse
import base64
import itertools
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


FLAG_REGEX = re.compile(rb"UMCS\{[^}\r\n]{1,100}\}")
B64_REGEX = re.compile(r"^[A-Za-z0-9+/=]{6,}$")


def run_command(cmd, cwd=None, allow_fail=False):
    """
    Run an external command and return the completed process.

    FFmpeg is used because this challenge hides data inside media containers.
    """
    print(f"[+] Running: {' '.join(cmd)}")

    proc = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode != 0 and not allow_fail:
        print("[!] Command failed.")
        print(proc.stderr)
        sys.exit(1)

    return proc


def check_dependency(name):
    """
    Ensure a required command exists on the system.
    """
    if shutil.which(name) is None:
        print(f"[!] Missing dependency: {name}")
        print(f"    Install it first. On Kali/Debian/Ubuntu:")
        print(f"    sudo apt install ffmpeg")
        sys.exit(1)


def extract_mkv_attachments(mkv_path, workdir):
    """
    Extract attachments from the MKV file.

    The command may return a non-zero code because no output video file is specified.
    That is acceptable as long as the attachment is dumped successfully.
    """
    before = set(os.listdir(workdir))

    run_command(
        ["ffmpeg", "-y", "-dump_attachment:t", "", "-i", str(mkv_path)],
        cwd=workdir,
        allow_fail=True,
    )

    after = set(os.listdir(workdir))
    created = sorted(after - before)

    print("[+] Files created by attachment extraction:")
    for item in created:
        print(f"    {item}")

    mp4_files = [Path(workdir) / item for item in created if item.lower().endswith(".mp4")]

    if not mp4_files:
        print("[!] No MP4 attachment found.")
        print("    Check the FFmpeg output manually.")
        sys.exit(1)

    return mp4_files[0]


def extract_subtitles(mp4_path, workdir):
    """
    Extract the first subtitle stream from the MP4 file as an SRT file.
    """
    srt_path = Path(workdir) / "subs.srt"

    run_command(
        [
            "ffmpeg",
            "-y",
            "-i",
            str(mp4_path),
            "-map",
            "0:s:0",
            str(srt_path),
        ],
        cwd=workdir,
    )

    if not srt_path.exists():
        print("[!] Subtitle extraction failed. subs.srt was not created.")
        sys.exit(1)

    return srt_path


def extract_base64_tokens(srt_path):
    """
    Parse the SRT file and collect lines that look like Base64 fragments.

    SRT files usually contain:
    - subtitle index numbers
    - timestamps
    - subtitle text

    We only want the subtitle text lines that look like Base64.
    """
    tokens = []

    with open(srt_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if "-->" in line:
                continue

            if line.isdigit():
                continue

            if B64_REGEX.match(line):
                tokens.append(line)

    print("[+] Base64-looking tokens found:")
    for token in tokens:
        print(f"    {token}")

    if not tokens:
        print("[!] No Base64-like tokens found in subtitles.")
        sys.exit(1)

    return tokens


def b64decode_lenient(data):
    """
    Decode Base64 even if padding is missing.
    """
    data = data.strip()
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data + padding, validate=False)


def recover_flag_from_tokens(tokens):
    """
    Try every ordered subset of Base64 tokens.

    This is useful because the subtitle contains decoy chunks.
    The real flag is created by joining only selected chunks.
    """
    candidates = []

    for r in range(1, len(tokens) + 1):
        for combo in itertools.combinations(tokens, r):
            joined = "".join(combo)

            try:
                decoded = b64decode_lenient(joined)
            except Exception:
                continue

            for match in FLAG_REGEX.findall(decoded):
                flag = match.decode("utf-8", errors="ignore")
                candidates.append((flag, combo, decoded))

    if not candidates:
        print("[!] No flag found from Base64 token combinations.")
        sys.exit(1)

    # Prefer the shortest valid flag. Decoy chunks usually make longer fake candidates.
    candidates.sort(key=lambda item: len(item[0]))

    print("[+] Candidate flags:")
    for flag, combo, _ in candidates:
        print(f"    {flag}    from chunks: {combo}")

    return candidates[0][0]


def main():
    parser = argparse.ArgumentParser(
        description="Solver for the Noisy_Penguins CTF challenge"
    )
    parser.add_argument(
        "mkv",
        help="Path to Noisy_Penguins.mkv",
    )
    parser.add_argument(
        "-o",
        "--out",
        default="noisy_penguins_out",
        help="Output working directory",
    )

    args = parser.parse_args()

    check_dependency("ffmpeg")

    mkv_path = Path(args.mkv).resolve()

    if not mkv_path.exists():
        print(f"[!] File not found: {mkv_path}")
        sys.exit(1)

    workdir = Path(args.out).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    print(f"[+] Input MKV: {mkv_path}")
    print(f"[+] Workdir:   {workdir}")

    mp4_path = extract_mkv_attachments(mkv_path, workdir)
    print(f"[+] Extracted MP4 attachment: {mp4_path}")

    srt_path = extract_subtitles(mp4_path, workdir)
    print(f"[+] Extracted subtitle file: {srt_path}")

    tokens = extract_base64_tokens(srt_path)
    flag = recover_flag_from_tokens(tokens)

    print()
    print("[+] Final flag:")
    print(flag)


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Install Dependencies

This solver uses FFmpeg to inspect and extract data from media containers.

On Kali, Debian, or Ubuntu:

```bash
sudo apt update
sudo apt install ffmpeg -y
```

Verify FFmpeg is installed:

```bash
ffmpeg -version
```

---

## 2. Place the Challenge File and Solver Together

Example directory:

```text
Noisy_Penguins.mkv
solve_noisy_penguins.py
```

Make the script executable:

```bash
chmod +x solve_noisy_penguins.py
```

---

## 3. Run the Solver

```bash
python3 solve_noisy_penguins.py Noisy_Penguins.mkv
```

Expected important output:

```text
[+] Files created by attachment extraction:
    PINGU.mp4

[+] Extracted MP4 attachment: noisy_penguins_out/PINGU.mp4
[+] Extracted subtitle file: noisy_penguins_out/subs.srt

[+] Base64-looking tokens found:
    VU1DU3thc2
    RkFLRV9GbEFn
    MxMV9wM25H
    dTFuX24wMHR9
    TmV2ZXJHb25uYUdpdmVZb3VVcA==

[+] Candidate flags:
    UMCS{asc11_p3nGu1n_n00t}

[+] Final flag:
UMCS{asc11_p3nGu1n_n00t}
```

---

## Troubleshooting Notes

If the script says:

```text
Missing dependency: ffmpeg
```

Install FFmpeg:

```bash
sudo apt install ffmpeg -y
```

If no MP4 attachment is found, run the attachment extraction manually:

```bash
ffmpeg -dump_attachment:t "" -i Noisy_Penguins.mkv
ls -la
```

If subtitle extraction fails, inspect the extracted MP4:

```bash
ffprobe PINGU.mp4
```

Look for a subtitle stream such as:

```text
Stream #0:x: Subtitle
```

Then manually extract it:

```bash
ffmpeg -i PINGU.mp4 -map 0:s:0 subs.srt
```

---

# Flag

The recovered flag is:

```text
UMCS{asc11_p3nGu1n_n00t}
```

---

# Conclusion

The challenge hides the flag using a layered multimedia steganography technique. The visible “noot noot” and Pingu theme act as hints and mild distractions, but the real solution is to inspect the MKV container structure.

The key lesson is:

```text
Always inspect container metadata, attachments, and subtitle streams in media forensics challenges.
```

The solving chain is:

```text
MKV file
 -> hidden MP4 attachment
 -> subtitle stream
 -> Base64 fragments
 -> remove decoys
 -> decode flag
```

Final flag:

```text
UMCS{asc11_p3nGu1n_n00t}
```
