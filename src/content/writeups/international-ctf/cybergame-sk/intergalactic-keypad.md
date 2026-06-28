---
title: "Intergalactic Keypad"
summary: "CyberGame.SK cybergame sk, forensics, reverse engineering writeup covering Intergalactic Keypad with analysis, solution steps, and final recovery notes."
date: 2026-05-18
tags:
  - ctf
  - cybergame-sk
  - forensics
  - reverse-engineering
  - malware-analysis
  - cryptography
category: "international-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://scontent.fkul11-2.fna.fbcdn.net/v/t39.30808-1/638315334_912211214722245_1753300060671872827_n.jpg?stp=dst-jpg_tt6&cstp=mx180x180&ctp=s180x180&_nc_cat=105&ccb=1-7&_nc_sid=2d3e12&_nc_ohc=tmZZ3tgT6bwQ7kNvwGoDB83&_nc_oc=AdoJZqRKxReRj76CRTP46td-B7AaAkrMrDS2ghidHSGCPZQNz6wXSKnMjvyeQ-UJgSHUwYcx5DrUHcoHmVsz8zFB&_nc_zt=24&_nc_ht=scontent.fkul11-2.fna&_nc_gid=y1Q08Jq9DhDlqGjKjQUDEg&_nc_ss=7b289&oh=00_Af_Ow3s347ZkjkRHjGV77tVd8INvQ45jyBC3iw6yTuzRqA&oe=6A3ACF21"
---
## 1. Challenge Overview

**Challenge:** Intergalactic - Keypad
**Category:** Reverse Engineering / Crypto
**Goal:** Recover the correct keypad passcode and use it as the password for the encrypted ZIP archive.
**Provided files:**

```text
intergalactic_keypad.exe
flag.zip
```

The challenge description gives the main hint:

> “Beneath a layer of arithmetic noise lies a deterministic check.”

That tells us the binary likely contains obfuscated arithmetic, but the passcode validation is still deterministic and recoverable.

---

## 2. Reconnaissance and Initial Observations

First, identify both files:

```bash
file intergalactic_keypad.exe
file flag.zip
```

Output:

```text
intergalactic_keypad.exe: PE32+ executable for MS Windows, x86-64, GUI
flag.zip: Zip archive data
```

List the ZIP contents:

```bash
unzip -l flag.zip
```

Output:

```text
Archive:  flag.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  1258457  2026-03-19 00:30   the_boss.png
---------                     -------
```

The archive contains one PNG file, but it is encrypted.

Next, inspect strings in the executable:

```bash
strings -a intergalactic_keypad.exe | grep -iE "correct|wrong|pass|random"
```

Interesting strings:

```text
Correct!
Wrong passcode.
random_device: rdrand failed
random_device: rand_s failed
random_device: rdseed failed
```

The `random_device` strings are misleading runtime/library noise. The actual passcode logic is deterministic.

---

## 3. Technical Analysis

Disassemble the binary:

```bash
objdump -d -M intel intergalactic_keypad.exe > disasm.txt
```

The important verification flow is around the keypad submit routine.

Relevant logic:

```asm
call   0x140014270        ; main passcode checker
test   al, al
je     fail

call   0x1400139b0        ; secondary hash / guardian check
cmp    eax, 0xfd4e8cd4
jne    fail
```

The main checker at `0x140014270` performs these checks:

1. Input length must be `0x15`, which is **21 digits**.

2. Every character must be numeric.

3. Each digit is passed through arithmetic helper functions.

4. The result is compared against embedded target tables.

5. A final accumulator must equal:


```text
0xf178ad4b
```

The secondary guardian hash must equal:

```text
0xfd4e8cd4
```

After simplifying the arithmetic noise, each position only has one valid digit.

Recovered digit table:

|Position|Digit|
|--:|--:|
|0|1|
|1|9|
|2|3|
|3|9|
|4|4|
|5|7|
|6|5|
|7|7|
|8|2|
|9|9|
|10|3|
|11|5|
|12|7|
|13|9|
|14|2|
|15|3|
|16|9|
|17|8|
|18|4|
|19|7|
|20|3|

Therefore, the passcode is:

```text
193947572935792398473
```

---

## 4. Root Cause / Vulnerability

The weakness is **client-side deterministic secret validation**.

The ZIP password is not protected by a server or external verification. Instead, the executable contains all validation logic and all constants needed to recover the correct passcode.

Even though the binary uses arithmetic obfuscation, the logic is still reversible because:

```text
same input + same constants = same output
```

So once the validator is understood, the passcode can be recovered offline.

---

## 5. Exploitation Plan

The exploitation path is:

1. Identify that `flag.zip` is password-protected.

2. Reverse `intergalactic_keypad.exe`.

3. Locate the passcode checker.

4. Determine the required input length: 21 digits.

5. Simplify the arithmetic helper functions.

6. Recover the unique digit for each passcode position.

7. Use the recovered passcode as the ZIP password.

8. Extract `the_boss.png`.

9. Read the flag from the image.


---

## 6. Proof of Concept

Minimal PoC:

```bash
unzip -P '193947572935792398473' flag.zip -d out_flag
```

Expected result:

```text
Archive:  flag.zip
 extracting: out_flag/the_boss.png
```

Open the extracted image:

```bash
xdg-open out_flag/the_boss.png
```

The flag appears as text at the top of the image.

---

## 7. Full Python Exploit / Solver

Save this as `solve.py`:

```python
#!/usr/bin/env python3
from pathlib import Path
import zipfile
import sys


PASSCODE = "193947572935792398473"
FLAG = "SK-CERT{MB4_1n_Th3_D4yl1ghT_cL4rity_1n_Th3_Gr4v3}"


def extract_zip(zip_path: Path, output_dir: Path, password: str) -> list[Path]:
    """
    Extracts the encrypted ZIP using the recovered keypad passcode.
    """
    if not zip_path.exists():
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    extracted_files = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()

        if not names:
            raise RuntimeError("ZIP archive is empty.")

        for name in names:
            try:
                data = zf.read(name, pwd=password.encode())
            except RuntimeError as err:
                raise RuntimeError("Wrong ZIP password or encrypted file read failed.") from err

            out_file = output_dir / name
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_bytes(data)
            extracted_files.append(out_file)

    return extracted_files


def main():
    zip_path = Path("flag.zip")
    output_dir = Path("out_flag")

    print("[+] Intergalactic - Keypad solver")
    print(f"[+] Recovered keypad passcode: {PASSCODE}")

    try:
        extracted = extract_zip(zip_path, output_dir, PASSCODE)
    except Exception as err:
        print(f"[-] Error: {err}")
        sys.exit(1)

    print("[+] ZIP decrypted successfully")

    for file in extracted:
        print(f"[+] Extracted: {file}")

        # Basic validation for the extracted PNG.
        magic = file.read_bytes()[:8]
        if magic == b"\x89PNG\r\n\x1a\n":
            print("[+] Extracted file is a valid PNG image")

    print(f"[+] Flag: {FLAG}")


if __name__ == "__main__":
    main()
```

---

## 8. Running the Solver

No external Python packages are required.

```bash
python3 solve.py
```

Or, using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
python3 solve.py
```

---

## 9. Expected Output

```text
[+] Intergalactic - Keypad solver
[+] Recovered keypad passcode: 193947572935792398473
[+] ZIP decrypted successfully
[+] Extracted: out_flag/the_boss.png
[+] Extracted file is a valid PNG image
[+] Flag: SK-CERT{MB4_1n_Th3_D4yl1ghT_cL4rity_1n_Th3_Gr4v3}
```

---

## 10. Flag

![pasted-image-20260502122457](/images/writeups/international-ctf/cybergame-sk/intergalactic-keypad/pasted-image-20260502122457.png)

```text
SK-CERT{MB4_1n_Th3_D4yl1ghT_cL4rity_1n_Th3_Gr4v3}
```

---

## 11. Conclusion

The challenge hides a ZIP password behind a Windows keypad application. The executable looks noisy because it uses many arithmetic helper functions, opaque predicates, rotations, XORs, and target tables. However, the check is fully deterministic.

After reversing the validation routine, the correct 21-digit passcode is recovered:

```text
193947572935792398473
```

Using that passcode decrypts `flag.zip`, extracts `the_boss.png`, and reveals the flag visually inside the image. The main lesson is that obfuscation only slows reverse engineering; it does not protect a secret when the full validation logic and constants are shipped inside the client binary.
