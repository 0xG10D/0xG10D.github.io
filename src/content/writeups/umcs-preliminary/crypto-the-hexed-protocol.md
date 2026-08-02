---
slug: "local-ctf/umcs-preliminary/crypto-the-hexed-protocol"
event: "umcs-preliminary"
title: "The Hexed Protocol"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering The Hexed Protocol with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - cryptography
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** The Hexed Protocol
**Category:** Crypto / Forensics
**Points:** 500
**Flag Format:** `UMCS{}`
**Provided Files:**

```text
vault_dump.txt
scraps.md
```

The challenge provides two important artifacts:

1. `vault_dump.txt` — a long hexadecimal blob representing an encrypted vault.

2. `scraps.md` — an internal HR memo describing the required vault password format.


The objective is to reconstruct the vault, recover the password using the HR policy, decrypt the vault, and extract the hidden flag.

---

# Initial Analysis

The file `vault_dump.txt` contains only hexadecimal characters. This suggests that the actual binary vault was converted into hex.

Reconstructing it conceptually:

```bash
xxd -r -p vault_dump.txt vault.kdbx
```

Inspecting the first bytes of the reconstructed file gives:

```text
03 d9 a2 9a 67 fb 4b b5 01 00 03 00
```

Interpreted as little-endian values:

```text
0x9AA2D903
0xB54BFB67
0x00030001
```

These are KeePass/KDBX magic bytes. Therefore, the dump is a hex-encoded KeePass database.

The parsed KDBX header shows:

```text
Cipher: AES
Compression: gzip
KDF rounds: 1000
Vault type: KDBX 3.x
```

The HR memo provides the critical password structure:

```text
[Core Company Value] + [4-Digit Department PIN] + [One Special Character]
```

It also states that only the first letter of the core value should be capitalized, and the possible core values are:

```text
SYNERGY, DISRUPTION, PIVOT, AGILITY, PARADIGM
```

So the normalized password prefixes are:

```text
Synergy
Disruption
Pivot
Agility
Paradigm
```

---

# Vulnerability / Weakness Identification

The weakness is not a flaw in AES or KeePass itself.

The actual issue is a **weak and predictable password policy**.

The password format reduces the keyspace to:

```text
5 core values × 10,000 PINs × special characters
```

Using a common special-character set such as:

```text
@!#$%&*?
```

the search space becomes:

```text
5 × 10,000 × 8 = 400,000 candidates
```

This is small enough for an offline mask attack.

The database uses only 1,000 AES-KDF rounds, which is also low for a password vault. That makes each password attempt relatively cheap.

---

# Exploitation Strategy

The solving process is:

1. Read `vault_dump.txt`.

2. Remove whitespace and decode the hex into raw bytes.

3. Parse the KDBX header.

4. Extract the cryptographic fields:

    - master seed

    - transform seed

    - transform rounds

    - encryption IV

    - stream-start bytes

5. Generate password candidates using the HR memo format.

6. For each candidate:

    - derive the KeePass master key

    - decrypt the first 32 bytes of the payload

    - compare it against the known stream-start bytes

7. Once the correct password is found:

    - decrypt the full payload

    - parse the KDBX hashed block stream

    - gzip-decompress the XML

    - search for `UMCS{...}`


The correct recovered password is:

```text
[REDACTED_PASSWORD]
```

---

# Proof of Concept

Manual reconstruction:

```bash
xxd -r -p vault_dump.txt vault.kdbx
file vault.kdbx
```

Expected result:

```text
vault.kdbx: Keepass password database 2.x KDBX
```

The password mask is:

```text
<Value><0000-9999><Special>
```

Example candidates:

```text
Synergy0000@
Synergy0001@
Disruption1337!
Pivot4092@
[REDACTED_PASSWORD]
```

Once `[REDACTED_PASSWORD]` is tested, the KDBX stream-start bytes validate successfully. The vault decrypts into XML, and the flag appears inside the `Notes` field of the `Master Infrastructure` entry:

```xml
<String>
    <Key>Notes</Key>
    <Value>UMCS{m4sk_4tt4cks_b34t_brut3_f0rc3}</Value>
</String>
```

---

# Full Python Solver

Save this as:

```bash
solve_hexed_protocol.py
```

```python
#!/usr/bin/env python3
"""
Solver for "The Hexed Protocol" CTF challenge.

The script:
1. Reads the hex-encoded KeePass vault dump.
2. Parses the KDBX3 header.
3. Generates password candidates from the HR memo policy.
4. Performs an offline mask attack.
5. Decrypts the vault.
6. Extracts the UMCS{...} flag from the KeePass XML.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import re
import string
import struct
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# KDBX 3.x header field IDs
FIELD_CIPHER_ID = 2
FIELD_COMPRESSION_FLAGS = 3
FIELD_MASTER_SEED = 4
FIELD_TRANSFORM_SEED = 5
FIELD_TRANSFORM_ROUNDS = 6
FIELD_ENCRYPTION_IV = 7
FIELD_STREAM_START_BYTES = 9

KDBX_SIGNATURE_1 = 0x9AA2D903
KDBX_SIGNATURE_2 = 0xB54BFB67

COMMON_SPECIALS = "@!#$%&*?"
DEFAULT_VALUES = [
    "SYNERGY",
    "DISRUPTION",
    "PIVOT",
    "AGILITY",
    "PARADIGM",
]


def ordered_unique(text: str) -> str:
    """
    Remove duplicate characters while preserving order.
    """
    seen = set()
    output = []

    for ch in text:
        if ch not in seen:
            seen.add(ch)
            output.append(ch)

    return "".join(output)


def read_hex_dump(path: Path) -> bytes:
    """
    Read the hex dump and convert it into raw bytes.
    """
    hex_text = re.sub(r"\s+", "", path.read_text())

    try:
        return bytes.fromhex(hex_text)
    except ValueError as exc:
        raise ValueError(f"{path} is not valid hexadecimal data") from exc


def parse_kdbx3_header(data: bytes) -> Tuple[Dict[int, bytes], int]:
    """
    Parse a KeePass KDBX 3.x header.

    KDBX3 header format:

        4 bytes  signature 1
        4 bytes  signature 2
        4 bytes  version
        repeated header fields:
            1 byte   field ID
            2 bytes  field size, little-endian
            N bytes  field data

    Field ID 0 marks the end of the header.
    """
    if len(data) < 12:
        raise ValueError("Input is too small to be a KDBX file")

    sig1, sig2 = struct.unpack("<II", data[:8])

    if sig1 != KDBX_SIGNATURE_1 or sig2 != KDBX_SIGNATURE_2:
        raise ValueError("Invalid KeePass/KDBX magic bytes")

    version = struct.unpack("<I", data[8:12])[0]

    if (version >> 16) != 3:
        raise ValueError(f"Unsupported KDBX version: 0x{version:08x}")

    fields: Dict[int, bytes] = {}
    offset = 12

    while offset + 3 <= len(data):
        field_id = data[offset]
        field_size = struct.unpack("<H", data[offset + 1:offset + 3])[0]
        offset += 3

        field_data = data[offset:offset + field_size]

        if len(field_data) != field_size:
            raise ValueError("Truncated KDBX header field")

        fields[field_id] = field_data
        offset += field_size

        if field_id == 0:
            return fields, offset

    raise ValueError("KDBX header terminator was not found")


def aes_ecb_transform(transform_seed: bytes, composite_key: bytes, rounds: int) -> bytes:
    """
    Apply the KeePass KDBX3 AES-KDF transform.

    The composite key is encrypted repeatedly using AES-ECB under the
    transform seed.
    """
    transformed = composite_key

    encryptor = Cipher(
        algorithms.AES(transform_seed),
        modes.ECB(),
    ).encryptor()

    for _ in range(rounds):
        transformed = encryptor.update(transformed)

    encryptor.finalize()
    return transformed


def derive_master_key(password: str, fields: Dict[int, bytes]) -> bytes:
    """
    Derive the final KeePass database key from a password.

    For a password-only KDBX3 database:

        password_key  = SHA256(password)
        composite_key = SHA256(password_key)
        transformed   = AES-KDF(composite_key)
        final_key     = SHA256(master_seed || SHA256(transformed))
    """
    password_key = hashlib.sha256(password.encode("utf-8")).digest()
    composite_key = hashlib.sha256(password_key).digest()

    rounds = struct.unpack("<Q", fields[FIELD_TRANSFORM_ROUNDS])[0]

    transformed = aes_ecb_transform(
        fields[FIELD_TRANSFORM_SEED],
        composite_key,
        rounds,
    )

    transformed_hash = hashlib.sha256(transformed).digest()

    return hashlib.sha256(
        fields[FIELD_MASTER_SEED] + transformed_hash
    ).digest()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-CBC decrypt helper.
    """
    decryptor = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()


def is_correct_password(
    password: [REDACTED_PASSWORD]
    fields: Dict[int, bytes],
    encrypted_payload: bytes,
) -> bool:
    """
    Quickly test a password.

    A valid KDBX3 decryption starts with StreamStartBytes from the header.
    We only decrypt the first 32 bytes for speed.
    """
    key = derive_master_key(password, fields)

    first_plaintext_block = aes_cbc_decrypt(
        key,
        fields[FIELD_ENCRYPTION_IV],
        encrypted_payload[:32],
    )

    return first_plaintext_block == fields[FIELD_STREAM_START_BYTES]


def parse_hashed_block_stream(block_stream: bytes) -> bytes:
    """
    Parse the KeePass hashed block stream.

    Each block contains:

        uint32 block_index
        32-byte SHA256(block_data)
        uint32 block_size
        block_data

    A zero-sized block ends the stream.
    """
    position = 0
    chunks: List[bytes] = []

    while True:
        if position + 40 > len(block_stream):
            raise ValueError("Truncated hashed block stream")

        block_index = struct.unpack("<I", block_stream[position:position + 4])[0]
        position += 4

        expected_hash = block_stream[position:position + 32]
        position += 32

        block_size = struct.unpack("<I", block_stream[position:position + 4])[0]
        position += 4

        block_data = block_stream[position:position + block_size]
        position += block_size

        if len(block_data) != block_size:
            raise ValueError(f"Truncated block {block_index}")

        if block_size == 0:
            break

        actual_hash = hashlib.sha256(block_data).digest()

        if actual_hash != expected_hash:
            raise ValueError(f"Hash mismatch in block {block_index}")

        chunks.append(block_data)

    return b"".join(chunks)


def decrypt_database_xml(
    password: [REDACTED_PASSWORD]
    fields: Dict[int, bytes],
    encrypted_payload: bytes,
) -> bytes:
    """
    Decrypt the full KDBX payload and return the inner XML document.
    """
    key = derive_master_key(password, fields)

    plaintext = aes_cbc_decrypt(
        key,
        fields[FIELD_ENCRYPTION_IV],
        encrypted_payload,
    )

    stream_start = fields[FIELD_STREAM_START_BYTES]

    if not plaintext.startswith(stream_start):
        raise ValueError("Wrong password or corrupted database")

    block_stream = plaintext[len(stream_start):]
    compressed_or_xml = parse_hashed_block_stream(block_stream)

    compression_flags = struct.unpack("<I", fields[FIELD_COMPRESSION_FLAGS])[0]

    if compression_flags == 1:
        return gzip.decompress(compressed_or_xml)

    if compression_flags == 0:
        return compressed_or_xml

    raise ValueError(f"Unsupported compression flag: {compression_flags}")


def parse_core_values(memo_path: Path | None) -> List[str]:
    """
    Extract core values from the HR memo.

    The memo says only the first letter should be capitalized.
    """
    values = DEFAULT_VALUES

    if memo_path is not None and memo_path.exists():
        memo = memo_path.read_text(errors="replace")

        match = re.search(
            r"core values are:\s*([A-Z,\s]+)",
            memo,
            re.IGNORECASE,
        )

        if match:
            parsed = re.findall(
                r"[A-Z]+",
                match.group(1),
                flags=re.IGNORECASE,
            )

            if parsed:
                values = parsed

    return [value.capitalize() for value in values]


def generate_candidates(values: List[str], specials: str) -> Iterable[str]:
    """
    Generate candidates using:

        [Core Company Value] + [4-Digit Department PIN] + [Special Character]
    """
    for pin in range(10_000):
        pin_text = f"{pin:04d}"

        for value in values:
            for special in specials:
                yield f"{value}{pin_text}{special}"


def brute_force_password(
    fields: Dict[int, bytes],
    encrypted_payload: bytes,
    values: List[str],
    specials: str,
) -> str | None:
    """
    Perform the mask attack.
    """
    total = 10_000 * len(values) * len(specials)

    for index, candidate in enumerate(
        generate_candidates(values, specials),
        start=1,
    ):
        if is_correct_password(candidate, fields, encrypted_payload):
            print(
                f"[+] Password found after {index:,}/{total:,} attempts: "
                f"{candidate}"
            )
            return candidate

        if index % 25_000 == 0:
            print(f"[*] Tried {index:,}/{total:,} candidates...")

    return None


def extract_flag(xml: bytes) -> str | None:
    """
    Search the decrypted XML for the flag.
    """
    match = re.search(rb"UMCS\{[^}]+\}", xml)

    if not match:
        return None

    return match.group(0).decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Solve The Hexed Protocol CTF challenge"
    )

    parser.add_argument(
        "vault_dump",
        type=Path,
        help="Path to vault_dump.txt",
    )

    parser.add_argument(
        "--memo",
        type=Path,
        default=None,
        help="Optional path to scraps.md",
    )

    parser.add_argument(
        "--specials",
        default=COMMON_SPECIALS,
        help=f"Special characters to try first. Default: {COMMON_SPECIALS!r}",
    )

    parser.add_argument(
        "--full-punctuation",
        action="store_true",
        help="Fallback to all characters from Python string.punctuation",
    )

    parser.add_argument(
        "--password",
        default=None,
        help="Skip brute force and decrypt with a known password",
    )

    parser.add_argument(
        "--save-xml",
        type=Path,
        default=None,
        help="Optional path to save decrypted KeePass XML",
    )

    args = parser.parse_args()

    vault_bytes = read_hex_dump(args.vault_dump)
    fields, payload_offset = parse_kdbx3_header(vault_bytes)
    encrypted_payload = vault_bytes[payload_offset:]

    values = parse_core_values(args.memo)

    print(f"[*] Parsed KDBX payload: {len(vault_bytes):,} bytes")
    print(f"[*] Core values: {', '.join(values)}")
    print(
        "[*] KDF rounds: "
        f"{struct.unpack('<Q', fields[FIELD_TRANSFORM_ROUNDS])[0]:,}"
    )

    password = args.password

    if password is None:
        first_pass_specials = ordered_unique(args.specials)

        print(
            f"[*] Starting mask attack with specials: "
            f"{first_pass_specials!r}"
        )

        password = brute_force_password(
            fields,
            encrypted_payload,
            values,
            first_pass_specials,
        )

        if password is None and args.full_punctuation:
            fallback_specials = ordered_unique(
                args.specials + string.punctuation
            )

            if fallback_specials != first_pass_specials:
                print(
                    "[*] First pass failed. Falling back to punctuation set: "
                    f"{fallback_specials!r}"
                )

                password = brute_force_password(
                    fields,
                    encrypted_payload,
                    values,
                    fallback_specials,
                )

    if password is None:
        print(
            "[-] Password was not found. Try --full-punctuation or "
            "expand --specials.",
            file=sys.stderr,
        )
        return 1

    xml = decrypt_database_xml(
        password,
        fields,
        encrypted_payload,
    )

    if args.save_xml:
        args.save_xml.write_bytes(xml)
        print(f"[+] Decrypted XML saved to: {args.save_xml}")

    flag = extract_flag(xml)

    if flag is None:
        print(
            "[-] Decryption worked, but no UMCS{...} flag was found.",
            file=sys.stderr,
        )
        return 2

    print(f"[+] Flag: {flag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

---

# Walkthrough

Install the dependency:

```bash
python3 -m pip install cryptography
```

Run the solver:

```bash
python3 solve_hexed_protocol.py vault_dump.txt --memo scraps.md
```

Expected output:

```text
[*] Parsed KDBX payload: 1,742 bytes
[*] Core values: Synergy, Disruption, Pivot, Agility, Paradigm
[*] KDF rounds: 1,000
[*] Starting mask attack with specials: '@!#$%&*?'
[*] Tried 25,000/400,000 candidates...
[*] Tried 50,000/400,000 candidates...
[*] Tried 75,000/400,000 candidates...
[*] Tried 100,000/400,000 candidates...
[*] Tried 125,000/400,000 candidates...
[*] Tried 150,000/400,000 candidates...
[+] Password found after 163,713/400,000 attempts: [REDACTED_PASSWORD]
[+] Flag: UMCS{m4sk_4tt4cks_b34t_brut3_f0rc3}
```

To save the decrypted KeePass XML:

```bash
python3 solve_hexed_protocol.py vault_dump.txt --memo scraps.md --save-xml decrypted.xml
```

To skip brute force after recovering the password:

```bash
python3 solve_hexed_protocol.py vault_dump.txt --password [REDACTED_PASSWORD]
```

Troubleshooting:

```text
ModuleNotFoundError: No module named 'cryptography'
```

Fix:

```bash
python3 -m pip install cryptography
```

If the password is not found, expand the special-character search:

```bash
python3 solve_hexed_protocol.py vault_dump.txt --memo scraps.md --full-punctuation
```

---

# Flag

The recovered password is:

```text
[REDACTED_PASSWORD]
```

The decrypted KeePass XML contains the flag in the `Notes` field:

```text
UMCS{m4sk_4tt4cks_b34t_brut3_f0rc3}
```

---

# Conclusion

The challenge hides a KeePass database inside a hex dump. The encryption itself is not broken. The real weakness is the predictable HR password policy, which reduces the vault password to a small mask-based search space.

Key lesson:

```text
Strong encryption fails operationally when password construction rules are predictable.
```

A secure vault password should not be derived from a known company value, a short numeric PIN, and a single special character.
