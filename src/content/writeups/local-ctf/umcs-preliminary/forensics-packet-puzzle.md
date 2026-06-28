---
title: "Packet Puzzle"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Packet Puzzle with analysis, solution steps, and final recovery notes."
date: 2026-04-26
tags:
  - ctf
  - umcs-preliminary
  - forensics
  - reverse-engineering
  - network
category: "local-ctf"
difficulty: "medium"
platform: "ctf"
draft: false
boxImage: "https://umcybersec.site/assets/logo-BsYk-M08.png"
---
# Challenge Overview

**Challenge Name:** Packet_Puzzle
**Category:** Forensics / Network Forensics
**Points:** 460
**Flag Format:** `umcs{}`
**Provided File:** `Packet_Puzzle.pcap`

The challenge provides a suspicious PCAP captured from a compromised host. The goal is to analyze the network traffic, identify the hidden transmitted data, reconstruct the fragmented payload, and recover the final flag.

The recovered flag is:

```text
umcs{wireshark_never_lies}
```

# Initial Analysis

We start by identifying the file type:

```bash
file Packet_Puzzle.pcap
```

Expected result:

```text
Packet_Puzzle.pcap: pcap capture file, microsecond ts, Raw IPv4
```

The important observation is that this is a **raw IPv4 PCAP**, not a normal Ethernet-framed PCAP. That means some tools or scripts expecting Ethernet headers may parse it incorrectly.

A quick protocol check shows normal-looking traffic, including DNS, ICMP, and other packets. However, the suspicious data is inside TCP payloads going to these destination ports:

```text
4444
4445
4446
```

The traffic appears intentionally fragmented. Each TCP payload contains part of a Base64-encoded object.

A useful manual inspection command is:

```bash
tcpdump -nn -r Packet_Puzzle.pcap 'tcp and (dst port 4444 or dst port 4445 or dst port 4446)' -A
```

The payloads look like Base64 fragments. When reconstructed correctly, they decode into a PNG image. However, the PNG is intentionally corrupted in a few places.

# Vulnerability / Weakness Identification

The weakness is not a software vulnerability in a service. This is a forensic reconstruction challenge.

The hidden data was transmitted insecurely as fragmented Base64 data across predictable TCP destination ports:

```text
4444, 4445, 4446
```

The challenge tries to hide the payload using three layers of obstruction:

1. Mixing the suspicious traffic with normal network activity.

2. Splitting the Base64 data across multiple TCP packets and ports.

3. Corrupting small parts of the decoded PNG file.


The critical trick is the reconstruction order.

A wrong approach is to concatenate all suspicious TCP payloads in normal packet order. That produces an invalid or unsupported image.

The correct order is:

```text
all chunks sent to port 4444
then all chunks sent to port 4445
then all chunks sent to port 4446
```

After Base64 decoding, the PNG still has minor corruption:

```text
0x80 PNG signature byte  -> should be 0x89
IHDU                    -> should be IHDR
IENU                    -> should be IEND
```

Once these are patched, the PNG becomes valid and displays the flag.

# Exploitation Strategy

The solving plan is:

1. Parse the PCAP manually using Python.

2. Support raw IPv4 packets because the capture is not Ethernet-based.

3. Extract only TCP payloads whose destination port is one of:


```text
4444, 4445, 4446
```

4. Sort the extracted chunks by:


```text
destination port first, then original packet order
```

5. Concatenate all payload chunks.

6. Remove non-Base64 characters.

7. Decode the Base64 data.

8. Patch the corrupted PNG markers.

9. Verify the PNG structure and write it to disk.

10. Open the recovered image and read the flag.


# Proof of Concept

The suspicious payloads can be confirmed manually with:

```bash
tcpdump -nn -r Packet_Puzzle.pcap 'tcp and dst port 4444' -A
tcpdump -nn -r Packet_Puzzle.pcap 'tcp and dst port 4445' -A
tcpdump -nn -r Packet_Puzzle.pcap 'tcp and dst port 4446' -A
```

Each stream contains Base64-like data.

The core reconstruction logic is:

```python
chunks.sort(key=lambda x: (x[0], x[1]))
```

Where:

```text
x[0] = destination port
x[1] = original packet index
```

This forces the order:

```text
4444 -> 4445 -> 4446
```

After decoding, the PNG header is partially broken:

```text
80 50 4E 47 0D 0A 1A 0A
```

A valid PNG signature should be:

```text
89 50 4E 47 0D 0A 1A 0A
```

So the first byte must be patched from `0x80` to `0x89`.

The PNG chunk names are also corrupted:

```text
IHDU -> IHDR
IENU -> IEND
```

Once fixed, the image opens successfully.

# Full Python Solver

Save this as:

```bash
solve_packet_puzzle.py
```

```python
#!/usr/bin/env python3
import argparse
import base64
import binascii
import re
import struct
import zlib
from pathlib import Path


TARGET_PORTS = {4444, 4445, 4446}


def read_pcap_packets(pcap_path: Path):
    """
    Minimal PCAP reader.

    This supports classic PCAP files with little-endian or big-endian headers.
    The challenge PCAP is raw IPv4, so we do not assume Ethernet exists.
    """
    data = pcap_path.read_bytes()

    if len(data) < 24:
        raise ValueError("Invalid PCAP file: file is too small")

    magic = data[:4]

    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP magic header")

    offset = 24
    packet_index = 0

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + "IIII",
            data[offset:offset + 16]
        )
        offset += 16

        packet = data[offset:offset + incl_len]
        offset += incl_len

        yield packet_index, packet
        packet_index += 1


def get_ipv4_packet(packet: bytes):
    """
    Return the IPv4 packet bytes.

    The challenge capture uses Raw IPv4 packets, but this function also supports
    normal Ethernet + IPv4 packets for portability.
    """

    # Raw IPv4
    if len(packet) >= 20 and packet[0] >> 4 == 4:
        return packet

    # Ethernet + IPv4
    if len(packet) >= 34 and packet[12:14] == b"\x08\x00":
        return packet[14:]

    return None


def extract_suspicious_tcp_chunks(pcap_path: Path):
    """
    Extract TCP payloads sent to the suspicious destination ports.
    Returns tuples of:

        (destination_port, packet_index, payload)
    """
    chunks = []

    for packet_index, packet in read_pcap_packets(pcap_path):
        ip = get_ipv4_packet(packet)

        if not ip or len(ip) < 20:
            continue

        version = ip[0] >> 4
        ihl = (ip[0] & 0x0F) * 4

        if version != 4 or len(ip) < ihl:
            continue

        total_length = struct.unpack("!H", ip[2:4])[0]
        protocol = ip[9]

        # TCP protocol number is 6
        if protocol != 6:
            continue

        ip = ip[:total_length]
        tcp = ip[ihl:]

        if len(tcp) < 20:
            continue

        src_port, dst_port = struct.unpack("!HH", tcp[:4])
        tcp_header_length = ((tcp[12] >> 4) & 0x0F) * 4

        if len(tcp) < tcp_header_length:
            continue

        payload = tcp[tcp_header_length:]

        if dst_port in TARGET_PORTS and payload:
            chunks.append((dst_port, packet_index, payload))

    return chunks


def repair_png(decoded_data: bytes) -> bytes:
    """
    Repair the intentionally corrupted PNG.

    Known corruptions:
    - PNG signature begins with 0x80 instead of 0x89
    - IHDR chunk name is corrupted as IHDU
    - IEND chunk name is corrupted as IENU
    """
    fixed = bytearray(decoded_data)

    # Fix PNG signature.
    if fixed[:4] == b"\x80PNG":
        fixed[0] = 0x89

    fixed = bytes(fixed)

    # Fix corrupted chunk names.
    fixed = fixed.replace(b"IHDU", b"IHDR")
    fixed = fixed.replace(b"IENU", b"IEND")

    return fixed


def verify_png(png_data: bytes):
    """
    Basic PNG verification.

    This checks:
    - PNG signature
    - Chunk CRC values
    - IDAT zlib stream validity
    """
    if not png_data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("Invalid PNG signature after repair")

    offset = 8
    idat_data = b""

    while offset + 8 <= len(png_data):
        length = struct.unpack(">I", png_data[offset:offset + 4])[0]
        chunk_type = png_data[offset + 4:offset + 8]
        chunk_data_start = offset + 8
        chunk_data_end = chunk_data_start + length
        crc_start = chunk_data_end
        crc_end = crc_start + 4

        if crc_end > len(png_data):
            raise ValueError("PNG chunk extends beyond file boundary")

        chunk_data = png_data[chunk_data_start:chunk_data_end]
        stored_crc = struct.unpack(">I", png_data[crc_start:crc_end])[0]
        calculated_crc = binascii.crc32(chunk_type + chunk_data) & 0xFFFFFFFF

        if stored_crc != calculated_crc:
            raise ValueError(
                f"Bad CRC in chunk {chunk_type!r}: "
                f"stored={stored_crc:08x}, calculated={calculated_crc:08x}"
            )

        if chunk_type == b"IDAT":
            idat_data += chunk_data

        offset = crc_end

        if chunk_type == b"IEND":
            break

    if not idat_data:
        raise ValueError("No IDAT data found in PNG")

    # If this fails, the PNG image data is still corrupted.
    zlib.decompress(idat_data)


def solve(pcap_path: Path, output_path: Path):
    print("[*] Reading PCAP...")
    chunks = extract_suspicious_tcp_chunks(pcap_path)

    if not chunks:
        raise RuntimeError("No suspicious TCP payloads found")

    print(f"[+] Extracted {len(chunks)} suspicious TCP chunks")

    port_counts = {}
    for dst_port, _, _ in chunks:
        port_counts[dst_port] = port_counts.get(dst_port, 0) + 1

    for port in sorted(port_counts):
        print(f"[+] Port {port}: {port_counts[port]} chunks")

    # Important:
    # The correct reconstruction order is grouped by destination port first,
    # then by original packet order inside each port.
    chunks.sort(key=lambda item: (item[0], item[1]))

    print("[*] Reconstructing Base64 payload...")
    b64_payload = b"".join(payload for _, _, payload in chunks)

    # Remove any non-Base64 bytes just in case the payload includes separators.
    b64_payload = re.sub(rb"[^A-Za-z0-9+/=]", b"", b64_payload)

    print("[*] Decoding Base64...")
    decoded = base64.b64decode(b64_payload)

    print("[*] Repairing PNG corruption...")
    repaired_png = repair_png(decoded)

    print("[*] Verifying PNG...")
    verify_png(repaired_png)

    output_path.write_bytes(repaired_png)

    print(f"[+] Valid PNG written to: {output_path}")
    print("[+] Open the image to read the flag.")
    print("[+] Flag: umcs{wireshark_never_lies}")


def main():
    parser = argparse.ArgumentParser(
        description="Solver for UMCS Packet_Puzzle challenge"
    )
    parser.add_argument(
        "pcap",
        help="Path to Packet_Puzzle.pcap"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="recovered_correct.png",
        help="Output PNG filename"
    )

    args = parser.parse_args()

    solve(Path(args.pcap), Path(args.output))


if __name__ == "__main__":
    main()
```

# Walkthrough

Place the script in the same directory as the PCAP:

```bash
ls
```

Expected files:

```text
Packet_Puzzle.pcap
solve_packet_puzzle.py
```

Run the solver:

```bash
python3 solve_packet_puzzle.py Packet_Puzzle.pcap
```

Expected output:

```text
[*] Reading PCAP...
[+] Extracted 90 suspicious TCP chunks
[+] Port 4444: ...
[+] Port 4445: ...
[+] Port 4446: ...
[*] Reconstructing Base64 payload...
[*] Decoding Base64...
[*] Repairing PNG corruption...
[*] Verifying PNG...
[+] Valid PNG written to: recovered_correct.png
[+] Open the image to read the flag.
[+] Flag: umcs{wireshark_never_lies}
```

Open the recovered image.

On WSL:

```bash
explorer.exe recovered_correct.png
```

On Linux desktop:

```bash
xdg-open recovered_correct.png
```

You should see the flag rendered inside the image.

## Troubleshooting Notes

If the image says unsupported file type, the chunks were probably reconstructed in the wrong order.

Wrong order:

```text
packet order only
```

Correct order:

```text
port 4444 chunks
then port 4445 chunks
then port 4446 chunks
```

If the script fails at PNG verification, check that the repair logic includes these patches:

```text
0x80PNG -> 0x89PNG
IHDU    -> IHDR
IENU    -> IEND
```

No third-party Python packages are required. The script uses only Python standard library modules.

# Flag

The repaired PNG displays:

```text
umcs{wireshark_never_lies}
```

# Conclusion

The challenge hides a PNG image inside fragmented TCP payloads. The important forensic insight is that the payload is not meant to be reconstructed by global packet order. Instead, the data must be grouped by destination port, then decoded as Base64.

The root cause of the hiding technique is simple but effective:

```text
cleartext Base64 data + fragmented TCP packets + misleading traffic + minor file corruption
```

The key lesson is that PCAP forensics often requires more than simply following streams. Packet ordering, protocol metadata, destination ports, and file-format validation all matter when reconstructing hidden payloads.
