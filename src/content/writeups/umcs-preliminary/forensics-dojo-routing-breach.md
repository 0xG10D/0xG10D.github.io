---
slug: "local-ctf/umcs-preliminary/forensics-dojo-routing-breach"
event: "umcs-preliminary"
title: "Dojo Routing Breach"
summary: "UMCS Preliminary umcs preliminary, forensics, reverse engineering writeup covering Dojo Routing Breach with analysis, solution steps, and final recovery notes."
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

**Challenge Name:** Dojo Routing Breach
**Category:** Forensics / Misc / Network
**Points:** 500
**Flag Format:** `UMCS{}`
**Provided File:** `Dojo_Routing_Breach.pcap`

The challenge provides a packet capture containing heavy network noise. The goal is to identify a hidden pattern inside the traffic and recover the flag.

The hint says:

```text
A true martial artist visualizes the form before striking.

| | _ _ _ _ _ _ _ _ | | / V \ | | _ _ \ _ / / \ _ _ _ _ _ |
```

This hint strongly suggests that the solution involves **visualizing a structure or topology**, not simply searching for strings inside the capture.

---

# Initial Analysis

The provided file is a PCAP capture:

```bash
file Dojo_Routing_Breach.pcap
```

Expected output:

```text
Dojo_Routing_Breach.pcap: pcap capture file
```

A quick strings search does not reveal the flag:

```bash
strings Dojo_Routing_Breach.pcap | grep -i UMCS
```

No useful output is found.

Next, inspect the protocols inside the capture:

```bash
tcpdump -nn -r Dojo_Routing_Breach.pcap | head
```

The important observation is that the capture contains **OSPF traffic**.

OSPF uses IPv4 protocol number `89`. This can be filtered with:

```bash
tcpdump -nn -r Dojo_Routing_Breach.pcap 'ip proto 89'
```

The challenge description says there is a “storm of interference” but a “silent pattern remains.” This means most packets are likely noise, and only a specific protocol or packet type contains the real data.

The useful packets are:

```text
OSPF Link State Update packets
```

More specifically:

```text
OSPF packet type 4 = Link State Update
```

Inside those updates are **Router-LSA** entries. These entries describe router topology, which matches the hint about visualizing the form before striking.

---

# Vulnerability / Weakness Identification

This is not a software vulnerability in the traditional sense. The weakness is a **steganographic encoding technique** inside routing metadata.

The challenge hides data inside OSPF Router-LSA information.

Each useful router ID follows this pattern:

```text
10.X.Y.C
```

Where:

```text
X = visual/grid coordinate
Y = visual/grid coordinate
C = ASCII value of one character
```

For example:

```text
[REDACTED_LOCAL_IP]
```

The last octet, `85`, can be converted to ASCII:

```python
chr(85) = 'U'
```

The OSPF Router-LSA links define the ordering of the characters. In other words, the packets describe a graph/topology, and the flag must be reconstructed by walking the topology.

The useful Router-LSA packets have:

```text
LSA type: 1   # Router-LSA
LSA length: 36
Link count: 1
```

Noise packets may contain empty Router-LSAs or unrelated updates. These are ignored.

---

# Exploitation Strategy

The solving strategy is:

1. Parse the PCAP file.

2. Extract IPv4 packets.

3. Keep only packets where:


```text
IPv4 protocol == 89
```

This identifies OSPF packets.

4. Keep only OSPF packets where:


```text
OSPF type == 4
```

This identifies Link State Update packets.

5. Parse the Link State Advertisement data.

6. Keep only Router-LSAs:


```text
LSA type == 1
```

7. Keep only Router-LSAs with exactly one link:


```text
LSA length == 36
Link count == 1
```

8. Build a directed graph:


```text
Advertising Router  ->  Link ID
```

9. Find starting nodes with:


```text
out-degree = 1
in-degree = 0
```

10. Walk each chain.

11. Convert the last octet of each router ID into ASCII.

12. Reverse each chain because the directed route is visually reversed.

13. Join all recovered chunks to obtain the flag.


---

# Proof of Concept

A useful Router-LSA contains data like this:

```text
Advertising Router: 10.X.Y.ASCII
Link ID:            10.X.Y.ASCII
```

The `Advertising Router` is treated as the current node, and the `Link ID` is treated as the next node.

Example:

```text
[REDACTED_LOCAL_IP] -> [REDACTED_LOCAL_IP]
```

The last octets are:

```text
85 -> U
77 -> M
```

So those nodes contain characters.

The graph link tells the solver how to order the characters.

The key idea is that the flag is not stored as a normal string. It is stored as a **routing topology**.

A simplified version of the extraction logic is:

```python
char = chr(int(router_id.split(".")[3]))
```

For example:

```python
router_id = "[REDACTED_LOCAL_IP]"
print(chr(int(router_id.split(".")[3])))
```

Output:

```text
{
```

This is how the flag characters are recovered.

---

# Full Python Solver

Save the following script as:

```bash
solve_dojo.py
```

```python
#!/usr/bin/env python3
import sys
import struct
import socket
from collections import defaultdict, Counter


def ip_to_str(raw: bytes) -> str:
    """
    Convert 4 raw bytes into dotted IPv4 format.
    """
    return socket.inet_ntoa(raw)


def parse_pcap(path):
    """
    Minimal PCAP parser.

    Supports normal PCAP files and extracts:
    - packet bytes
    - link-layer type

    This avoids requiring Scapy or Tshark.
    """
    packets = []

    with open(path, "rb") as f:
        global_header = f.read(24)

        if len(global_header) < 24:
            raise ValueError("File is too small to be a valid PCAP")

        magic = global_header[:4]

        # Detect endianness.
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise ValueError("Unsupported file format. Expected normal PCAP, not PCAPNG.")

        # PCAP global header:
        # magic_number, version_major, version_minor, thiszone,
        # sigfigs, snaplen, network
        network = struct.unpack(endian + "I", global_header[20:24])[0]

        while True:
            packet_header = f.read(16)

            if not packet_header:
                break

            if len(packet_header) < 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                endian + "IIII",
                packet_header
            )

            packet_data = f.read(incl_len)

            if len(packet_data) != incl_len:
                break

            packets.append(packet_data)

    return network, packets


def extract_ipv4_packet(packet: bytes, linktype: int):
    """
    Extract an IPv4 packet from common PCAP link-layer formats.

    Supported link types:
    - 101: Raw IPv4
    - 1: Ethernet
    - 113: Linux cooked capture v1
    """
    LINKTYPE_ETHERNET = 1
    LINKTYPE_RAW = 101
    LINKTYPE_LINUX_SLL = 113

    # Raw IPv4 packet.
    if linktype == LINKTYPE_RAW:
        if len(packet) >= 1 and packet[0] >> 4 == 4:
            return packet
        return None

    # Ethernet frame.
    if linktype == LINKTYPE_ETHERNET:
        if len(packet) < 14:
            return None

        ethertype = struct.unpack("!H", packet[12:14])[0]

        # IPv4 ethertype.
        if ethertype == 0x0800:
            return packet[14:]

        return None

    # Linux cooked capture.
    if linktype == LINKTYPE_LINUX_SLL:
        if len(packet) < 16:
            return None

        protocol = struct.unpack("!H", packet[14:16])[0]

        # IPv4 protocol.
        if protocol == 0x0800:
            return packet[16:]

        return None

    return None


def parse_ipv4(ip_packet: bytes):
    """
    Parse an IPv4 packet and return:
    - protocol number
    - source IP
    - destination IP
    - payload
    """
    if len(ip_packet) < 20:
        return None

    version = ip_packet[0] >> 4
    ihl = (ip_packet[0] & 0x0F) * 4

    if version != 4:
        return None

    if len(ip_packet) < ihl:
        return None

    total_length = struct.unpack("!H", ip_packet[2:4])[0]

    if total_length > len(ip_packet):
        return None

    protocol = ip_packet[9]
    src_ip = ip_to_str(ip_packet[12:16])
    dst_ip = ip_to_str(ip_packet[16:20])
    payload = ip_packet[ihl:total_length]

    return protocol, src_ip, dst_ip, payload


def parse_ospf_lsu(payload: bytes):
    """
    Parse OSPF Link State Update packets.

    OSPF header layout:
    - byte 0: version
    - byte 1: type
    - bytes 2-3: packet length
    - bytes 4-7: router ID
    - bytes 8-11: area ID
    - bytes 12-23: checksum/auth data

    Link State Update packets contain:
    - 4-byte LSA count
    - repeated LSA structures
    """
    results = []

    if len(payload) < 24:
        return results

    ospf_type = payload[1]

    # OSPF type 4 = Link State Update.
    if ospf_type != 4:
        return results

    ospf_length = struct.unpack("!H", payload[2:4])[0]

    if ospf_length > len(payload):
        return results

    ospf_body = payload[24:ospf_length]

    if len(ospf_body) < 4:
        return results

    lsa_count = struct.unpack("!I", ospf_body[:4])[0]
    offset = 4

    for _ in range(lsa_count):
        if offset + 20 > len(ospf_body):
            break

        lsa_header = ospf_body[offset:offset + 20]

        # LSA header fields.
        lsa_type = lsa_header[3]
        link_state_id = ip_to_str(lsa_header[4:8])
        advertising_router = ip_to_str(lsa_header[8:12])
        lsa_length = struct.unpack("!H", lsa_header[18:20])[0]

        if lsa_length < 20:
            break

        lsa_data = ospf_body[offset + 20:offset + lsa_length]

        if len(lsa_data) != lsa_length - 20:
            break

        # Router-LSA:
        # body begins with:
        # - flags: 1 byte
        # - zero/options: 1 byte
        # - number of links: 2 bytes
        if lsa_type == 1 and len(lsa_data) >= 4:
            link_count = struct.unpack("!H", lsa_data[2:4])[0]

            # A Router-LSA with exactly one link has:
            # 20-byte LSA header + 4-byte router-LSA header + 12-byte link = 36 bytes.
            if link_count == 1 and lsa_length == 36 and len(lsa_data) >= 16:
                link_id = ip_to_str(lsa_data[4:8])

                results.append({
                    "advertising_router": advertising_router,
                    "link_state_id": link_state_id,
                    "link_id": link_id,
                    "lsa_length": lsa_length,
                    "link_count": link_count,
                })

        offset += lsa_length

    return results


def router_id_to_char(router_id: str) -> str:
    """
    Convert router ID 10.X.Y.ASCII into the ASCII character
    stored in the final octet.
    """
    parts = router_id.split(".")

    if len(parts) != 4:
        raise ValueError(f"Invalid router ID: {router_id}")

    ascii_value = int(parts[3])

    if ascii_value < 0 or ascii_value > 255:
        raise ValueError(f"Invalid ASCII value in router ID: {router_id}")

    return chr(ascii_value)


def solve(path: str) -> str:
    linktype, packets = parse_pcap(path)

    edges = []
    nodes = set()

    for packet in packets:
        ip_packet = extract_ipv4_packet(packet, linktype)

        if ip_packet is None:
            continue

        parsed = parse_ipv4(ip_packet)

        if parsed is None:
            continue

        protocol, src_ip, dst_ip, ip_payload = parsed

        # IPv4 protocol 89 is OSPF.
        if protocol != 89:
            continue

        lsa_entries = parse_ospf_lsu(ip_payload)

        for entry in lsa_entries:
            current_node = entry["advertising_router"]
            next_node = entry["link_id"]

            edges.append((current_node, next_node))
            nodes.add(current_node)
            nodes.add(next_node)

    if not edges:
        raise RuntimeError("No useful OSPF Router-LSA edges were found.")

    # Build directed graph.
    graph = defaultdict(list)
    indegree = Counter()
    outdegree = Counter()

    for source, destination in edges:
        graph[source].append(destination)
        outdegree[source] += 1
        indegree[destination] += 1

    # Starting nodes have an outgoing edge but no incoming edge.
    starts = [
        node
        for node in nodes
        if outdegree[node] == 1 and indegree[node] == 0
    ]

    if not starts:
        raise RuntimeError("Could not find any starting node in the topology graph.")

    recovered_chunks = []

    # Sort by the first coordinate so the visual rows are processed consistently.
    starts.sort(key=lambda ip_addr: int(ip_addr.split(".")[1]))

    for start in starts:
        path = []
        current = start
        seen = set()

        while True:
            if current in seen:
                raise RuntimeError(f"Cycle detected at node {current}")

            seen.add(current)
            path.append(current)

            if not graph[current]:
                break

            current = graph[current][0]

        # The route is reversed visually, so reverse each chain.
        chunk = "".join(router_id_to_char(node) for node in path)[::-1]
        recovered_chunks.append(chunk)

    flag = "".join(recovered_chunks)

    return flag


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} Dojo_Routing_Breach.pcap")
        sys.exit(1)

    pcap_path = sys.argv[1]

    try:
        flag = solve(pcap_path)
        print(flag)
    except Exception as error:
        print(f"[!] Error: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
```

---

# Walkthrough

## 1. Place the PCAP and solver in the same directory

Example:

```bash
ls
```

Expected:

```text
Dojo_Routing_Breach.pcap
solve_dojo.py
```

## 2. Make the solver executable

```bash
chmod +x solve_dojo.py
```

## 3. Run the solver

```bash
python3 solve_dojo.py Dojo_Routing_Breach.pcap
```

Expected output:

```text
UMCS{ls4_t0p0logy_m4st3r_doj0}
```

## 4. Troubleshooting

If the script prints:

```text
No useful OSPF Router-LSA edges were found.
```

Possible causes:

1. The wrong PCAP file was used.

2. The file was converted to PCAPNG.

3. The link-layer type is not one of the supported formats.


Check the file type:

```bash
file Dojo_Routing_Breach.pcap
```

If it is PCAPNG, convert it to normal PCAP:

```bash
editcap -F pcap input.pcapng Dojo_Routing_Breach.pcap
```

If `editcap` is missing, install Wireshark tools:

```bash
sudo apt install wireshark-common
```

To manually confirm OSPF traffic exists:

```bash
tcpdump -nn -r Dojo_Routing_Breach.pcap 'ip proto 89'
```

---

# Flag

The solver reconstructs the hidden OSPF topology and converts the encoded router IDs back into ASCII.

Recovered flag:

```text
UMCS{ls4_t0p0logy_m4st3r_doj0}
```

---

# Conclusion

The challenge hides the flag inside **OSPF Router-LSA topology data**. The packet capture contains distracting traffic, but the important signal is found by filtering for OSPF Link State Update packets.

The key weakness is that router IDs and LSA links were used as a covert channel:

```text
Router ID = 10.X.Y.ASCII
```

The `X` and `Y` values act like visual coordinates, while the final octet stores the ASCII character. The LSA links define the order in which the characters should be read.

The main lesson is that network forensics challenges are not always solved by searching packet payloads. Metadata, protocol fields, routing tables, topology graphs, timing, and structure can all be used to hide data.
