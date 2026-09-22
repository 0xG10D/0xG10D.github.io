---
slug: "hackthebox/sherlocks/htb-sherlock-phantomring"
event: "hack-the-box-sherlocks"
title: "HTB Sherlock PhantomRing"
summary: "Reverse engineering a Linux ELF post-exploitation agent in Ghidra: its io_uring-based C2 channel, command set, privilege-escalation recon, and eBPF/ftrace anti-monitoring behavior."
date: 2026-09-09
tags:
  - htb
  - sherlock
  - malware-analysis
  - reverse-engineering
  - ghidra
  - linux
  - elf
  - io-uring
  - ebpf
  - c2
  - mitre-attack
category: "forensics"
difficulty: "easy"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/sherlocks/avatar/a215c5ed-f9a8-4a3b-87f0-ca3cbdbc892e-1782143987.png"
---

## Introduction

In this Hack The Box Sherlock, I analyzed a suspicious Linux binary named `agent`. Unlike the Windows malware I normally see in FLARE-VM exercises, this sample is a **64-bit Linux ELF executable**.

The objective was not only to answer the Sherlock questions, but also to understand **how the malware works internally**. I used static analysis and reverse engineering to identify its Command and Control (C2) server, supported commands, privilege-escalation reconnaissance, anti-EDR behavior, and self-destruction capability.

The most interesting part of this sample is its use of **`io_uring`**, together with functionality designed to interfere with Linux tracing and eBPF-based security monitoring.

---

# 1. Tools Used

### FLARE-VM

I performed my analysis from **FLARE-VM**, which provides many reverse-engineering and malware-analysis tools in one Windows environment.

### Ghidra

Ghidra was the main tool used for this Sherlock.

I used it for:

- Decompiling the ELF binary
- Searching strings
- Following cross-references
- Understanding functions
- Identifying command handlers
- Tracing C2 communication
- Investigating anti-EDR functionality

### FLOSS

FLOSS was initially used for string extraction.

My first command was:

```cmd
floss "C:\Users\g01d\Desktop\Sherlock HTB\PhantomRing\phantom_ring\agent"
```

However, FLOSS returned:

```text
FLOSS currently supports the following formats
for string decoding and stackstrings: PE
```

This happened because the malware is a **Linux ELF**, while FLOSS's advanced stack/tight/decoded string analysis is focused on PE binaries.

Static strings can still be requested:

```cmd
floss --only static -- "C:\Users\g01d\Desktop\Sherlock HTB\PhantomRing\phantom_ring\agent"
```

This was also a useful lesson: **not every malware-analysis tool supports every executable format**.

---

# 2. Sample Information

The sample analyzed:

```text
Filename: agent
Format: ELF 64-bit
Architecture: x86-64
Type: PIE executable
Stripped: No
Operating System: Linux
```

SHA256:

```text
2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5
```

A Windows command that can be used to calculate the hash is:

```cmd
certutil -hashfile agent SHA256
```

The binary is dynamically linked against:

```text
liburing.so.2
libc.so.6
```

`liburing.so.2` immediately became interesting because it indicated that the program uses **Linux `io_uring`**.

---

# 3. Basic Malware Flow

After reversing the `main()` function, I understood the basic execution flow as:

```text
Agent starts
     |
     v
Initialize io_uring
     |
     v
Configure C2
192.168.56.1:4445
     |
     v
Attempt connection
     |
     +---- Failed ----> sleep 120 seconds
     |                       |
     |                       +---- retry
     |
     v
Connected
     |
     v
Receive command
     |
     v
process_cmd()
     |
     v
Execute requested action
     |
     v
Send result to attacker
     |
     v
Wait for next command
```

This made it clear that `agent` behaves like a **Linux RAT/backdoor or post-exploitation agent**.

---

# 4. Finding the C2 Port

### Question

> What port does the agent connect to on the C2 server?

I started from the C2 IP string in Ghidra:

```text
192.168.56.1
```

I opened:

```text
Window → Defined Strings
```

Then searched for the IP and followed its **XREF** into `main()`.

The decompiler showed:

```c
uStack_10106 = htons(0x115d);

inet_pton(
    2,
    "192.168.56.1",
    auStack_10104
);
```

`htons()` converts a port number into network byte order.

The value was:

```text
0x115d
```

Converting hexadecimal to decimal:

```text
0x115d = 4445
```

Therefore:

```text
C2 = 192.168.56.1:4445
```

### Answer

```text
4445
```

---

# 5. Finding the Reconnection Delay

### Question

> How many seconds does the agent wait before attempting to reconnect after a failed connection?

Still inside `main()`, I found:

```c
fwrite(
    "connect() failed: trying to reconnect\n",
    1,
    0x26,
    stderr
);

close(iVar2);

sleep(0x78);
```

The delay is represented in hexadecimal:

```text
0x78
```

Converting:

```text
0x78 = 120
```

### Answer

```text
120 seconds
```

So its C2 logic is essentially:

```text
Connect
   ↓
Failed?
   ↓
Wait 120 seconds
   ↓
Retry
```

---

# 6. What is `io_uring`?

One of the new concepts I learned during this Sherlock was **`io_uring`**.

Normally Linux applications perform operations using system calls such as:

```text
read()
write()
connect()
recv()
```

`io_uring` provides an asynchronous I/O mechanism where applications submit operations into shared queues.

The malware contains functions such as:

```c
io_uring_queue_init()
io_uring_get_sqe()
io_uring_prep_connect()
io_uring_submit()
io_uring_wait_cqe()
io_uring_prep_recv()
```

The name **SQE** means:

```text
Submission Queue Entry
```

The application prepares a request, places it into the queue, and the kernel processes it.

Some EDR implementations historically focused heavily on traditional syscall paths. Using alternative interfaces such as `io_uring` can therefore complicate monitoring, although this does **not mean `io_uring` automatically bypasses every modern EDR**.

### Answer

```text
io_uring
```

---

# 7. Number of Supported Commands

Inside `main()` I found:

```c
process_cmd(...);
```

I followed this function in Ghidra.

Inside `process_cmd()`, different command strings were compared before calling their respective handlers.

The malware supports:

| Command | Purpose |
|---|---|
| `get` | Retrieve a file from victim |
| `recv` | Receive/write a file to victim |
| `users` | Enumerate logged-in users |
| `ss` | Discover network connections |
| `ps` | Enumerate processes |
| `me` | Identify current user |
| `kick` | Terminate a target |
| `privesc` | Search for privilege-escalation opportunities |
| `sdestruct` | Delete the malware |
| `killbpf` | Attack tracing/eBPF monitoring |
| `exit` | Disconnect |

### Answer

```text
11 commands
```

This command structure is one reason I classified the malware as a **remote post-exploitation agent**.

---

# 8. Logged-In User Enumeration

### Question

> What file does the agent read to enumerate logged-in users?

I followed the handler associated with:

```text
users
```

The malware accesses:

```text
/var/run/utmp
```

### What is `utmp`?

`utmp` is a Linux file containing information about current login sessions.

Programs such as:

```bash
who
w
```

can use login/session information to tell which users are currently logged in.

For an attacker, this is valuable reconnaissance because it answers:

> "Who is currently using this machine?"

### Answer

```text
/var/run/utmp
```

This behavior maps well to **MITRE ATT&CK T1033 – System Owner/User Discovery**. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1033/))

---

# 9. Process Discovery

The malware also supports:

```text
ps
```

On Linux, information about running processes can be obtained through:

```text
/proc
```

`/proc` is not a normal directory containing ordinary files. It is a **virtual filesystem created by the Linux kernel**.

For example:

```text
/proc/1234/
```

contains information about process PID `1234`.

MITRE classifies process enumeration as **T1057 – Process Discovery**, including enumeration through `/proc` on Linux. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1057/))

---

# 10. Searching for SUID Binaries

### Question

> What directory does the agent scan when searching for SUID binaries for privilege escalation?

The `privesc` command eventually scans:

```text
/usr/bin
```

### What is SUID?

SUID means:

```text
Set User ID
```

A file with the SUID permission may execute with the privileges of its **owner**, rather than the user launching it.

For example, if a vulnerable SUID executable belongs to:

```text
root
```

an attacker may potentially abuse it to gain elevated privileges.

Conceptually:

```text
Low privileged user
       |
       v
Interesting SUID executable
       |
       v
Possible privilege escalation
       |
       v
root
```

The malware is therefore performing **privilege-escalation reconnaissance**.

### Answer

```text
/usr/bin
```

---

# 11. The `killbpf` Command

This was the most interesting command in the malware.

I followed:

```text
killbpf
```

into:

```c
cmd_killbpf()
```

This function contains several different anti-monitoring actions.

---

# 12. Disabling Linux Kernel Tracing

The function contains:

```c
local_6138[0] =
"/sys/kernel/debug/tracing/tracing_on";

local_6138[1] =
"/sys/kernel/debug/tracing/set_event";

local_6138[2] =
"/sys/kernel/debug/tracing/current_tracer";
```

The malware loops through these files and attempts to modify them.

The first one is:

```text
/sys/kernel/debug/tracing/tracing_on
```

### What is `tracing_on`?

This is part of Linux **ftrace**.

ftrace is a Linux kernel tracing framework that can help administrators, developers, monitoring tools, and security products observe kernel activity.

Conceptually:

```text
Kernel activity
     |
     v
ftrace
     |
     v
Security / debugging visibility
```

If tracing is disabled:

```text
Kernel activity
     X
     |
Reduced telemetry
```

### Answer

```text
/sys/kernel/debug/tracing/tracing_on
```

---

# 13. What is eBPF?

Another major concept in this challenge was **eBPF**.

eBPF allows small programs to run safely inside the Linux kernel for tasks such as:

- networking
- observability
- tracing
- performance monitoring
- security monitoring

Modern Linux security products may use eBPF to observe events such as:

```text
process execution
network connections
file access
system activity
```

---

# 14. What are BPF Maps?

eBPF programs need somewhere to store and exchange information.

That is where **BPF maps** are used.

Think of a BPF map as a kernel-managed data structure:

```text
eBPF program
     |
     v
 BPF Map
     |
     v
User-space security application
```

They may contain information such as:

```text
PID
network event
process information
security telemetry
```

---

# 15. Finding Security Tools Using BPF Maps

### Question

> What string does the agent search for in `/proc/[pid]/maps` to identify security tools using eBPF?

Inside `cmd_killbpf()` I found:

```c
snprintf(
    local_6118,
    0x100,
    "/proc/%s/maps",
    local_6150->d_name
);
```

This generates paths such as:

```text
/proc/1234/maps
/proc/5678/maps
```

The malware reads each file using:

```c
read_file_uring(...)
```

Then performs:

```c
pcVar5 =
strstr(
    local_4018,
    "anon_inode:bpf-map"
);
```

### Answer

```text
anon_inode:bpf-map
```

---

# 16. Killing Processes Using BPF

If the string is found, the malware converts the directory name into a PID:

```c
iVar2 = atoi(local_6150->d_name);
```

Then executes:

```c
kill(iVar2,9);
```

Signal number:

```text
9
```

is:

```text
SIGKILL
```

SIGKILL tells Linux to immediately terminate the process.

Therefore the malware's logic becomes:

```text
Enumerate /proc
      |
      v
Read /proc/<PID>/maps
      |
      v
Find "anon_inode:bpf-map"
      |
      v
Identify BPF-using process
      |
      v
kill(PID, SIGKILL)
```

This does not guarantee that every process found is an EDR, but it clearly demonstrates an attempt to disrupt BPF-using processes.

---

# 17. Removing BPF Objects

`cmd_killbpf()` also opens:

```text
/sys/fs/bpf
```

It enumerates entries and constructs paths such as:

```c
snprintf(
    local_4018,
    0x200,
    "/sys/fs/bpf/%s",
    local_6168->d_name
);
```

It then calls:

```c
io_uring_prep_unlinkat(...)
```

to remove them.

So `killbpf` actually performs several actions:

```text
1. Disable kernel tracing
2. Enumerate /sys/fs/bpf
3. Delete BPF entries
4. Enumerate processes
5. Search process maps for BPF maps
6. Kill matching processes
```

This strongly represents **defense impairment**. MITRE ATT&CK describes disabling or modifying security tools as **T1562.001 – Impair Defenses: Disable or Modify Tools**. ([MITRE ATT&CK](https://attack.mitre.org/docs/changelogs/v13.1-v14.0/changelog-detailed.html))

---

# 18. Self-Destruction

### Question

> What procfs path does the agent read to find its own executable location before self-destruction?

The malware uses:

```text
/proc/self/exe
```

### What does `/proc/self/exe` mean?

Inside `/proc`, the keyword:

```text
self
```

refers to the currently running process.

Therefore:

```text
/proc/self/exe
```

is a symbolic link pointing to the executable that started the current process.

The malware can use this to locate itself without knowing where it was originally stored.

### Answer

```text
/proc/self/exe
```

---

# 19. Self-Destruction Command

The command used to trigger this functionality is:

```text
sdestruct
```

The purpose is simple:

```text
Locate own executable
        |
        v
Delete executable
        |
        v
Reduce forensic evidence
```

MITRE ATT&CK maps malicious cleanup and self-deletion behavior to **T1070.004 – Indicator Removal: File Deletion**. MITRE specifically notes that attackers may delete malware or tools to minimize their footprint. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1070/004/))

### Answer

```text
sdestruct
```

---

# 20. File Transfer Capability

The agent contains both:

```text
get
recv
```

A useful way to understand them is from the attacker's perspective.

### `recv`

The victim **receives** a file from the attacker.

```text
Attacker
   |
   | upload
   v
Victim
```

This could allow the operator to deploy:

- additional malware
- scripts
- tools
- exploit binaries

MITRE maps transferring tools/files into a compromised environment to **T1105 – Ingress Tool Transfer**. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1105/))

### `get`

The attacker retrieves a file from the victim:

```text
Victim
   |
   | data
   v
Attacker
```

If stolen data is transferred through the existing C2 channel, this corresponds to **T1041 – Exfiltration Over C2 Channel**. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1041/))

---

# 21. Network Discovery

The agent contains an:

```text
ss
```

command that can retrieve information about network connections.

This allows an attacker to understand:

- existing connections
- remote systems
- services being contacted
- potentially interesting infrastructure

MITRE ATT&CK maps network connection enumeration to **T1049 – System Network Connections Discovery**. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1049/))

---

# 22. C2 Communication

The malware creates its connection using:

```c
socket(2,1,0);
```

and:

```c
io_uring_prep_connect(...)
```

with:

```text
192.168.56.1:4445
```

It then waits for commands from the remote operator.

This is not a normal web API or HTTPS application protocol. It behaves as a custom socket-based C2 mechanism.

MITRE's **T1095 – Non-Application Layer Protocol** covers adversaries communicating with C2 through protocols below the application layer, including transport-layer communication. ([MITRE ATT&CK](https://attack.mitre.org/techniques/T1095/))

---

# 23. MITRE ATT&CK Mapping

| Technique | ID | Observed behavior |
|---|---|---|
| System Owner/User Discovery | T1033 | Enumerates logged-in users |
| Process Discovery | T1057 | Enumerates `/proc` |
| System Network Connections Discovery | T1049 | `ss` capability |
| Ingress Tool Transfer | T1105 | `recv` |
| Exfiltration Over C2 Channel | T1041 | `get` |
| Non-Application Layer Protocol | T1095 | Custom socket C2 |
| Disable or Modify Tools | T1562.001 | `killbpf` anti-monitoring |
| File Deletion | T1070.004 | `sdestruct` |

---

# 24. Indicators of Compromise

### Network

```text
192.168.56.1
TCP/4445
```

### SHA256

```text
2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5
```

### Interesting strings

```text
killbpf
sdestruct
anon_inode:bpf-map
/proc/self/exe
/var/run/utmp
/usr/bin
/sys/fs/bpf
/sys/kernel/debug/tracing/tracing_on
/sys/kernel/debug/tracing/set_event
/sys/kernel/debug/tracing/current_tracer
```

---

# 25. Detection Opportunities

From a defender/SOC perspective, several behaviors would be suspicious when combined:

```text
Unknown process
   +
connection to unusual TCP port
   +
enumeration of /proc/*/maps
   +
access to /sys/fs/bpf
   +
modification of tracing controls
   +
SIGKILL against BPF-using processes
```

Another useful detection point would be monitoring unexpected writes to:

```text
/sys/kernel/debug/tracing/tracing_on
```

and unexpected deletion of objects under:

```text
/sys/fs/bpf
```

A normal application generally has little reason to perform **all of these actions together**.

---

# 26. What I Learned

This Sherlock helped me understand that malware analysis is not simply finding suspicious strings.

The workflow I used was:

```text
Interesting string
      |
      v
Find XREF
      |
      v
Open function
      |
      v
Read decompiled code
      |
      v
Identify Linux API
      |
      v
Understand behavior
      |
      v
Determine attacker purpose
```

For example:

```text
"anon_inode:bpf-map"
        |
        v
XREF
        |
        v
cmd_killbpf()
        |
        v
/proc/<PID>/maps
        |
        v
strstr()
        |
        v
kill(PID,9)
```

Instead of simply answering:

> `anon_inode:bpf-map`

I could now explain **where it is searched, why it is searched, and what happens after the malware finds it**.

That is the biggest skill I gained from this Sherlock.

---

# Conclusion

PhantomRing's `agent` is a Linux post-exploitation malware implant designed to give a remote operator control over a compromised system.

The sample can perform reconnaissance, transfer files, search for privilege-escalation opportunities, inspect users and processes, communicate with a C2 server, interfere with kernel/eBPF monitoring, and finally delete itself.

The most interesting feature was the combination of:

```text
io_uring
+
ftrace disruption
+
BPF map detection
+
process termination
+
self-deletion
```

Before this challenge, terms such as **io_uring, eBPF, BPF maps, ftrace, procfs, SUID and SIGKILL** were concepts I had not deeply explored. Reversing the malware in Ghidra helped me understand how those Linux features look when they are actually abused by malicious software.

Rather than only solving the questions, this Sherlock became a useful introduction to **Linux malware reverse engineering and anti-EDR behavior**.
