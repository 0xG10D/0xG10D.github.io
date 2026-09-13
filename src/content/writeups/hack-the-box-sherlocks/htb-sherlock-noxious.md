---
slug: "hackthebox/sherlocks/htb-sherlock-noxious"
event: "hack-the-box-sherlocks"
title: "HTB Sherlock Noxious"
summary: "Network forensics on an Active Directory PCAP: spotting LLMNR poisoning from a rogue Responder host, rebuilding the captured NetNTLMv2 hash from Wireshark, and cracking it with Hashcat."
date: 2026-09-12
tags:
  - htb
  - sherlock
  - dfir
  - network-forensics
  - wireshark
  - llmnr
  - responder
  - ntlm
  - netntlmv2
  - hashcat
  - active-directory
category: "forensics"
difficulty: "easy"
platform: "hackthebox"
draft: false
boxImage: "https://cdn.services-k8s.prod.aws.htb.systems/content/sherlocks/avatar/9e4d9101-1ea9-40f3-b4a7-7879c7533528.png"
---

## Introduction

**Noxious** is a Hack The Box Sherlock focused on network forensics inside an Active Directory environment.

In this investigation, an IDS detected unusual **LLMNR traffic** involving the workstation `Forela-WKstn002` (`172.17.79.136`). The main suspicion was that a rogue machine inside the network was running **Responder** and performing an **LLMNR poisoning attack**.

The goal was to use the provided packet capture to identify the rogue device, understand how the victim leaked NTLM credentials, reconstruct the captured NetNTLMv2 hash, crack the password, and finally identify the file share the victim originally wanted to access.

This Sherlock was useful because it showed how something as simple as a hostname typo can lead to credential exposure in a Windows/Active Directory network.

---

# Tools Used

## Wireshark

Used for:

- Reading the PCAP

- Filtering LLMNR traffic

- Identifying the rogue machine

- Inspecting DHCP information

- Following SMB traffic

- Inspecting NTLM negotiation packets

- Extracting the NTLM server challenge

- Extracting the NTProofStr

- Finding the intended SMB share


## Hashcat

Used to crack the captured **NetNTLMv2** challenge-response.

Hashcat mode:

```
-m 5600
```

`5600` is the Hashcat mode for NetNTLMv2.

## RockYou Wordlist

```
/usr/share/wordlists/rockyou.txt
```

Used as the dictionary for the offline password-cracking attempt.

---

# Important Terms

## Active Directory

**Active Directory (AD)** is Microsoft's directory service commonly used in Windows enterprise networks.

It manages things such as:

- Users

- Computers

- Groups

- Authentication

- Domain resources

- File shares


In this Sherlock, the victim workstation belonged to an Active Directory environment.

---

## IDS

**IDS** stands for **Intrusion Detection System**.

Its job is to monitor network or host activity and alert when suspicious behaviour is detected.

In this scenario, the IDS detected unusual LLMNR activity.

---

## LLMNR

**LLMNR** stands for **Link-Local Multicast Name Resolution**.

Windows can use LLMNR when normal DNS name resolution fails.

For example, if a user tries to access:

```
\\DCC01
```

and DNS cannot resolve `DCC01`, Windows may ask other machines on the local network:

```
Who knows DCC01?
```

IPv4 LLMNR uses:

```
224.0.0.252
UDP/5355
```

This behaviour can be abused by attackers.

---

## Responder

**Responder** is a tool often used during internal network penetration testing.

It listens for protocols such as:

- LLMNR

- NBT-NS

- mDNS


If a victim asks:

```
Who is DCC01?
```

Responder can reply:

```
I am DCC01.
```

The victim may then automatically attempt NTLM authentication to the attacker's machine.

Responder can capture the NetNTLMv2 challenge-response and the attacker can try to crack it offline.

---

## SMB

**SMB** stands for **Server Message Block**.

Windows uses SMB for services such as:

- File sharing

- Printer sharing

- Named pipes

- Accessing network resources


The usual SMB port is:

```
TCP/445
```

---

## NTLM / NetNTLMv2

NTLM is a Windows authentication protocol.

In this incident, the attacker did **not** directly receive the victim's plaintext password.

Instead, the attacker received an NTLMv2 challenge-response.

The attacker can then test password guesses offline.

Hashcat refers to this captured network format as:

```
NetNTLMv2
```

---

## NTLMSSP

**NTLMSSP** stands for **NTLM Security Support Provider**.

The authentication normally contains three important stages:

```
NTLMSSP_NEGOTIATE
        ↓
NTLMSSP_CHALLENGE
        ↓
NTLMSSP_AUTH
```

The server sends a random challenge and the client creates a response using the user's credentials.

---

## NTLM Server Challenge

The **server challenge** is an 8-byte value sent to the client during the NTLM challenge stage.

In this investigation:

```
601019d191f054f1
```

---

## NTProofStr

`NTProofStr` is part of the NTLMv2 response.

It is needed together with:

- Username

- Domain

- Server challenge

- Remaining NTLMv2 response blob


to rebuild the NetNTLMv2 hash for cracking.

---

# Investigation

## Task 1 — Find the malicious IP address

The victim workstation was already provided:

```
Forela-WKstn002
172.17.79.136
```

I started by filtering for LLMNR traffic from the victim.

### Wireshark filter

```
ip.addr == 172.17.79.136 && udp.port == 5355
```

The victim repeatedly sent:

```
172.17.79.136 → 224.0.0.252
Standard query A DCC01
```

This means the victim was asking the local network to resolve the hostname `DCC01`.

Then another device answered:

```
172.17.79.135 → 172.17.79.136
Standard query response A DCC01 A 172.17.79.135
```

So `172.17.79.135` was claiming:

```
I am DCC01.
```

That behaviour matched the suspected LLMNR poisoning attack.

### Answer

```
172.17.79.135
```

---

# Task 2 — Find the hostname of the rogue machine

Now that the rogue IP was known, I looked for DHCP traffic from it.

### Wireshark filter

```
ip.addr == 172.17.79.135 && dhcp
```

I found a DHCP Request from:

```
172.17.79.135
```

Inside the DHCP packet:

```
Option: (12) Host Name
    Host Name: kali
```

DHCP Option 12 contains the hostname supplied by the client.

### Answer

```
kali
```

---

# Task 3 — Find the username whose hash was captured

Next I searched for NTLM authentication between the victim and the rogue device.

### Wireshark filter

```
ntlmssp.messagetype == 3
```

Message type `3` is:

```
NTLMSSP_AUTH
```

In Frame `9292`, Wireshark showed:

```
Domain name: FORELA
User name: john.deacon
Host name: FORELA-WKSTN002
```

The SMB header also summarized it as:

```
Acct: john.deacon
Domain: FORELA
Host: FORELA-WKSTN002
```

### Answer

```
john.deacon
```

---

# Task 4 — Find when the hash was captured for the first time

The victim authenticated multiple times, so I needed the earliest `NTLMSSP_AUTH` packet.

### Wireshark filter

```
ntlmssp.messagetype == 3
```

I sorted the packets by time and inspected the first authentication packet.

Frame `9292` showed:

```
UTC Arrival Time:
Jun 24, 2024 11:18:30.922052000 UTC
```

For forensic timing I used the **frame arrival time**, not the timestamp embedded inside the NTLMv2 response.

### Answer

```
2024-06-24 11:18:30 UTC
```

---

# Task 5 — Find the typo that caused the credential leak

The LLMNR traffic showed the victim asking for:

```
DCC01
```

However, later SMB traffic showed the legitimate server name:

```
DC01
```

So the user typed:

```
DCC01
```

instead of:

```
DC01
```

The extra `C` caused normal name resolution to fail.

That caused Windows to fall back to LLMNR, giving the attacker's Responder instance a chance to answer.

### Answer

```
DCC01
```

---

# Why the typo mattered

The attack chain was:

```
Victim wants \\DC01\...
        ↓
Victim accidentally types \\DCC01\...
        ↓
DNS cannot resolve DCC01
        ↓
Windows sends LLMNR query
        ↓
Responder replies "I am DCC01"
        ↓
Victim connects to attacker
        ↓
Victim sends NTLM authentication
        ↓
Attacker captures NetNTLMv2 response
```

This was the main cause of the credential exposure.

---

# Task 6 — Find the NTLM server challenge

I filtered for NTLM challenge packets.

### Wireshark filter

```
ntlmssp.messagetype == 2
```

Message type `2` is:

```
NTLMSSP_CHALLENGE
```

Frame `9291` contained:

```
NTLM Server Challenge: 601019d191f054f1
```

This packet came directly before the authentication packet in Frame `9292`.

### Answer

```
601019d191f054f1
```

---

# Task 7 — Find the NTProofStr

I returned to the matching authentication packet.

### Wireshark filter

```
ntlmssp.messagetype == 3
```

Then expanded:

```
NTLM Secure Service Provider
→ NTLM Response
→ NTLMv2 Response
```

Frame `9292` contained:

```
NTProofStr:
c0cc803a6d9fb5a9082253a04dbd4cd4
```

There were multiple NTLM authentication attempts in the capture, so it was important to use the NTProofStr from the authentication packet that matched the selected server challenge.

### Answer

```
c0cc803a6d9fb5a9082253a04dbd4cd4
```

---

# Task 8 — Recover the victim's password

Now I had enough information to reconstruct the NetNTLMv2 hash.

Known values:

```
Username:
john.deacon

Domain:
FORELA

Server Challenge:
601019d191f054f1

NTProofStr:
c0cc803a6d9fb5a9082253a04dbd4cd4
```

From Frame `9292`, I copied the full NTLMv2 Response.

It started with:

```
c0cc803a6d9fb5a9082253a04dbd4cd401010000...
```

The first 32 hexadecimal characters are the NTProofStr.

So the remaining response blob starts with:

```
010100000000000080e4d59406c6da01...
```

The Hashcat format is:

```
username::domain:server_challenge:NTProofStr:blob
```

So the reconstructed hash looked like:

```
john.deacon::FORELA:601019d191f054f1:c0cc803a6d9fb5a9082253a04dbd4cd4:0101000000000000...
```

I saved it:

```
nano hash.txt
```

Then ran Hashcat:

```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Hashcat reported:

```
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Recovered........: 1/1 (100.00%)
```

The recovered password was:

```
NotMyPassword0k?
```

The crack took only around 14 seconds on my CPU using RockYou.

### Answer

```
NotMyPassword0k?
```

---

# Why this password was weak

At first glance:

```
NotMyPassword0k?
```

looks reasonably complex because it contains:

- Uppercase characters

- Lowercase characters

- Numbers

- A special character


But complexity rules alone do not guarantee a strong password.

The password was already present in a common password dictionary, meaning an attacker could recover it very quickly with an offline dictionary attack.

This is why password uniqueness and resistance to known password lists matter more than simply adding symbols or numbers.

---

# Task 9 — Find the real file share

Finally, I looked at SMB Tree Connect traffic.

### Wireshark filter

```
smb2.cmd == 3
```

`SMB2 Tree Connect` is used when a client connects to an SMB share.

The capture showed:

```
\\DC01\DC-Confidential
```

I also saw the available shares:

```
ADMIN$
C$
DC-Confidential
IPC$
NETLOGON
SYSVOL
```

The victim's intended share was:

```
\\DC01\DC-Confidential
```

### Answer

```
\\DC01\DC-Confidential
```

---

# Final Attack Timeline

The full incident can be summarized as:

```
1. john.deacon attempts to access:
   \\DC01\DC-Confidential

2. The hostname is accidentally mistyped as:
   DCC01

3. DNS cannot resolve DCC01.

4. Forela-WKstn002 sends an LLMNR request:
   "Who is DCC01?"

5. Rogue machine 172.17.79.135 answers.

6. The rogue host identifies itself through DHCP as:
   kali

7. The victim attempts SMB authentication.

8. The attacker receives john.deacon's NetNTLMv2 response.

9. The challenge-response is reconstructed.

10. Hashcat cracks the password:
    NotMyPassword0k?
```

---

# Useful Wireshark Filters

## LLMNR

```
llmnr
```

or:

```
udp.port == 5355
```

Victim-specific:

```
ip.addr == 172.17.79.136 && udp.port == 5355
```

---

## Rogue DHCP traffic

```
ip.addr == 172.17.79.135 && dhcp
```

---

## NTLM authentication

```
ntlmssp
```

Authentication only:

```
ntlmssp.messagetype == 3
```

Challenge only:

```
ntlmssp.messagetype == 2
```

---

## SMB Tree Connect

```
smb2.cmd == 3
```

---

# Hashcat Commands

Create the hash file:

```
nano hash.txt
```

Crack NetNTLMv2:

```
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

Show recovered result:

```
hashcat -m 5600 hash.txt --show
```

Optional optimized mode:

```
hashcat -m 5600 -O hash.txt /usr/share/wordlists/rockyou.txt
```

---

# Indicators Found

```
Victim IP:
172.17.79.136

Victim Host:
FORELA-WKSTN002

Victim User:
john.deacon

Domain:
FORELA

Rogue IP:
172.17.79.135

Rogue Hostname:
kali

Mistyped Host:
DCC01

Legitimate Host:
DC01

Target Share:
\\DC01\DC-Confidential

Captured Authentication:
NetNTLMv2

Recovered Password:
NotMyPassword0k?
```

---

# Lessons Learned

The main lesson from Noxious is that LLMNR can become dangerous inside Windows networks when an attacker is already present on the same local network.

A small mistake such as:

```
DC01 → DCC01
```

was enough to trigger fallback name resolution.

Responder abused that fallback mechanism and convinced the victim that the attacker-controlled host was the requested server.

The victim then automatically attempted NTLM authentication, giving the attacker material that could be cracked offline.

This challenge also showed why packet-level investigation is important. By following the traffic in order, we could reconstruct the entire attack without needing access to the original endpoints.

---

# Defensive Takeaways

To reduce the risk of this type of attack:

- Disable LLMNR where possible.

- Disable NBT-NS if it is not required.

- Use strong, unique passwords that are not present in common wordlists.

- Enforce SMB signing where appropriate.

- Monitor unusual LLMNR/NBT-NS responses.

- Alert when one workstation answers name-resolution requests for many unrelated hostnames.

- Monitor unexpected NTLM authentication to workstations.

- Prefer Kerberos in Active Directory environments where possible.

- Investigate unexpected SMB authentication immediately.


---

# Conclusion

Noxious was a good network forensics Sherlock because it connected several topics together:

```
LLMNR
→ Responder
→ SMB
→ NTLM
→ NetNTLMv2
→ Hashcat
```

The most interesting part for me was seeing how the whole attack started from one typo in a file-server hostname.

Instead of only finding the final answer, following each packet made it much easier to understand how Responder captures NTLM authentication and how the captured values are rebuilt into a format that Hashcat can crack.

The final incident showed that the victim was trying to access:

```
\\DC01\DC-Confidential
```

but the typo `DCC01` caused LLMNR to trigger, allowing the rogue device to capture `john.deacon`'s NetNTLMv2 authentication and recover the password offline.
