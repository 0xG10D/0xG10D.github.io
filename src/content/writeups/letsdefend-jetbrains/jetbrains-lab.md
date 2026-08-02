---
event: "letsdefend-jetbrains"
title: "JetBrains Lab"
summary: "LetsDefend JetBrains lab writeup using Wireshark to reconstruct TeamCity exploitation, webshell activity, and MITRE ATT&CK mapping."
date: 2026-07-23
tags:
  - letsdefend
  - cyberdefenders
  - wireshark
  - pcap
  - teamcity
  - cve-2024-27198
  - incident-response
  - mitre-attack
category: "forensics"
difficulty: "info"
platform: "other"
draft: false
---
## Lab Objective

Analyze network traffic using Wireshark to identify web server exploitation, extract attacker IOCs and persistence mechanisms, and map attack techniques to MITRE ATT&CK.

Link Lab: https://cyberdefenders.org/blueteam-ctf-challenges/jetbrains/

## Scenario
During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation.

As part of the investigation, I was provided with a packet capture (PCAP) of the network traffic during the attack. The goal was to reconstruct the attack timeline, identify the initial entry point, document the attacker's tools and techniques, and determine the extent of compromise.

## Questions

### 1. Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?

![pasted-image-20260723085421](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723085421.png)

I used this Wireshark display filter to review HTTP POST requests and identify the traffic related to the reverse shell upload:

```
http.request.method == POST
```

![pasted-image-20260723085715](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723085715.png)

From the screenshot, the first relevant item was `plugins.html`. After that request, the attacker uploaded a reverse shell through the plugin upload feature.

```
POST /admin/pluginUpload.html HTTP/1.1\r\n
```

The attacker IP was visible in the IPv4 packet details:

```
Internet Protocol Version 4, Src: 23.158.56.196, Dst: 172.17.0.2
```

```
Answer: 23.158.56.196
```

### 2. To identify potential vulnerability exploitation, what version of our web server service is running?

Using the same filter, I inspected the request that exposed server information.

```
POST /hax?jsp=/app/rest/users/id:2/tokens/[REDACTED_TOKEN];.jsp HTTP/1.1\r\n
```

The request exposed the server version:

![pasted-image-20260723091002](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723091002.png)

```
Answer: 2023.11.3
```

### 3. After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?

![pasted-image-20260723091515](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723091515.png)

```
Answer: CVE-2024-27198
```

**CVE-2024-27198 (CVSS Score: 9.8 - Critical):** An alternative path issue in the TeamCity web component that permits unauthenticated remote code execution (RCE). Attackers exploit this by sending specially crafted HTTP GET requests to bypass authentication and manipulate administrative controls.

### 4. The attacker exploited the vulnerability to create a user account. What credentials did he set up?

![pasted-image-20260723091840](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723091840.png)

```
{"username": "c91oyemw", "password": "[REDACTED_PASSWORD]", "email": "c91oyemw@example.com", "roles": {"role": [{"roleId": "SYSTEM_ADMIN", "scope": "g"}]}}HTTP/1.1 200
```

```
Answer: c91oyemw:[REDACTED_PASSWORD]
```

### 5. The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?

![pasted-image-20260723092123](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723092123.png)

```
Answer: NSt8bHTg.zip
```

### 6. When did the attacker execute their first command via the web shell?

![pasted-image-20260723092434](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723092434.png)

```
Jun 30, 2024 08:03:06.371218000 UTC
```

```
Answer: 2024-06-30 08:03
```

### 7. The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?

Using this filter, I reviewed the commands the attacker sent to the web server:

```text
http contains "cmd="
```

![pasted-image-20260723093545](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723093545.png)

```
cmd=bash -c 'echo "username:[REDACTED_USER],password:[REDACTED_PASSWORD]" > /tmp/Creds.txt'
```

```
Answer: [REDACTED_USER]:[REDACTED_PASSWORD]
```

This confirmed that the attacker changed the stored username.

![pasted-image-20260723093525](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723093525.png)

### 8. What is the MITRE Technique ID for the attacker's action in the previous question (Q7) when tampering with the text file?

![pasted-image-20260723094306](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723094306.png)

```
Answer: T1565.001
```


### 9. The attacker tried to escape from the container but did not succeed. What command did he use?

![pasted-image-20260723093650](/images/writeups/letsdefend/jetbrains/jetbrains-lab/pasted-image-20260723093650.png)

```
cmd=docker+run+--rm+-it+--privileged+ubuntu
```

```
Answer: docker run --rm -it -v /:/host ubuntu chroot /host
```
