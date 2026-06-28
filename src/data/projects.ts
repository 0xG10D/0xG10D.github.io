export interface Project {
  id: string;
  name: string;
  title: string;
  type: string;
  tagline: string;
  summary: string;
  overview: string;
  problem: string;
  securityUseCaseTitle: string;
  securityUseCase: string;
  helpTitle: string;
  helpText: string;
  stack: string[];
  features: string[];
  workflow: string[];
  future: string[];
  repoUrl: string;
  route: string;
  screenshots?: {
    src: string;
    alt: string;
    caption: string;
    wide?: boolean;
  }[];
}

export const projects: Project[] = [
  {
    id: 'awd-watchdog',
    name: 'AWD-Watchdog',
    title: 'AWD-Watchdog',
    type: 'Attack-Defense CTF monitoring',
    tagline: 'Defensive visibility for authorized Attack-Defense CTF rounds.',
    summary:
      'A lightweight defensive toolkit that combines IDS alerts, web logs, file integrity monitoring, PCAP capture, and health checks for AWD rounds.',
    overview:
      'AWD-Watchdog is built for authorized Attack-Defense CTF environments where teams need fast visibility into who is hitting their box, which endpoint is under pressure, and whether service changes or outages need immediate action.',
    problem:
      'In AWD rounds, teams often split attention between patching, checking service health, watching logs, and collecting evidence. This toolkit pulls those signals into one defensive workflow so decisions can happen faster.',
    securityUseCaseTitle: 'Security use case',
    securityUseCase:
      'It supports defensive monitoring, alert triage, evidence collection, and patch guidance. It does not automate attacks or exploit other teams.',
    helpTitle: 'How it helps during AWD',
    helpText:
      'The dashboard view helps a team move from alert to action: identify the source IP, inspect the targeted endpoint, patch vulnerable logic, restart the service, confirm the checker still passes, and preserve evidence for review.',
    stack: ['Python', 'Suricata', 'Zeek', 'tcpdump', 'auditd', 'inotifywait', 'Shell'],
    features: [
      'Parses Suricata eve.json alerts, Apache/Nginx access logs, and optional Zeek http.log data.',
      'Ranks source IPs, attacked HTTP paths, services, and likely vulnerability classes.',
      'Watches web and service folders for suspicious file changes using inotifywait.',
      'Runs HTTP/TCP health checks so the team can see service availability during a round.',
      'Writes JSONL evidence and supports rotating tcpdump capture for post-round review.',
      'Supports optional Discord or Telegram alerting for team coordination.'
    ],
    workflow: [
      'Collect network, web, and host signals from the challenge box.',
      'Classify activity such as SQL injection, command injection, traversal, upload abuse, or debug probing.',
      'Surface attacker IPs, target endpoints, and file-change evidence in the terminal dashboard.',
      'Use the alert context to patch, restart services, verify checkers, and improve rules.'
    ],
    future: [
      'Add richer web dashboard views for long-running competitions.',
      'Export evidence into SIEM-friendly formats.',
      'Expand competition playbooks and custom rule packs.',
      'Harden service deployment profiles for repeat team use.'
    ],
    repoUrl: 'https://github.com/0xG10D/AWD-Watchdog',
    route: '/projects/awd-watchdog/'
  },
  {
    id: 'wavesentinel-wids',
    name: 'WaveSentinel / AirGuard WIDS',
    title: 'WaveSentinel / AirGuard WIDS',
    type: 'Wireless intrusion detection',
    tagline: 'Wireless IDS lab project for authorized 802.11 monitoring.',
    summary:
      'A defensive 802.11 monitoring system that captures monitor-mode traffic, raises wireless alerts, and presents analyst-friendly dashboard views.',
    overview:
      'WaveSentinel is a defensive wireless intrusion detection project for authorized lab environments. It monitors 802.11 frames, raises wireless alerts, stores runtime evidence, and presents findings through dashboard views.',
    problem:
      'Wireless labs generate noisy packet streams. WaveSentinel turns monitor-mode traffic into readable status, alert feeds, and analyst filters so suspicious behavior is easier to explain and review.',
    securityUseCaseTitle: 'Detection focus',
    securityUseCase:
      'The project focuses on deauthentication flood indicators, beacon flood behavior, suspicious 802.11 frame patterns, disassociation activity, and rogue AP or evil twin indicators shown in the alert workflow.',
    helpTitle: 'How it helps wireless labs',
    helpText:
      'The Simple View supports quick operator decisions, while Analyst View gives raw inventory and filters for deeper investigation. Runtime files keep a record of alerts, devices, traffic logs, status, and activity.',
    stack: ['Python', 'Scapy', 'Flask', '802.11 monitor mode', 'CSV/JSON logs', 'HTML/CSS'],
    features: [
      'Captures live 802.11 traffic from a monitor-mode wireless adapter.',
      'Tracks access points, clients, beacon activity, deauthentication frames, and suspicious traffic patterns.',
      'Provides Simple View and Analyst View dashboard modes for different audiences.',
      'Writes runtime evidence to alerts, devices, traffic logs, status, and activity log files.',
      'Uses severity, attack type, BSSID, ESSID, and channel filters in the analyst workflow.',
      'Includes safety controls such as clean session reset and stale lock handling.'
    ],
    workflow: [
      'Enable monitor mode on a supported adapter and lock the capture channel.',
      'Capture IEEE 802.11 frames with Scapy and extract frame metadata.',
      'Apply detection rules for deauthentication floods, beacon floods, disassociation activity, and rogue AP or evil twin indicators.',
      'Persist alerts and device state into local CSV/JSON files.',
      'Render status, recommendations, filters, and alert feeds in the dashboard.'
    ],
    future: [
      'Tune thresholds across more adapters, channels, and crowded lab environments.',
      'Add stronger rogue AP baselining and known-network comparison.',
      'Improve packet capture summaries for replay-free lab demonstrations.',
      'Package dashboard screenshots and operator guides for easier setup.'
    ],
    repoUrl: 'https://github.com/0xG10D/wavesentinel-wids',
    route: '/projects/wavesentinel-wids/',
    screenshots: [
      {
        src: '/images/projects/wavesentinel-wids/architecture.png',
        alt: 'WaveSentinel workflow flowchart',
        caption:
          'Monitoring workflow from adapter checks through frame capture, rule analysis, alert generation, logging, and dashboard updates.',
        wide: true
      },
      {
        src: '/images/projects/wavesentinel-wids/dashboard.png',
        alt: 'WaveSentinel dashboard simple view',
        caption:
          'Simple dashboard view with status, plain-language findings, recommendations, and summary counters.'
      },
      {
        src: '/images/projects/wavesentinel-wids/detection-output.png',
        alt: 'WaveSentinel alert feed showing beacon flood detection',
        caption:
          'Alert feed showing beacon flood, deauthentication, disassociation, and rogue AP or evil twin indicators.'
      }
    ]
  }
];

export const getProjectById = (id: string) => projects.find((project) => project.id === id);
