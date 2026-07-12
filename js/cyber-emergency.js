/**
 * CyberShield SOC Cyber Emergency Center Controller
 * ---------------------------------------------------------------------------
 * Provides real-time containment playbooks, interactive wizards, checklists,
 * incident timelines, India Government escalation guides (cybercrime.gov.in / 1930),
 * and exportable evidence audit sheets.
 */

// 1. Injected Stylesheet for Cyber Emergency Center UI
const emergencyStyles = `
  /* Emergency Sidebar Navigation */
  .emergency-menu-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: rgba(15, 23, 42, 0.3);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    color: var(--text-secondary);
    text-align: left;
    width: 100%;
  }

  .emergency-menu-item:hover {
    background: rgba(239, 68, 68, 0.08);
    border-color: rgba(239, 68, 68, 0.2);
    color: var(--text-primary);
    transform: translateX(4px);
  }

  .emergency-menu-item.active {
    background: rgba(239, 68, 68, 0.15);
    border-color: var(--rose-glow);
    color: #fff;
    box-shadow: 0 0 15px rgba(244, 63, 94, 0.15);
  }

  .emergency-menu-item .menu-icon {
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  /* Severity Badges */
  .sev-badge {
    font-family: var(--font-mono);
    font-size: 9px;
    font-weight: 700;
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    margin-left: auto;
  }

  .sev-critical {
    background: rgba(225, 29, 72, 0.15);
    color: var(--rose-bright);
    border: 1px solid rgba(225, 29, 72, 0.3);
    box-shadow: 0 0 8px rgba(225, 29, 72, 0.2);
    animation: pulse-red 2s infinite;
  }

  .sev-high {
    background: rgba(217, 119, 6, 0.15);
    color: var(--amber-bright);
    border: 1px solid rgba(217, 119, 6, 0.3);
  }

  .sev-medium {
    background: rgba(234, 179, 8, 0.15);
    color: #fef08a;
    border: 1px solid rgba(234, 179, 8, 0.3);
  }

  .sev-low {
    background: rgba(6, 182, 212, 0.15);
    color: var(--cyan-bright);
    border: 1px solid rgba(6, 182, 212, 0.3);
  }

  @keyframes pulse-red {
    0% { opacity: 0.8; }
    50% { opacity: 1; box-shadow: 0 0 12px rgba(225, 29, 72, 0.4); }
    100% { opacity: 0.8; }
  }

  /* Wizard Steps and Checklists */
  .wizard-progress-bar-outer {
    width: 100%;
    height: 6px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: 24px;
  }

  .wizard-progress-bar-inner {
    height: 100%;
    background: linear-gradient(90deg, var(--rose-glow), var(--cyan-glow));
    width: 0%;
    transition: width 0.4s ease;
    box-shadow: 0 0 10px rgba(6, 182, 212, 0.5);
  }

  .step-checkbox-wrapper {
    display: flex;
    gap: 16px;
    padding: 16px;
    background: rgba(15, 23, 42, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.04);
    border-radius: 8px;
    transition: all 0.2s;
  }

  .step-checkbox-wrapper:hover {
    border-color: rgba(255, 255, 255, 0.08);
    background: rgba(15, 23, 42, 0.35);
  }

  .step-checkbox-wrapper.completed {
    border-color: rgba(16, 185, 129, 0.2);
    background: rgba(16, 185, 129, 0.02);
  }

  .custom-emergency-checkbox {
    width: 20px;
    height: 20px;
    border-radius: 4px;
    border: 1.5px solid var(--text-muted);
    background: rgba(3, 7, 18, 0.6);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: all 0.2s;
    user-select: none;
  }

  .custom-emergency-checkbox.checked {
    background: var(--emerald-glow);
    border-color: var(--emerald-glow);
    color: #020617;
  }

  .custom-emergency-checkbox i {
    width: 12px;
    height: 12px;
    stroke-width: 3px;
  }

  /* Timeline */
  .soc-timeline-container {
    position: relative;
    padding-left: 24px;
    border-left: 2px dashed rgba(255, 255, 255, 0.1);
    margin-top: 16px;
    margin-bottom: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .soc-timeline-node {
    position: relative;
  }

  .soc-timeline-dot {
    position: absolute;
    left: -31px;
    top: 4px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--rose-dark);
    border: 2px solid #020617;
    box-shadow: 0 0 6px var(--rose-glow);
  }

  .soc-timeline-node:nth-child(even) .soc-timeline-dot {
    background: var(--cyan-dark);
    box-shadow: 0 0 6px var(--cyan-glow);
  }

  .soc-timeline-time {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--rose-bright);
    font-weight: 700;
  }

  .soc-timeline-node:nth-child(even) .soc-timeline-time {
    color: var(--cyan-bright);
  }

  /* Interactive Collapsible FAQ inside Emergency */
  .emergency-faq-item {
    border: 1px solid rgba(255, 255, 255, 0.05);
    background: rgba(15, 23, 42, 0.2);
    border-radius: 6px;
    overflow: hidden;
    margin-bottom: 8px;
    transition: all 0.2s;
  }

  .emergency-faq-item:hover {
    border-color: rgba(255, 255, 255, 0.1);
  }

  .emergency-faq-header {
    padding: 12px 16px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    user-select: none;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-primary);
  }

  .emergency-faq-header i {
    transition: transform 0.2s ease;
    width: 14px;
    height: 14px;
    color: var(--text-muted);
  }

  .emergency-faq-item.expanded .emergency-faq-header i {
    transform: rotate(180deg);
    color: var(--rose-bright);
  }

  .emergency-faq-body {
    padding: 0 16px;
    max-height: 0;
    overflow: hidden;
    transition: max-height 0.25s ease-out, padding 0.25s ease-out;
    font-size: 12.5px;
    color: var(--text-secondary);
    line-height: 1.5;
    background: rgba(3, 7, 18, 0.2);
  }

  .emergency-faq-item.expanded .emergency-faq-body {
    padding: 12px 16px;
    max-height: 200px;
    border-top: 1px solid rgba(255, 255, 255, 0.03);
  }
`;

// Inject Stylesheet
const styleEl = document.createElement('style');
styleEl.textContent = emergencyStyles;
document.head.appendChild(styleEl);

// 2. Playbooks Static Database
const PLAYBOOKS = [
  {
    id: "report_incident",
    icon: "shield-alert",
    title: "Report Cyber Incident",
    severity: "medium",
    description: "System assessment flow to identify compromised corporate identities, isolate infected local machines, and prepare an official incident report for legal escalation.",
    steps: [
      "Conduct threat assessment & identify anomalies (unauthorized logins, file alterations, rogue mails).",
      "Isolate affected hosts immediately by disconnecting ethernet lines, router Wi-Fi links, or cellular data.",
      "Capture forensic artifacts such as complete email header source files, system timestamps, and error screens.",
      "Check credential integrity by conducting a comprehensive compromise check on secondary identity channels.",
      "Report the incident formally to India Cyber Crime authorities (via 1930 Helpline or portal)."
    ],
    checklists: {
      evidence: [
        "Take clear screenshots of fake messages, ransom screens, or suspicious alerts.",
        "Save original mail header sources (.eml format) or messaging logs with caller IDs.",
        "Document precise system timestamps, date-times, and active session locations.",
        "Verify public IP addresses involved via local diagnostics loggers."
      ],
      password_reset: [
        "Initiate a comprehensive credentials rotation on all active workspace modules.",
        "Create high-entropy unique passphrases (16+ chars) using specialized random entropy nodes."
      ],
      mfa: [
        "Force-revoke active OAuth permissions from external identity providers.",
        "Setup hardware-based or app-based authenticator keys to lock out active session stealers."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Anomaly Recognition", desc: "System triggers alerts on unusual transaction volumes, lateral data transfers, or repeated invalid auth handshakes." },
      { time: "T+15m", title: "Host Isolation", desc: "Operative dispatches immediate network disconnection, cutting LAN grids and shutting down wireless endpoint cards." },
      { time: "T+30m", title: "Forensic Extraction", desc: "Extraction of raw event logs, memory registers, active port listings, and screenshot caches to preserve evidentiary integrity." },
      { time: "T+60m", title: "Official Escalation", desc: "Establish secure connection to National Cyber Crime portal (cybercrime.gov.in) to flag rogue entities." }
    ],
    faq: [
      { q: "What should I do first if my system gets hacked?", a: "Immediately isolate the computer or smartphone by disabling Wi-Fi, Ethernet, and mobile networks. This prevents malware from spreading laterally or stealing data in real-time." },
      { q: "How do I escalate this to official authorities in India?", a: "Dial the National Cyber Crime Helpline at 1930 immediately, or submit a formal, secure complaint on the official National Cyber Crime Reporting Portal: https://cybercrime.gov.in" },
      { q: "Will CyberShield submit complaints for me automatically?", a: "No. This module is strictly educational. It guides you step-by-step to gather the correct evidence and safety checklists, which you must manually submit to official portals." }
    ],
    recommendations: [
      "Disconnect all external backup drives immediately to avoid secondary infection or ransomware encryption.",
      "Review connected device accounts in settings and log out of all active sessions globally.",
      "Never disclose OTP codes, recovery keys, or bank codes to callers claiming to represent security teams."
    ]
  },
  {
    id: "credential_leak",
    icon: "key-round",
    title: "Credential Leak Response",
    severity: "high",
    description: "Critical protocols to secure enterprise identities and revoke active session hijackers after database breaches or credentials exposure.",
    steps: [
      "Review HaveIBeenPwned or CyberShield leak logs to determine the compromised passwords and endpoints.",
      "Change the compromised password instantly across all linked domains using a high-entropy passphrase.",
      "Terminate all other active corporate sessions via your provider's security checkup page.",
      "Audit recovery coordinates (secondary email address, phone numbers, secret security questions).",
      "Deploy app-based multi-factor authentication (MFA) or secure physical security keys."
    ],
    checklists: {
      evidence: [
        "Document the specific breach source database name and estimated date of exposure.",
        "Save screenshots of data leak notifications or compromised account status indicators.",
        "List all corporate services and portals sharing the exact same credentials."
      ],
      password_reset: [
        "Create and save a new unique password utilizing random passphrase groupings.",
        "Ensure the new access credential is not repeated or derived from old leaked seeds."
      ],
      mfa: [
        "Activate App-Based TOTP authenticator tokens (such as Google Authenticator, Microsoft Authenticator, or Aegis).",
        "Generate and securely print a hardcopy of backup emergency bypass codes."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Exposure Detected", desc: "Breach announcement or threat monitor logs flag email credentials in an external database dump." },
      { time: "T+5m", title: "Passphrase Rotation", desc: "User triggers immediate password reset using isolated client nodes, establishing unique 16+ char codes." },
      { time: "T+10m", title: "Session Eviction", desc: "Enforce global logout, forcing all connected mobile endpoints, browser cookies, and API hooks to re-authenticate." },
      { time: "T+15m", title: "MFA Lockout", desc: "Enforce multi-factor verification on the identity domain, rendering the leaked password useless for intruders." }
    ],
    faq: [
      { q: "Is SMS-based verification secure enough?", a: "No. SMS verification is highly vulnerable to SIM-swap attacks, social engineering, and signal intercept. App-based MFA (e.g. Google Authenticator) is highly preferred." },
      { q: "What should I do if my recovery email is also compromised?", a: "Access the secondary recovery email provider's emergency recovery page immediately. Securing your primary email account is the top priority." }
    ],
    recommendations: [
      "Use a modern local encrypted password manager to maintain unique logins for every single platform.",
      "Never reuse master passwords on general forums, newsletters, or third-party web endpoints.",
      "Actively verify logins on Google, Microsoft, or Apple account security dashboard nodes periodically."
    ]
  },
  {
    id: "banking_fraud",
    icon: "credit-card",
    title: "Banking Fraud Guide",
    severity: "critical",
    description: "Urgent containment playbook to block compromised credit cards, freeze funds in UPI transit, and execute the Golden Hour liability protections.",
    steps: [
      "Contact your banking helpline instantly to freeze debit/credit cards and block netbanking access.",
      "Immediately dial 1930 (Indian National Cyber Crime Helpline) to trace and freeze stolen funds in transit.",
      "Collect transaction numbers, dates, times, recipient accounts, and transaction reference SMS logs.",
      "Change netbanking passwords, mobile bank PINs, and UPI access keys from an isolated device.",
      "Submit a written dispute form (chargeback request) at your bank branch within 24 hours."
    ],
    checklists: {
      evidence: [
        "Capture precise debit/credit transaction reference numbers from official SMS or email alerts.",
        "Download complete PDF bank statements highlight the fraudulent withdrawals.",
        "Screenshot fraudulent UPI request interfaces, WhatsApp chats, or payment links."
      ],
      password_reset: [
        "Reset UPI PINs, ATM PINs, and online bank portal passwords immediately.",
        "Clear browser autofill settings that store payment cards or netbanking credentials."
      ],
      mfa: [
        "Enforce strict daily transaction limits on credit cards and netbanking portals.",
        "Disable international transaction options and contactless (NFC) limits on payment cards."
      ],
      bank_contact: [
        "Obtained bank's official Dispute Ticket or Incident ID for formal reference.",
        "Submitted written claim explaining the unauthorized transaction under RBI 'zero-liability' rules."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Fraud Discovered", desc: "User receives unauthorized debit transaction alerts or UPI payment notification blocks." },
      { time: "T+10m", title: "Card Blocked", desc: "User uses the mobile app or blocks via IVR call, cutting off physical card lines from future charges." },
      { time: "T+20m", title: "Helpline 1930", desc: "User dials 1930 to alert Indian financial controllers. The funds can be locked in real-time if caught in intermediate wallets." },
      { time: "T+1h", title: "Dispute Submission", desc: "Drafting of dispute parameters to secure complete liability exemptions according to corporate banking charters." }
    ],
    faq: [
      { q: "What is the 'Golden Hour' in cyber banking fraud?", a: "The first 2 to 3 hours after a fraudulent transaction. Reporting to the bank and dialing 1930 within this window yields a high probability of stopping and reversing the funds in transit." },
      { q: "What are my legal rights under RBI regulations in India?", a: "If you report the unauthorized transaction within 3 days, your liability is ZERO. Reporting between 4 to 7 days caps your liability, while late reports are subject to bank policies." }
    ],
    recommendations: [
      "Turn off international transactions and keep online usage limits low when your cards are not actively in use.",
      "Never click links sent via SMS requesting OTP inputs for KYC verification, card upgrades, or lottery payouts.",
      "Always check for HTTPS and domain spelling before entering card details on checkout gateways."
    ]
  },
  {
    id: "social_media",
    icon: "message-square",
    title: "Social Media Recovery",
    severity: "high",
    description: "Step-by-step restoration guide for hacked WhatsApp, Instagram, LinkedIn, or Facebook accounts to reclaim control and prevent secondary scams.",
    steps: [
      "Access the platform's dedicated recovery portal (e.g., instagram.com/hacked, facebook.com/hacked).",
      "Re-verify your mobile number via official SMS OTP prompts to automatically evict existing sessions.",
      "Submit official ID verification or video selfie authorization to confirm profile identity.",
      "Warn friends, colleagues, and followers via separate channels that your profile has been hijacked.",
      "Audit and clean connected applications, rogue links, or profile descriptions set by the hacker."
    ],
    checklists: {
      evidence: [
        "Screenshot security alerts notifying that your registered email address or phone number has changed.",
        "Capture posts, comments, or spam messages published by the intruder from your profile.",
        "Identify specific links or phishing forms you interacted with prior to losing access."
      ],
      password_reset: [
        "Reset the linked email account's password first to ensure secure verification routing.",
        "Change the social profile's access passphrase to a strong, high-entropy unique combo."
      ],
      mfa: [
        "Setup 2FA inside WhatsApp or Instagram settings using a dynamic authenticator app.",
        "Record and save backup offline recovery codes in a secure vault."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Account Hijack", desc: "Attacker tricks user into giving up OTP or clicking phishing hooks, changing contact coordinates instantly." },
      { time: "T+5m", title: "Platform Escalation", desc: "User triggers official platform compromise forms, launching secure fallback identity verification loops." },
      { time: "T+15m", title: "Contact Alerts", desc: "User posts safety notices on secondary channels to warn followers and stop financial baiting campaigns." },
      { time: "T+24h", title: "Control Reclaimed", desc: "Platform inspects video logs or verification sheets and reinstates user access coordinates." }
    ],
    faq: [
      { q: "What should I do if my WhatsApp is hacked?", a: "Re-register WhatsApp on your phone by entering your phone number and verifying the 6-digit SMS code. This instantly logs out the attacker. If they enabled 2-step verification, you may have to wait 7 days to bypass it." },
      { q: "How do platforms verify my identity?", a: "Platforms use video selfies (analyzing facial structures against your uploaded photos) or request previous passwords and photo ID uploads to confirm ownership." }
    ],
    recommendations: [
      "Enable WhatsApp/Instagram 2-step verification PINs immediately. Never share these PIN codes with anyone.",
      "Review connected third-party apps regularly and remove permissions for any unknown software.",
      "Avoid clicking on shared links that claim you can win prizes, cast votes, or view private gossip."
    ]
  },
  {
    id: "email_recovery",
    icon: "mail",
    title: "Email Account Recovery",
    severity: "critical",
    description: "Reclaiming access to compromised Gmail or Outlook accounts which serve as the central gateway to your banking, social, and professional identities.",
    steps: [
      "Visit official email recovery hubs: google.com/accounts/recovery or account.live.com/acsr.",
      "Provide previously used passwords, trusted backup codes, or register SMS recovery coordinates.",
      "Once logged in, audit active mail-forwarding settings to ensure hackers are not copying incoming mails.",
      "Delete search filters or automated trash routing designed to conceal security warnings.",
      "Perform a full Google Security Checkup or Microsoft Security Audit to sever active threat links."
    ],
    checklists: {
      evidence: [
        "Take screenshot of notices that your password or recovery verification phone was modified.",
        "Document exact timestamps when you lost email sync on your mail clients.",
        "Capture foreign IP addresses or device models listed in the login security logs."
      ],
      password_reset: [
        "Reset your email master password to a 16+ character high-security random layout.",
        "Do not use words related to your nickname, birth year, or phone numbers."
      ],
      mfa: [
        "Set up Authenticator OTP verification on your mobile device.",
        "Revoke old app-passwords and disconnect secondary email OAuth grants."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Master Auth Loss", desc: "Email client returns authentication failure. Security coordinates show altered settings." },
      { time: "T+10m", title: "Recovery Triggered", desc: "Initiating recovery protocols using trusted browsers, historical IP networks, or verified recovery seeds." },
      { time: "T+30m", title: "Credential Isolation", desc: "Access regained. Immediately deleting rogue filters that auto-forward incoming bank OTP alerts." },
      { time: "T+45m", title: "Security Hardening", desc: "Updating multi-factor credentials, clearing cookies, and verifying recovery coordinates." }
    ],
    faq: [
      { q: "Why did the hacker create automatic email filters?", a: "Hackers configure rules to auto-archive, delete, or forward security alerts and bank messages. This prevents you from noticing unauthorized account actions." },
      { q: "What if the hacker changed all recovery options?", a: "Use the 'Try another way' link on the login page from a device or location you have frequently used in the past. Providers use historical network records to help verify ownership." }
    ],
    recommendations: [
      "Always write down and store your email recovery keys in a safe, physical, offline notebook.",
      "Never click password reset buttons on unsolicited notification emails.",
      "Regularly review your email's 'Forwarding and POP/IMAP' settings for unauthorized email addresses."
    ]
  },
  {
    id: "malware_emergency",
    icon: "bug",
    title: "Malware Emergency",
    severity: "critical",
    description: "Emergency containment and clean-up workflow when systems are compromised by active ransomware, keyloggers, or trojan spywares.",
    steps: [
      "Disconnect the infected device from all physical cables, Wi-Fi connections, and network environments.",
      "Do NOT power down completely if ransomware is running (to preserve RAM keys); instead, put host in sleep mode or disable networking.",
      "Boot the operating system in Safe Mode (with absolute networking features completely disabled).",
      "Run a comprehensive full disk scanner using Microsoft Safety Scanner or a trusted offline AV tool.",
      "If ransomware is active, capture screenshots of the ransom note and check NoMoreRansom.org for decryptors."
    ],
    checklists: {
      evidence: [
        "Photograph the ransom screen or error dialogs displaying the attacker's details.",
        "Record the exact extensions of encrypted files (e.g., .locked, .crypt) and document target file paths.",
        "Save screenshots of active background tasks or startup directories in Task Manager."
      ],
      password_reset: [
        "From an independent clean device, reset passwords for your banking, email, and master vaults.",
        "Never perform credentials updates from the infected host before a clean OS reload."
      ],
      mfa: [
        "Set up mandatory MFA on all accounts, forcing existing sessions on the malware-exposed device to expire."
      ],
      scan_device: [
        "Completed a boot-time scan or offline scanner execution to clear system registry malware.",
        "Verified host files (e.g., C:\\Windows\\System32\\drivers\\etc\\hosts) do not contain rogue redirects."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Malware Activation", desc: "System locks up, displays massive popups, files show unusual extensions, or CPU spikes to 100%." },
      { time: "T+2m", title: "Network Severance", desc: "Operative disconnects ethernet and disables router Wi-Fi, halting remote control and data exfiltration." },
      { time: "T+15m", title: "Safe Mode Boot", desc: "Booting the host into Safe Mode, preventing malware startup modules and registry items from mounting." },
      { time: "T+45m", title: "Offline AV Scan", desc: "Executing offline anti-malware binaries to parse, isolate, and safely delete trojans and active spy modules." }
    ],
    faq: [
      { q: "Should I pay the ransom in ransomware attacks?", a: "No! Paying ransom does not guarantee you will get your files back and directly funds cybercriminals. Free tools are often released on portals like nomoreransom.org." },
      { q: "Is a normal factory reset enough to clean spyware?", a: "Usually yes, a full factory reset with disk wipe is highly effective. For advanced infections, a clean OS installation from a verified USB boot drive is the gold standard." }
    ],
    recommendations: [
      "Maintain offline, disconnected cold backups of critical files. Ransomware will encrypt connected network backups.",
      "Keep Windows Defender or trusted AV active shields enabled. Never disable real-time protection to run cracked software.",
      "Enable 'Show File Extensions' in OS file explorer to avoid opening double extension malware like 'document.pdf.exe'."
    ]
  },
  {
    id: "phishing_report",
    icon: "fish",
    title: "Phishing Report",
    severity: "low",
    description: "Triage flow to inspect deceptive URLs, capture raw header artifacts, and report fraudulent domains to global and national anti-abuse repositories.",
    steps: [
      "Do NOT enter passwords, OTP codes, or personal identities on the suspicious web interface.",
      "Analyze the full domain spelling, check for secure SSL certificates, and inspect for subdomains.",
      "Screenshot the fake portal landing page and copy the exact URL string safely.",
      "Obtain raw email headers (.eml source) if the phishing hook arrived via your inbox.",
      "Submit the phishing domain details to APWG, Google Safe Browsing, and Indian authorities."
    ],
    checklists: {
      evidence: [
        "Copy the exact, unmodified phishing URL (use a clean text editor; do not click on it).",
        "Screenshot the deceptive landing page layout, including the browser's address bar.",
        "Save the raw source email file with full headers to document original sender IP nodes."
      ],
      password_reset: [
        "If you previously input passwords, change that credential on the legitimate portal immediately.",
        "Enable immediate global logouts on that service node to clear active hijacked sessions."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Link Opened", desc: "User clicks email or SMS link and realizes the portal demands active credentials or PIN codes on a strange URL." },
      { time: "T+2m", title: "Session Abort", desc: "User closes the page, avoids typing any details, and copies the domain name to local clipboard buffers." },
      { time: "T+5m", title: "Header Capture", desc: "Extraction of complete email header source files to discover true sender gateways and relays." },
      { time: "T+10m", title: "Abuse Escalation", desc: "Submitting details to cybercrime.gov.in and phishing reporting engines to blacklist the malicious domain." }
    ],
    faq: [
      { q: "What are homograph domain attacks?", a: "They use character alphabets that look identical to Latin letters (e.g., using Cyrillic 'о' instead of Latin 'o') to trick users into believing they are visiting real corporate sites." },
      { q: "I clicked the link but didn't enter data. Am I hacked?", a: "Usually no, simply loading the page is unlikely to compromise you unless your browser has severe unpatched vulnerabilities. Running a quick malware scan provides peace of mind." }
    ],
    recommendations: [
      "Verify unexpected delivery alerts, bank blocks, or account locks by logging in directly via the official app.",
      "Bookmark your critical online banking, email, and social portals and only access them using those bookmarks.",
      "Enable Google Safe Browsing features inside your web browsers to get automatic blocks on phishing portals."
    ]
  },
  {
    id: "mobile_security",
    icon: "tablet",
    title: "Mobile Security Help",
    severity: "high",
    description: "Mitigation playbooks against smartphone spyware, remote-access screen sharing tools, rogue configuration profiles, and SIM-swapping.",
    steps: [
      "Inspect network signal immediately. If network signal disappears without warning, call telecom operator to check SIM status.",
      "Scan and remove unrecognized remote access apps (such as AnyDesk, TeamViewer, or rogue screen-share utilities).",
      "Navigate to Android 'Device Admin Apps' or iOS 'VPN & Device Management' to delete unauthorized profiles.",
      "Revoke advanced device permissions like 'Accessibility Services' or 'Notification Access' for unknown apps.",
      "Uninstall all third-party apps loaded from sideloaded APK stores or untrusted third-party developers."
    ],
    checklists: {
      evidence: [
        "Take screenshots of unauthorized app installs, excessive popups, or unknown battery consumption logs.",
        "Save photos or document text messages containing anomalous registration codes or OTP requests."
      ],
      password_reset: [
        "Change credentials for critical apps (banking, email, social) using an independent secure workstation."
      ],
      mfa: [
        "Establish an on-device app lock or password PIN to prevent physical identity theft.",
        "Enable SIM PIN locks to block attackers from inserting your physical SIM card into other devices."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Anomalous Indicators", desc: "Device overheats, shows fast battery drain, has unexplained data usage, or network signal flatlines." },
      { time: "T+5m", title: "SIM-Swap Check", desc: "Dialing telecom carrier via secondary line to check if SIM reissue requests have been initialized." },
      { time: "T+15m", title: "Profile Auditing", desc: "Purging rogue iOS profiles or Android Device Admin apps to sever root control anchors." },
      { time: "T+30m", title: "Factory Hardening", desc: "Running deep mobile anti-malware checks or executing a full hardware factory master reset." }
    ],
    faq: [
      { q: "How does a SIM-swap attack work?", a: "Attackers trick your cellular provider into registering your phone number to a new SIM card they control. This routes all your OTP codes directly to the hacker's phone." },
      { q: "What does a rogue configuration profile do?", a: "On iPhones or Androids, enterprise profiles can route all your internet traffic through a rogue VPN, monitor screen content, and extract sensitive session tokens." }
    ],
    recommendations: [
      "Never sideload apps or click 'Allow install from unknown sources' inside your smartphone settings.",
      "Lock down accessibility permissions. Malicious apps use accessibility to read onscreen passwords.",
      "Keep phone operating system up to date. Security updates patch major spyware exploits like Pegasus."
    ]
  },
  {
    id: "device_security",
    icon: "monitor",
    title: "Device Security Checklist",
    severity: "medium",
    description: "Routine PC and Mac workstation hardening guide to verify host firewalls, update security patches, and prevent persistent malware infections.",
    steps: [
      "Check and install the latest cumulative operating system updates and security patches.",
      "Verify that your system's built-in firewall is fully enabled and active shields are monitoring.",
      "Audit browser extensions. Delete any plugins that demand broad access to read all website details.",
      "Disable Remote Desktop (RDP) protocols and uninstall remote assistance software (e.g. AnyDesk).",
      "Ensure local user accounts are configured as standard accounts rather than administrators for daily operations."
    ],
    checklists: {
      evidence: [
        "Document your current operating system version, firewall state, and browser release channel.",
        "Export a clean listing of all active startup tasks and installed software."
      ],
      password_reset: [
        "Enforce strict biometric security (Windows Hello / Touch ID) or robust local sign-in passphrases."
      ],
      mfa: [
        "Ensure your master password manager requires multi-factor authorization to open the local vault."
      ]
    },
    timeline: [
      { time: "Day 1", title: "Endpoint Hardening", desc: "Configure routine operating system update settings and turn on automatic software patch streams." },
      { time: "Day 2", title: "Access Revocation", desc: "Delete unattended remote tools, disable folder sharing protocols, and clear browser tracking cookies." },
      { time: "Day 3", title: "Real-time Verification", desc: "Configure active real-time scanner schedules and verify that USB device autorun permissions are disabled." }
    ],
    faq: [
      { q: "Is Windows Defender enough for home users?", a: "Yes. Windows Defender paired with modern cloud protection provides highly effective, lightweight protection that matches expensive paid software." },
      { q: "Why should my daily account not be an Administrator?", a: "If malware infects a standard user account, it lacks the administrative rights to install system-wide rootkits or disable security tools automatically." }
    ],
    recommendations: [
      "Set your web browsers to automatically clear cookies and transient caches when you close them.",
      "Enable BitLocker or FileVault disk encryption. This protects data if your laptop is physically stolen.",
      "Block USB AutoPlay permissions in settings to prevent malware from running when drives are plugged in."
    ]
  },
  {
    id: "emergency_response",
    icon: "activity",
    title: "Emergency Response Checklist",
    severity: "critical",
    description: "Unified master zero-trust containment protocol to run immediately during any cyber attack to minimize lateral damage and initiate secure recovery.",
    steps: [
      "Sever all local network connections immediately (pull LAN cords, disconnect router, disable cellular links).",
      "Rotate credentials for your master email account, corporate domain, and secure database hubs.",
      "Check with your financial institutions and UPI networks to block and freeze transit wallets.",
      "Verify backup data integrity. Ensure backup files are isolated, verified clean, and not compromised.",
      "File a detailed, secure report with law enforcement authorities via the 1930 Helpline or official portal."
    ],
    checklists: {
      evidence: [
        "Document dates, precise system times, target servers, and known files modified.",
        "Photograph all physical system displays showcasing ransomware notes or suspicious logs.",
        "Compile a secure archive of raw packet logs, active sessions, and anomalous login details."
      ],
      password_reset: [
        "Rotate master passwords across every key organizational portal using offline secure clients."
      ],
      mfa: [
        "Enforce a global MFA session reset, expiring existing active browser tokens across all accounts."
      ]
    },
    timeline: [
      { time: "T+0m", title: "Threat Isolation", desc: "Unplug, isolate, and sever network access vectors to stop lateral malware propagation or active exfiltration." },
      { time: "T+15m", title: "Identity Lock", desc: "Revoking active session cookies, rotating email passwords, and blocking linked banking profiles." },
      { time: "T+45m", title: "Artifact Collection", desc: "Exporting raw logs, preserving memory files, and taking photos of ransom screens to build evidence logs." },
      { time: "T+1h", title: "Regulatory Report", desc: "Direct filing on official government portals to activate security response frameworks and helpline networks." }
    ],
    faq: [
      { q: "Why is network isolation the absolute first step?", a: "It severs the connection between the threat actor and your system. It halts active data exfiltration and prevents ransomware from spreading to other PCs on the network." },
      { q: "How do I ensure my backup drives are safe?", a: "Always unplug backup drives as soon as backing up is complete. If left connected, ransomware will detect and encrypt backup drives along with your system." }
    ],
    recommendations: [
      "Execute simulated fire-drills to test containment speeds and verify backup restore capabilities periodically.",
      "Maintain a physical paper directory of emergency contacts (bank, IT, cyber helplines) in case system access is lost.",
      "Always verify that recovery backup files are completely isolated from active network domains."
    ]
  }
];

// 3. Wizard Progress and Checkbox Persistence States
let activePlaybookId = "report_incident";
let checklistStates = {}; // key: playbookId_checkboxId, value: boolean

// 4. Initialization Logic
function initEmergencyCenter() {
  renderPlaybookSidebar();
  loadPlaybook(activePlaybookId);

  // Expose public functions to window for onclick handlers
  window.selectPlaybook = function(playbookId) {
    activePlaybookId = playbookId;
    loadPlaybook(playbookId);
    renderPlaybookSidebar(); // Re-render to update active indicator
    
    // Add SOC recent activity log
    if (typeof window.addRecentActivity === 'function') {
      window.addRecentActivity('incident', `Analyzed Incident Playbook: ${playbookId.toUpperCase()}`);
    }
  };

  window.toggleEmergencyCheckbox = function(playbookId, checkboxId) {
    const key = `${playbookId}_${checkboxId}`;
    checklistStates[key] = !checklistStates[key];
    
    // Refresh the wizard UI to recalculate progress
    updateWizardProgress(playbookId);
    // Refresh the dynamic playbook content
    loadPlaybook(playbookId);
  };

  window.toggleEmergencyFAQ = function(playbookId, index) {
    const el = document.getElementById(`em-faq-${playbookId}-${index}`);
    if (el) {
      const isExpanded = el.classList.contains('expanded');
      // Collapse all FAQ items in the active playbook
      document.querySelectorAll('.emergency-faq-item').forEach(item => {
        item.classList.remove('expanded');
      });
      if (!isExpanded) {
        el.classList.add('expanded');
      }
    }
  };

  window.copyEmergencySteps = function(playbookId) {
    const playbook = PLAYBOOKS.find(p => p.id === playbookId);
    if (!playbook) return;

    let text = `CYBERSHIELD SECURE PLAYBOOK: ${playbook.title.toUpperCase()}\n`;
    text += `==================================================\n`;
    text += `Severity: ${playbook.severity.toUpperCase()}\n`;
    text += `Description: ${playbook.description}\n\n`;
    text += `IMMEDIATE RECOVERY STEPS:\n`;
    playbook.steps.forEach((step, idx) => {
      const isCompleted = checklistStates[`${playbookId}_step_${idx}`] ? "[COMPLETED]" : "[ ]";
      text += `${idx + 1}. ${isCompleted} ${step}\n`;
    });
    
    text += `\nEVIDENCE LOGGING CHECKLIST:\n`;
    playbook.checklists.evidence.forEach((item, idx) => {
      const isCompleted = checklistStates[`${playbookId}_ev_${idx}`] ? "[COMPLETED]" : "[ ]";
      text += `- ${isCompleted} ${item}\n`;
    });

    text += `\nOFFICIAL EMERGENCY CONTACTS (INDIA):\n`;
    text += `- Cyber Helpline: 1930 (Golden Hour response)\n`;
    text += `- National Cyber Crime Portal: https://cybercrime.gov.in\n`;
    text += `\nThis document is educational only. Restoring operations securely is the top priority.\n`;

    navigator.clipboard.writeText(text).then(() => {
      window.showNotification("Incident response instructions copied to clipboard!", "success");
    }).catch(() => {
      window.showNotification("Failed to copy. Manual copy from checklist is available.", "info");
    });
  };

  window.downloadEmergencyChecklistPDF = function(playbookId) {
    const playbook = PLAYBOOKS.find(p => p.id === playbookId);
    if (!playbook) return;

    // Generate beautiful self-contained HTML file formatted for printing to PDF
    let stepsHtml = "";
    playbook.steps.forEach((step, idx) => {
      const isChecked = checklistStates[`${playbookId}_step_${idx}`];
      stepsHtml += `
        <div class="pdf-item">
          <div class="pdf-box ${isChecked ? 'checked' : ''}"></div>
          <div>
            <strong>Step ${idx + 1}:</strong> ${step}
            <span class="pdf-status">${isChecked ? 'COMPLETED' : 'PENDING'}</span>
          </div>
        </div>
      `;
    });

    let evHtml = "";
    playbook.checklists.evidence.forEach((item, idx) => {
      const isChecked = checklistStates[`${playbookId}_ev_${idx}`];
      evHtml += `
        <div class="pdf-item">
          <div class="pdf-box ${isChecked ? 'checked' : ''}"></div>
          <div>${item} <span class="pdf-status">${isChecked ? 'SECURED' : 'UNCHECKED'}</span></div>
        </div>
      `;
    });

    let extraHtml = "";
    if (playbook.checklists.password_reset) {
      playbook.checklists.password_reset.forEach((item, idx) => {
        const isChecked = checklistStates[`${playbookId}_pwd_${idx}`];
        extraHtml += `
          <div class="pdf-item">
            <div class="pdf-box ${isChecked ? 'checked' : ''}"></div>
            <div>${item} <span class="pdf-status">${isChecked ? 'ROBUST' : 'UNCHECKED'}</span></div>
          </div>
        `;
      });
    }

    const htmlDoc = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>CyberShield Secure Incident Response Audit Sheet</title>
          <meta charset="utf-8">
          <style>
            @page {
              size: A4 portrait;
              margin: 20mm;
            }
            body {
              background: #fafafa;
              color: #1e293b;
              font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
              font-size: 13px;
              line-height: 1.5;
              margin: 0;
              padding: 0;
            }
            .header {
              border-bottom: 2px solid #e11d48;
              padding-bottom: 12px;
              margin-bottom: 20px;
              display: flex;
              justify-content: space-between;
              align-items: center;
            }
            .header h1 {
              margin: 0;
              font-size: 20px;
              color: #0f172a;
              font-weight: 800;
              letter-spacing: -0.5px;
            }
            .header .subtitle {
              margin: 4px 0 0 0;
              font-size: 11px;
              color: #64748b;
            }
            .meta-box {
              background: #f1f5f9;
              border: 1px solid #cbd5e1;
              border-radius: 6px;
              padding: 12px;
              margin-bottom: 20px;
              display: grid;
              grid-template-columns: 1fr 1fr;
              gap: 8px;
            }
            .meta-item {
              font-size: 11px;
            }
            .section-title {
              font-size: 12px;
              font-weight: 700;
              color: #0f172a;
              text-transform: uppercase;
              border-bottom: 1px solid #cbd5e1;
              padding-bottom: 4px;
              margin: 20px 0 10px 0;
            }
            .pdf-item {
              display: flex;
              gap: 12px;
              margin-bottom: 10px;
              align-items: start;
            }
            .pdf-box {
              width: 14px;
              height: 14px;
              border: 1.5px solid #475569;
              border-radius: 3px;
              flex-shrink: 0;
              margin-top: 2px;
            }
            .pdf-box.checked {
              background: #10b981;
              border-color: #10b981;
            }
            .pdf-status {
              font-size: 9px;
              font-weight: 700;
              padding: 1px 4px;
              border-radius: 3px;
              background: #e2e8f0;
              color: #475569;
              margin-left: 6px;
              text-transform: uppercase;
            }
            .alert-info-box {
              background: #fffbeb;
              border: 1px solid #fef08a;
              border-radius: 6px;
              padding: 12px;
              margin-top: 25px;
            }
            .alert-info-box h4 {
              margin: 0 0 6px 0;
              color: #b45309;
              font-size: 12px;
            }
            .alert-info-box p {
              margin: 0;
              font-size: 11px;
              color: #78350f;
              line-height: 1.4;
            }
            .footer {
              margin-top: 40px;
              border-top: 1px solid #cbd5e1;
              padding-top: 12px;
              font-size: 10px;
              color: #64748b;
              text-align: center;
            }
          </style>
        </head>
        <body>
          <div class="header">
            <div>
              <h1>CYBERSHIELD RESPONSE AUDIT LOG</h1>
              <p class="subtitle">Secure Incident Checklist & Forensic Abstractions</p>
            </div>
            <div style="text-align: right;">
              <span style="font-weight:700; color: #e11d48;">SEVERITY: ${playbook.severity.toUpperCase()}</span>
            </div>
          </div>

          <div class="meta-box">
            <div class="meta-item"><strong>Incident Category:</strong> ${playbook.title}</div>
            <div class="meta-item"><strong>Compiled Timestamp:</strong> ${new Date().toLocaleString()}</div>
            <div class="meta-item"><strong>System Authority:</strong> CyberShield secure sandbox module</div>
            <div class="meta-item"><strong>Audit Verification ID:</strong> CS-IR-${playbook.id.toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}</div>
          </div>

          <p style="font-size:11.5px; color:#475569;">
            This file logs the exact recovery steps taken and forensic evidence preserved in response to the security incident. Save or print this checklist as a PDF to provide to local authorities, enterprise insurance grids, or the SOC operations chief.
          </p>

          <div class="section-title">Step-by-Step Response Logs</div>
          ${stepsHtml}

          <div class="section-title">Evidence & Indicator Checklist</div>
          ${evHtml}

          ${extraHtml ? '<div class="section-title">Credentials Reset Checklist</div>' + extraHtml : ''}

          <div class="alert-info-box">
            <h4>Official Indian Cybersecurity Escalation Gateways</h4>
            <p>
              In accordance with local cyber legislation, online monetary thefts and identity hijackings can be filed directly with authorities.
              Contact the <strong>National Cyber Crime Helpline: 1930</strong> (available 24/7) or log on securely to <strong>https://cybercrime.gov.in</strong> to submit evidence logs.
            </p>
          </div>

          <div class="footer">
            CyberShield SECURE-CORE IR Platform • System Diagnostic Version: v4.2.0 • For Educational & Advisory Use Only
          </div>
          
          <script>
            window.onload = function() {
              window.print();
            };
          <\/script>
        </body>
      </html>
    `;

    const blob = new Blob([htmlDoc], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberShield_Emergency_Report_${playbook.id}_${Date.now()}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    window.showNotification("Audit report exported as HTML/PDF. Click 'Save to PDF' in your print dialog.", "success");
  };

  // Attach quick nav buttons
  window.cyclePlaybook = function(direction) {
    const currentIndex = PLAYBOOKS.findIndex(p => p.id === activePlaybookId);
    let nextIndex = currentIndex + direction;
    if (nextIndex < 0) nextIndex = PLAYBOOKS.length - 1;
    if (nextIndex >= PLAYBOOKS.length) nextIndex = 0;
    
    window.selectPlaybook(PLAYBOOKS[nextIndex].id);
  };
}

// 5. Render Playbook Navigation List (Sidebar)
function renderPlaybookSidebar() {
  const container = document.getElementById('emergency-menu-list');
  if (!container) return;

  container.innerHTML = PLAYBOOKS.map(p => {
    const isActive = p.id === activePlaybookId;
    
    // Check total progress of checkboxes
    let totalCheckboxes = p.steps.length + p.checklists.evidence.length;
    if (p.checklists.password_reset) totalCheckboxes += p.checklists.password_reset.length;
    if (p.checklists.mfa) totalCheckboxes += p.checklists.mfa.length;
    if (p.checklists.scan_device) totalCheckboxes += p.checklists.scan_device.length;
    if (p.checklists.bank_contact) totalCheckboxes += p.checklists.bank_contact.length;

    let checkedCount = 0;
    p.steps.forEach((_, idx) => { if (checklistStates[`${p.id}_step_${idx}`]) checkedCount++; });
    p.checklists.evidence.forEach((_, idx) => { if (checklistStates[`${p.id}_ev_${idx}`]) checkedCount++; });
    if (p.checklists.password_reset) {
      p.checklists.password_reset.forEach((_, idx) => { if (checklistStates[`${p.id}_pwd_${idx}`]) checkedCount++; });
    }
    if (p.checklists.mfa) {
      p.checklists.mfa.forEach((_, idx) => { if (checklistStates[`${p.id}_mfa_${idx}`]) checkedCount++; });
    }
    if (p.checklists.scan_device) {
      p.checklists.scan_device.forEach((_, idx) => { if (checklistStates[`${p.id}_scan_${idx}`]) checkedCount++; });
    }
    if (p.checklists.bank_contact) {
      p.checklists.bank_contact.forEach((_, idx) => { if (checklistStates[`${p.id}_bank_${idx}`]) checkedCount++; });
    }

    const progressPercent = Math.round((checkedCount / totalCheckboxes) * 100) || 0;
    const progressLabel = progressPercent > 0 ? `<span style="font-size:10px; color:var(--emerald-bright); font-family:var(--font-mono); font-weight:bold; margin-left:8px;">${progressPercent}%</span>` : "";

    return `
      <button class="emergency-menu-item ${isActive ? 'active' : ''}" onclick="selectPlaybook('${p.id}')">
        <span class="menu-icon">
          <i data-lucide="${p.icon}"></i>
        </span>
        <div style="display:flex; flex-direction:column; gap:2px; flex-grow:1;">
          <span style="font-size:12.5px; font-weight:600;">${p.title}</span>
          <div style="display:flex; align-items:center; gap:6px;">
            <span class="sev-badge sev-${p.severity}">${p.severity}</span>
            ${progressLabel}
          </div>
        </div>
      </button>
    `;
  }).join('');

  if (window.lucide) window.lucide.createIcons();
}

// 6. Load a Playbook into the Wizard content container
function loadPlaybook(playbookId) {
  const container = document.getElementById('playbook-wizard-content');
  const playbook = PLAYBOOKS.find(p => p.id === playbookId);
  if (!container || !playbook) return;

  // Build the Wizard UI
  // Step-by-Step checklist render
  const stepsHtml = playbook.steps.map((step, idx) => {
    const isChecked = checklistStates[`${playbookId}_step_${idx}`] || false;
    return `
      <div class="step-checkbox-wrapper ${isChecked ? 'completed' : ''}" style="display:flex; gap:16px; align-items:start;">
        <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'step_${idx}')">
          ${isChecked ? '<i data-lucide="check"></i>' : ''}
        </div>
        <div style="flex-grow:1;">
          <h5 style="margin:0 0 4px 0; font-size:13.5px; font-weight:600; color:${isChecked ? 'var(--emerald-bright)' : '#fff'};">Action Point ${idx + 1}</h5>
          <p style="margin:0; font-size:12.5px; color:${isChecked ? 'var(--text-secondary)' : 'var(--text-primary)'}; line-height:1.5;">${step}</p>
        </div>
      </div>
    `;
  }).join('');

  // Evidence Checklist render
  const evidenceHtml = playbook.checklists.evidence.map((item, idx) => {
    const isChecked = checklistStates[`${playbookId}_ev_${idx}`] || false;
    return `
      <div style="display:flex; gap:10px; align-items:center;">
        <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'ev_${idx}')">
          ${isChecked ? '<i data-lucide="check"></i>' : ''}
        </div>
        <span style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">${item}</span>
      </div>
    `;
  }).join('');

  // Password reset Checklist (Optional)
  let passwordResetHtml = "";
  if (playbook.checklists.password_reset) {
    const inner = playbook.checklists.password_reset.map((item, idx) => {
      const isChecked = checklistStates[`${playbookId}_pwd_${idx}`] || false;
      return `
        <div style="display:flex; gap:10px; align-items:center;">
          <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'pwd_${idx}')">
            ${isChecked ? '<i data-lucide="check"></i>' : ''}
          </div>
          <span style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">${item}</span>
        </div>
      `;
    }).join('');
    passwordResetHtml = `
      <div style="display:flex; flex-direction:column; gap:12px; margin-top:20px;">
        <h4 style="font-size:12px; color:var(--cyan-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
          <i data-lucide="key-round" style="width:14px; height:14px;"></i> Password Security Node
        </h4>
        <div style="display:flex; flex-direction:column; gap:8px; background:rgba(6,182,212,0.02); padding:12px; border:1px solid rgba(6,182,212,0.1); border-radius:6px;">
          ${inner}
        </div>
      </div>
    `;
  }

  // MFA Checklist (Optional)
  let mfaHtml = "";
  if (playbook.checklists.mfa) {
    const inner = playbook.checklists.mfa.map((item, idx) => {
      const isChecked = checklistStates[`${playbookId}_mfa_${idx}`] || false;
      return `
        <div style="display:flex; gap:10px; align-items:center;">
          <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'mfa_${idx}')">
            ${isChecked ? '<i data-lucide="check"></i>' : ''}
          </div>
          <span style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">${item}</span>
        </div>
      `;
    }).join('');
    mfaHtml = `
      <div style="display:flex; flex-direction:column; gap:12px; margin-top:20px;">
        <h4 style="font-size:12px; color:var(--emerald-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
          <i data-lucide="shield-check" style="width:14px; height:14px;"></i> Enable Multi-Factor Authentication (MFA)
        </h4>
        <div style="display:flex; flex-direction:column; gap:8px; background:rgba(16,185,129,0.02); padding:12px; border:1px solid rgba(16,185,129,0.1); border-radius:6px;">
          ${inner}
        </div>
      </div>
    `;
  }

  // Scan Device Reminder (Optional)
  let scanDeviceHtml = "";
  if (playbook.checklists.scan_device) {
    const inner = playbook.checklists.scan_device.map((item, idx) => {
      const isChecked = checklistStates[`${playbookId}_scan_${idx}`] || false;
      return `
        <div style="display:flex; gap:10px; align-items:center;">
          <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'scan_${idx}')">
            ${isChecked ? '<i data-lucide="check"></i>' : ''}
          </div>
          <span style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">${item}</span>
        </div>
      `;
    }).join('');
    scanDeviceHtml = `
      <div style="display:flex; flex-direction:column; gap:12px; margin-top:20px;">
        <h4 style="font-size:12px; color:var(--amber-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
          <i data-lucide="cpu" style="width:14px; height:14px;"></i> Scan Device Security Reminder
        </h4>
        <div style="display:flex; flex-direction:column; gap:8px; background:rgba(245,158,11,0.02); padding:12px; border:1px solid rgba(245,158,11,0.1); border-radius:6px;">
          ${inner}
        </div>
      </div>
    `;
  }

  // Bank Contact Reminder (Optional)
  let bankContactHtml = "";
  if (playbook.checklists.bank_contact) {
    const inner = playbook.checklists.bank_contact.map((item, idx) => {
      const isChecked = checklistStates[`${playbookId}_bank_${idx}`] || false;
      return `
        <div style="display:flex; gap:10px; align-items:center;">
          <div class="custom-emergency-checkbox ${isChecked ? 'checked' : ''}" onclick="toggleEmergencyCheckbox('${playbookId}', 'bank_${idx}')">
            ${isChecked ? '<i data-lucide="check"></i>' : ''}
          </div>
          <span style="font-size:12.5px; color:var(--text-secondary); line-height:1.4;">${item}</span>
        </div>
      `;
    }).join('');
    bankContactHtml = `
      <div style="display:flex; flex-direction:column; gap:12px; margin-top:20px;">
        <h4 style="font-size:12px; color:var(--rose-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
          <i data-lucide="phone-call" style="width:14px; height:14px;"></i> Urgent Banking Institution Action
        </h4>
        <div style="display:flex; flex-direction:column; gap:8px; background:rgba(244,63,94,0.02); padding:12px; border:1px solid rgba(244,63,94,0.1); border-radius:6px;">
          ${inner}
        </div>
      </div>
    `;
  }

  // Timeline render
  const timelineHtml = playbook.timeline.map((node) => `
    <div class="soc-timeline-node">
      <div class="soc-timeline-dot"></div>
      <div class="soc-timeline-time">${node.time}</div>
      <div style="font-size:13px; font-weight:600; color:#fff; margin-bottom:2px;">${node.title}</div>
      <div style="font-size:12px; color:var(--text-secondary); line-height:1.4;">${node.desc}</div>
    </div>
  `).join('');

  // FAQ render
  const faqHtml = playbook.faq.map((item, idx) => `
    <div class="emergency-faq-item" id="em-faq-${playbookId}-${idx}">
      <div class="emergency-faq-header" onclick="toggleEmergencyFAQ('${playbookId}', ${idx})">
        <span>${item.q}</span>
        <i data-lucide="chevron-down"></i>
      </div>
      <div class="emergency-faq-body">
        ${item.a}
      </div>
    </div>
  `).join('');

  // Safety Recommendations render
  const recsHtml = playbook.recommendations.map((rec) => `
    <li style="font-size:12.5px; color:var(--text-secondary); line-height:1.5; margin-bottom:6px;">
      ${rec}
    </li>
  `).join('');

  // Calculate Progress Percent
  let totalCheckboxes = playbook.steps.length + playbook.checklists.evidence.length;
  if (playbook.checklists.password_reset) totalCheckboxes += playbook.checklists.password_reset.length;
  if (playbook.checklists.mfa) totalCheckboxes += playbook.checklists.mfa.length;
  if (playbook.checklists.scan_device) totalCheckboxes += playbook.checklists.scan_device.length;
  if (playbook.checklists.bank_contact) totalCheckboxes += playbook.checklists.bank_contact.length;

  let checkedCount = 0;
  playbook.steps.forEach((_, idx) => { if (checklistStates[`${playbookId}_step_${idx}`]) checkedCount++; });
  playbook.checklists.evidence.forEach((_, idx) => { if (checklistStates[`${playbookId}_ev_${idx}`]) checkedCount++; });
  if (playbook.checklists.password_reset) {
    playbook.checklists.password_reset.forEach((_, idx) => { if (checklistStates[`${playbookId}_pwd_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.mfa) {
    playbook.checklists.mfa.forEach((_, idx) => { if (checklistStates[`${playbookId}_mfa_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.scan_device) {
    playbook.checklists.scan_device.forEach((_, idx) => { if (checklistStates[`${playbookId}_scan_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.bank_contact) {
    playbook.checklists.bank_contact.forEach((_, idx) => { if (checklistStates[`${playbookId}_bank_${idx}`]) checkedCount++; });
  }

  const progressPercent = Math.round((checkedCount / totalCheckboxes) * 100) || 0;

  // Insert the full HTML
  container.innerHTML = `
    <!-- Playbook Title Header -->
    <div style="display:flex; align-items:start; justify-content:space-between; border-bottom:1px solid rgba(255,255,255,0.05); padding-bottom:16px; margin-bottom:20px; flex-wrap:wrap; gap:12px;">
      <div>
        <div style="display:flex; align-items:center; gap:10px;">
          <h2 style="font-size:20px; font-weight:800; color:#fff; font-family:var(--font-display); letter-spacing:-0.5px; margin:0;">${playbook.title.toUpperCase()}</h2>
          <span class="sev-badge sev-${playbook.severity}">${playbook.severity}</span>
        </div>
        <p style="margin:6px 0 0 0; font-size:13px; color:var(--text-secondary); line-height:1.5; max-width:680px;">${playbook.description}</p>
      </div>
      
      <!-- Copy and PDF actions -->
      <div style="display:flex; gap:10px;">
        <button class="btn-secondary" style="font-size:11.5px; padding:6px 12px;" onclick="copyEmergencySteps('${playbookId}')">
          <i data-lucide="copy" style="width:14px; height:14px;"></i> Copy Steps
        </button>
        <button class="btn-primary" style="font-size:11.5px; padding:6px 12px; background:rgba(225,29,72,0.1); border-color:var(--rose-dark); color:var(--rose-bright);" onclick="downloadEmergencyChecklistPDF('${playbookId}')">
          <i data-lucide="download" style="width:14px; height:14px; color:var(--rose-bright);"></i> Export Audit PDF
        </button>
      </div>
    </div>

    <!-- Progress Indicator Bar -->
    <div style="margin-bottom:24px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
        <span style="font-size:12px; font-family:var(--font-mono); color:var(--text-secondary);">CONTAINMENT PROTOCOL PROGRESS:</span>
        <span style="font-size:13px; font-family:var(--font-mono); color:var(--emerald-bright); font-weight:700;">${progressPercent}% (${checkedCount}/${totalCheckboxes} Checkpoints Completed)</span>
      </div>
      <div class="wizard-progress-bar-outer">
        <div class="wizard-progress-bar-inner" style="width: ${progressPercent}%;"></div>
      </div>
    </div>

    <!-- Split content layout: Left wizard checks, Right secondary logs -->
    <div style="display:grid; grid-template-columns: 1.1fr 1fr; gap:24px; flex-grow:1;" id="wizard-split-arena">
      <!-- Left pane: Playbook Stepper -->
      <div style="display:flex; flex-direction:column; gap:12px;">
        <h4 style="font-size:12px; color:var(--rose-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px; margin-bottom:4px;">
          <i data-lucide="alert-triangle" style="width:14px; height:14px;"></i> Interactive Containment Steps
        </h4>
        <div style="display:flex; flex-direction:column; gap:10px;">
          ${stepsHtml}
        </div>
        
        <!-- Safety Notices -->
        <div style="margin-top:20px; padding:12px; border:1px dashed rgba(244,63,94,0.2); background:rgba(244,63,94,0.02); border-radius:6px;">
          <h5 style="margin:0 0 4px 0; font-size:12.5px; font-weight:700; color:var(--rose-bright); display:flex; align-items:center; gap:6px;">
            <i data-lucide="info" style="width:14px; height:14px;"></i> EDUCATIONAL DISCLAIMER NOTICE
          </h5>
          <p style="margin:0; font-size:11.5px; color:var(--text-secondary); line-height:1.4;">
            This module is designed for cybersecurity awareness training. CyberShield will never collect password texts, financial pin numbers, or credentials. Report active incidents manually to official portals like <strong>cybercrime.gov.in</strong>.
          </p>
        </div>
      </div>

      <!-- Right pane: Evidence Checklists & Timelines -->
      <div style="display:flex; flex-direction:column; gap:16px;">
        <!-- Evidence and Indicators checklist -->
        <div style="display:flex; flex-direction:column; gap:12px;">
          <h4 style="font-size:12px; color:var(--cyan-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
            <i data-lucide="shield" style="width:14px; height:14px;"></i> Evidence & Forensic Gathering
          </h4>
          <div style="display:flex; flex-direction:column; gap:8px; background:rgba(255,255,255,0.02); padding:12px; border:1px solid rgba(255,255,255,0.04); border-radius:6px;">
            ${evidenceHtml}
          </div>
        </div>

        <!-- Extra specific checklists dynamically injected -->
        ${passwordResetHtml}
        ${mfaHtml}
        ${scanDeviceHtml}
        ${bankContactHtml}

        <!-- Interactive Chronological Incident Containment Timeline -->
        <div style="display:flex; flex-direction:column; gap:12px; margin-top:8px;">
          <h4 style="font-size:12px; color:var(--text-primary); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
            <i data-lucide="history" style="width:14px; height:14px;"></i> Standard Incident Containment Timeline
          </h4>
          <div class="soc-timeline-container">
            ${timelineHtml}
          </div>
        </div>

        <!-- Long-term Safety Recommendations -->
        <div style="display:flex; flex-direction:column; gap:10px; border-top:1px solid rgba(255,255,255,0.05); padding-top:16px; margin-top:8px;">
          <h4 style="font-size:12px; color:var(--emerald-bright); font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
            <i data-lucide="check-circle" style="width:14px; height:14px;"></i> Long-term Safety Recommendations
          </h4>
          <ul style="margin:0; padding-left:16px;">
            ${recsHtml}
          </ul>
        </div>

        <!-- Collapsible FAQs -->
        <div style="display:flex; flex-direction:column; gap:10px; border-top:1px solid rgba(255,255,255,0.05); padding-top:16px; margin-top:8px;">
          <h4 style="font-size:12px; color:#fff; font-family:var(--font-mono); text-transform:uppercase; letter-spacing:0.5px; display:flex; align-items:center; gap:6px;">
            <i data-lucide="help-circle" style="width:14px; height:14px;"></i> Playbook FAQ
          </h4>
          <div style="display:flex; flex-direction:column; gap:4px;">
            ${faqHtml}
          </div>
        </div>
      </div>
    </div>

    <!-- Quick navigation footer buttons -->
    <div style="display:flex; justify-content:space-between; align-items:center; padding-top:20px; border-top:1px solid rgba(255,255,255,0.05); margin-top:24px;">
      <button class="btn-secondary" style="font-size:12px;" onclick="cyclePlaybook(-1)">
        <i data-lucide="arrow-left" style="width:14px; height:14px; margin-right:4px;"></i> Previous Playbook
      </button>
      <button class="btn-secondary" style="font-size:12px;" onclick="cyclePlaybook(1)">
        Next Playbook <i data-lucide="arrow-right" style="width:14px; height:14px; margin-left:4px;"></i>
      </button>
    </div>
  `;

  if (window.lucide) window.lucide.createIcons();
}

// 7. Recalculate and render progress in sidebar and wizard
function updateWizardProgress(playbookId) {
  renderPlaybookSidebar();
  
  // Re-save specific state values if needed
  const playbook = PLAYBOOKS.find(p => p.id === playbookId);
  if (!playbook) return;

  let totalCheckboxes = playbook.steps.length + playbook.checklists.evidence.length;
  if (playbook.checklists.password_reset) totalCheckboxes += playbook.checklists.password_reset.length;
  if (playbook.checklists.mfa) totalCheckboxes += playbook.checklists.mfa.length;
  if (playbook.checklists.scan_device) totalCheckboxes += playbook.checklists.scan_device.length;
  if (playbook.checklists.bank_contact) totalCheckboxes += playbook.checklists.bank_contact.length;

  let checkedCount = 0;
  playbook.steps.forEach((_, idx) => { if (checklistStates[`${playbookId}_step_${idx}`]) checkedCount++; });
  playbook.checklists.evidence.forEach((_, idx) => { if (checklistStates[`${playbookId}_ev_${idx}`]) checkedCount++; });
  if (playbook.checklists.password_reset) {
    playbook.checklists.password_reset.forEach((_, idx) => { if (checklistStates[`${playbookId}_pwd_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.mfa) {
    playbook.checklists.mfa.forEach((_, idx) => { if (checklistStates[`${playbookId}_mfa_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.scan_device) {
    playbook.checklists.scan_device.forEach((_, idx) => { if (checklistStates[`${playbookId}_scan_${idx}`]) checkedCount++; });
  }
  if (playbook.checklists.bank_contact) {
    playbook.checklists.bank_contact.forEach((_, idx) => { if (checklistStates[`${playbookId}_bank_${idx}`]) checkedCount++; });
  }

  const progressPercent = Math.round((checkedCount / totalCheckboxes) * 100) || 0;
  
  // Quick dynamic updates to active wizard elements without full rebuild
  const bar = document.querySelector('.wizard-progress-bar-inner');
  if (bar) bar.style.width = `${progressPercent}%`;

  const txt = document.querySelector('span[style*="emerald-bright"]');
  if (txt) txt.textContent = `${progressPercent}% (${checkedCount}/${totalCheckboxes} Checkpoints Completed)`;
}

// 8. Execute on Module Load
initEmergencyCenter();
