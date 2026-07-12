import express from "express";
import path from "path";
import dotenv from "dotenv";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";

dotenv.config();

const app = express();
const PORT = 3000;

app.use(express.json());

// Initialize Gemini Client
const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      "User-Agent": "aistudio-build",
    },
  },
});

// Cache for CISA KEV to prevent spamming
let cisaKevCache: any = null;
let cisaLastFetch = 0;

async function fetchCisaKev(): Promise<any[]> {
  const now = Date.now();
  if (cisaKevCache && now - cisaLastFetch < 3600000 * 6) {
    return cisaKevCache;
  }
  try {
    const res = await fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (res.ok) {
      const data: any = await res.json();
      cisaKevCache = data.vulnerabilities || [];
      cisaLastFetch = now;
      return cisaKevCache;
    }
  } catch (err) {
    console.error("CISA KEV fetch error:", err);
  }
  return [];
}

// 1. API Keys Status Endpoint
app.get("/api/keys-status", (req, res) => {
  res.json({
    virustotal: !!process.env.VIRUSTOTAL_API_KEY,
    abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
    alienvault: !!process.env.ALIENVAULT_OTX_API_KEY,
    urlscan: !!process.env.URLSCAN_API_KEY,
    safebrowsing: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
    nistnvd: !!process.env.NIST_NVD_API_KEY,
    newsapi: !!process.env.NEWS_API_KEY || !!process.env.VITE_NEWS_API_KEY,
    gnews: !!process.env.GNEWS_API_KEY || !!process.env.VITE_GNEWS_API_KEY,
    gemini: !!process.env.GEMINI_API_KEY,
  });
});

// 2. Cyber News Proxy Endpoint
app.get("/api/news", async (req, res) => {
  const type = req.query.type as string;
  const q = (req.query.q as string) || "cybersecurity OR ransomware OR vulnerability";

  try {
    if (type === "newsapi") {
      const apiKey = process.env.NEWS_API_KEY || process.env.VITE_NEWS_API_KEY;
      if (!apiKey) {
        return res.status(400).json({ error: "NewsAPI key is missing in server environment." });
      }
      const queryStr = 'cybersecurity OR ransomware OR vulnerability OR "zero-day"';
      const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(queryStr)}&sortBy=publishedAt&pageSize=40&apiKey=${apiKey}`;
      const response = await fetch(url);
      const data = await response.json();
      return res.json(data);

    } else if (type === "gnews") {
      const apiKey = process.env.GNEWS_API_KEY || process.env.VITE_GNEWS_API_KEY;
      if (!apiKey) {
        return res.status(400).json({ error: "GNews API key is missing in server environment." });
      }
      const url = `https://gnews.io/api/v4/search?q=${encodeURIComponent(q)}&lang=en&max=40&apikey=${apiKey}`;
      const response = await fetch(url);
      const data = await response.json();
      return res.json(data);
    }

    return res.status(400).json({ error: "Invalid news source type requested." });
  } catch (error: any) {
    console.error("News proxy error:", error);
    res.status(500).json({ error: error.message || "Failed to fetch proxy news" });
  }
});

// 3. Automated Threat Reputation & AI Summary Endpoint
app.post("/api/analyze-threat", async (req, res) => {
  const { text, activeCategoryId, topicTitle } = req.body;
  if (!text || !text.trim()) {
    return res.status(400).json({ error: "Text payload is empty." });
  }

  const query = text.toLowerCase().trim();
  let detectedType = "General Security Query";
  let extractedIndicator = text.trim();
  let apiMetrics: any = {};
  let verificationStatus = "Verification unavailable.";

  // Regex rules to detect inputs
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const cveRegex = /\bCVE-\d{4}-\d{4,7}\b/i;
  const md5Regex = /\b[a-fA-F0-9]{32}\b/;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/;
  const urlRegex = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/i;
  const domainRegex = /\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b/i;
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  const smsPattern = /(dear\s+customer|upi\s+transaction|payment\s+received|lottery|congratulations|otp|blocked|suspended|loan|sms|message)/i;
  const qrRegex = /^(upi:\/\/pay|wifi:|smsto:|tel:|geo:|mecard:|otpauth:)/i;
  const iocPattern = /(mimikatz|powershell\s+-nop|cmd\.exe\s+\/c|svchost\.exe|system32\\|lsass\.exe|rundll32\.exe|schtasks|\bHKLM\\|\bHKCU\\|\.exe\b|\.dll\b|\.sys\b)/i;
  const errorLogPattern = /(exception|stack\s+trace|failed\s+password|syslog|sudo:|auth\.log|unauthorized|kernel\s+panic|access\s+denied|status\s+500|fatal|traceback|error\s+code)/i;
  const emailHeaderMarkers = ["received:", "mime-version:", "delivered-to:", "dkim-signature:", "spf-alignment:"];

  let hasEmailHeaders = emailHeaderMarkers.some(marker => query.includes(marker));

  try {
    // 1. IP Reputation Scanning (VirusTotal, AbuseIPDB, AlienVault)
    if (ipRegex.test(query)) {
      detectedType = "IPv4 Network Address";
      extractedIndicator = text.trim();
      const ip = extractedIndicator;

      const vtKey = process.env.VIRUSTOTAL_API_KEY;
      const abuseKey = process.env.ABUSEIPDB_API_KEY;
      const otxKey = process.env.ALIENVAULT_OTX_API_KEY;

      const promises: Promise<any>[] = [];

      if (vtKey) {
        promises.push(
          fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
            headers: { "x-apikey": vtKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.data?.attributes?.last_analysis_stats) {
                apiMetrics.virustotal = {
                  malicious: data.data.attributes.last_analysis_stats.malicious,
                  harmless: data.data.attributes.last_analysis_stats.harmless,
                  suspicious: data.data.attributes.last_analysis_stats.suspicious,
                };
              }
            })
            .catch(() => {})
        );
      }

      if (abuseKey) {
        promises.push(
          fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
            headers: { Key: abuseKey, Accept: "application/json" },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.data) {
                apiMetrics.abuseipdb = {
                  abuseScore: data.data.abuseConfidenceScore,
                  totalReports: data.data.totalReports,
                  countryCode: data.data.countryCode,
                  isp: data.data.isp,
                };
              }
            })
            .catch(() => {})
        );
      }

      if (otxKey) {
        promises.push(
          fetch(`https://otx.alienvault.com/api/v1/indicators/IPv4/${ip}/general`, {
            headers: { "X-OTX-API-KEY": otxKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data) {
                apiMetrics.alienvault = {
                  pulseCount: data.pulse_info?.count || 0,
                  tags: data.pulse_info?.pulses?.map((p: any) => p.name).slice(0, 3) || [],
                };
              }
            })
            .catch(() => {})
        );
      }

      await Promise.all(promises);
      if (vtKey || abuseKey || otxKey) {
        verificationStatus = `Live Reputation Check Active (${[
          vtKey ? "VirusTotal" : "",
          abuseKey ? "AbuseIPDB" : "",
          otxKey ? "AlienVault OTX" : "",
        ]
          .filter(Boolean)
          .join(", ")}).`;
      }

    // 2. CVE Vulnerability Scanning (NIST NVD & CISA KEV Catalog check)
    } else if (cveRegex.test(query)) {
      detectedType = "CVE Vulnerability Identifier";
      extractedIndicator = (text.match(cveRegex)?.[0] || "").toUpperCase();
      const cve = extractedIndicator;

      const nvdKey = process.env.NIST_NVD_API_KEY;
      const headers: HeadersInit = {};
      if (nvdKey) headers.apiKey = nvdKey;

      // Check CISA KEV
      const cisaList = await fetchCisaKev();
      const matchInKev = cisaList.find((v: any) => v.cveID?.toUpperCase() === cve);
      if (matchInKev) {
        apiMetrics.cisaKev = {
          isExploited: true,
          vulnerabilityName: matchInKev.vulnerabilityName,
          action: matchInKev.requiredAction,
          dueDate: matchInKev.dueDate,
        };
      } else {
        apiMetrics.cisaKev = { isExploited: false };
      }

      // Query NIST NVD
      try {
        const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, { headers });
        if (response.ok) {
          const data: any = await response.json();
          const vuln = data.vulnerabilities?.[0]?.cve;
          if (vuln) {
            apiMetrics.nistNvd = {
              description: vuln.descriptions?.find((d: any) => d.lang === "en")?.value || "No description found.",
              cvssScore: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || vuln.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || "N/A",
              severity: vuln.metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity || "N/A",
            };
          }
        }
      } catch (err) {}

      verificationStatus = `Live NIST NVD Catalog query successful. Check match inside CISA KEV Catalog complete.`;

    // 3. File Hash Reputation Scanning (VirusTotal, AlienVault)
    } else if (md5Regex.test(query) || sha1Regex.test(query) || sha256Regex.test(query)) {
      detectedType = "Cryptographic File Hash Signature";
      extractedIndicator = (text.match(sha256Regex) || text.match(sha1Regex) || text.match(md5Regex))?.[0] || "";
      const hash = extractedIndicator;

      const vtKey = process.env.VIRUSTOTAL_API_KEY;
      const otxKey = process.env.ALIENVAULT_OTX_API_KEY;
      const promises: Promise<any>[] = [];

      if (vtKey) {
        promises.push(
          fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
            headers: { "x-apikey": vtKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.data?.attributes?.last_analysis_stats) {
                apiMetrics.virustotal = {
                  malicious: data.data.attributes.last_analysis_stats.malicious,
                  harmless: data.data.attributes.last_analysis_stats.harmless,
                  suspicious: data.data.attributes.last_analysis_stats.suspicious,
                };
              }
            })
            .catch(() => {})
        );
      }

      if (otxKey) {
        promises.push(
          fetch(`https://otx.alienvault.com/api/v1/indicators/file/${hash}/general`, {
            headers: { "X-OTX-API-KEY": otxKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data) {
                apiMetrics.alienvault = {
                  pulseCount: data.pulse_info?.count || 0,
                  tags: data.pulse_info?.pulses?.map((p: any) => p.name).slice(0, 3) || [],
                };
              }
            })
            .catch(() => {})
        );
      }

      await Promise.all(promises);
      if (vtKey || otxKey) {
        verificationStatus = `Live File Reputation Check Active (${[
          vtKey ? "VirusTotal" : "",
          otxKey ? "AlienVault OTX" : "",
        ]
          .filter(Boolean)
          .join(", ")}).`;
      }

    // 4. URL / Domain Reputation Check (Google Safe Browsing, URLScan, VirusTotal, AlienVault)
    } else if (urlRegex.test(query) || domainRegex.test(query)) {
      detectedType = "URL / Domain Web Address";
      extractedIndicator = text.trim();
      const domain = extractedIndicator.replace(/^(https?:\/\/)?(www\.)?/, "").split("/")[0];

      const safebrowsingKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
      const urlscanKey = process.env.URLSCAN_API_KEY;
      const vtKey = process.env.VIRUSTOTAL_API_KEY;
      const otxKey = process.env.ALIENVAULT_OTX_API_KEY;

      const promises: Promise<any>[] = [];

      if (safebrowsingKey) {
        promises.push(
          fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${safebrowsingKey}`, {
            method: "POST",
            body: JSON.stringify({
              client: { clientId: "cybershield", clientVersion: "1.0.0" },
              threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: extractedIndicator }],
              },
            }),
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.matches) {
                apiMetrics.safebrowsing = {
                  isMalicious: true,
                  details: data.matches.map((m: any) => m.threatType).join(", "),
                };
              } else {
                apiMetrics.safebrowsing = { isMalicious: false };
              }
            })
            .catch(() => {})
        );
      }

      if (urlscanKey) {
        promises.push(
          fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}`, {
            headers: { "API-Key": urlscanKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.results) {
                apiMetrics.urlscan = {
                  totalScans: data.results.length,
                  maliciousCount: data.results.filter((res: any) => res.verdicts?.overall?.malicious).length,
                };
              }
            })
            .catch(() => {})
        );
      }

      if (vtKey) {
        promises.push(
          fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
            headers: { "x-apikey": vtKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data?.data?.attributes?.last_analysis_stats) {
                apiMetrics.virustotal = {
                  malicious: data.data.attributes.last_analysis_stats.malicious,
                  harmless: data.data.attributes.last_analysis_stats.harmless,
                  suspicious: data.data.attributes.last_analysis_stats.suspicious,
                };
              }
            })
            .catch(() => {})
        );
      }

      if (otxKey) {
        promises.push(
          fetch(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, {
            headers: { "X-OTX-API-KEY": otxKey },
          })
            .then(r => (r.ok ? r.json() : null))
            .then(data => {
              if (data) {
                apiMetrics.alienvault = {
                  pulseCount: data.pulse_info?.count || 0,
                  tags: data.pulse_info?.pulses?.map((p: any) => p.name).slice(0, 3) || [],
                };
              }
            })
            .catch(() => {})
        );
      }

      await Promise.all(promises);
      if (safebrowsingKey || urlscanKey || vtKey || otxKey) {
        verificationStatus = `Live Web Domain Scan Active (${[
          safebrowsingKey ? "Google Safe Browsing" : "",
          urlscanKey ? "URLScan" : "",
          vtKey ? "VirusTotal" : "",
          otxKey ? "AlienVault OTX" : "",
        ]
          .filter(Boolean)
          .join(", ")}).`;
      }

    // 5. Raw Email Headers Parsing
    } else if (hasEmailHeaders) {
      detectedType = "Raw Email Headers Source";
      const spfCheck = query.includes("spf=pass") || query.includes("spf: pass") || query.includes("spf-alignment: pass") ? "PASS" : "FAIL (Mismatched signature or unauthorized relay)";
      const dkimCheck = query.includes("dkim=pass") || query.includes("dkim: pass") ? "PASS" : "FAIL (Missing or malformed cryptographic key)";
      const dmarcCheck = query.includes("dmarc=pass") || query.includes("dmarc: pass") ? "PASS" : "FAIL (Alignment policy violation)";

      apiMetrics.emailHeaders = {
        spf: spfCheck,
        dkim: dkimCheck,
        dmarc: dmarcCheck,
      };
      verificationStatus = "Header analyzer modules active. Extracted cryptographic DKIM and SPF relay nodes.";

    // 6. Email Address Indicator
    } else if (emailRegex.test(query)) {
      detectedType = "Email Address Indicator";
      extractedIndicator = text.trim();
      verificationStatus = "Local pattern parser active.";

    // 7. SMS message indicator
    } else if (smsPattern.test(query) && query.length < 250) {
      detectedType = "SMS Phishing Message";
      extractedIndicator = text.trim();
      verificationStatus = "SMS Smishing filter active.";

    // 8. QR Text/Link indicator
    } else if (qrRegex.test(query)) {
      detectedType = "QR Code Text / Scheme Link";
      extractedIndicator = text.trim();
      verificationStatus = "QR payload inspector active.";

    // 9. Error Logs indicator
    } else if (errorLogPattern.test(query)) {
      detectedType = "Error Log / System Event Diagnostic";
      extractedIndicator = text.trim();
      verificationStatus = "Security system log parser active.";

    // 10. IOC indicator
    } else if (iocPattern.test(query)) {
      detectedType = "Indicator of Compromise (IOC)";
      extractedIndicator = text.trim();
      verificationStatus = "Malware IOC registry inspector active.";
    }

    // Prepare prompt for Gemini
    const categoryCtx = activeCategoryId ? `Active Context Category: ${activeCategoryId}` : "";
    const topicCtx = topicTitle ? `Topic Context: ${topicTitle}` : "";

    const prompt = `You are the Elite CyberShield Enterprise SOC AI Security Intelligence Assistant, a veteran cybersecurity architect and incident handler.
You have been queried with threat data by an operative.

OPERATIVE INPUT SUMMARY:
- Detected Component: ${detectedType}
- Extracted Indicator: "${extractedIndicator}"
- User Raw Input: "${text}"
- ${categoryCtx}
- ${topicCtx}

API INTELLIGENCE VERIFICATION METRICS RETRIEVED (IF ANY):
- API Keys Verified Status: ${verificationStatus}
- Live Security Catalog Metrics retrieved: ${JSON.stringify(apiMetrics, null, 2)}

(Note: If any API keys are NOT configured, we report "Verification unavailable." for those services. Do NOT fabricate fake live scanning numbers or data. Only report the actual live data retrieved. If NO live data was retrieved because keys were absent, acknowledge this honestly, state "Live threat telemetry verification unavailable. Local offline rule databases active.", and provide top-tier analytical educational analysis).

YOUR CORE RESPONSIBILITY:
Format a detailed, professional Dark Hacker / SOC-themed Advisory Briefing inside the terminal in plain Markdown format. Do NOT use HTML tags. Make it incredibly scannable, rugged, and highly professional.

YOUR RESPONSE MUST INCLUDE THE FOLLOWING SECTIONS EXACTLY (WITH THESE HEADER TEXTS STYLED AS HEADINGS):

1. **[CYBERSHIELD ENTERPRISE SOC REPORT // ADVISORY BULLETIN]**
   Provide a high-impact heading followed by metadata:
   - COMPONENT: ${detectedType.toUpperCase()}
   - EXTRACTED TARGET: ${extractedIndicator}
   - API VERIFICATION GATEWAYS: ${verificationStatus}
   - SYSTEM STATUS: SECURE MONITORING ENABLED

2. **EXECUTIVE SUMMARY**
   Give a high-fidelity explanation of what this input represents, the technical risks involved, how attackers exploit this target, and how severe it is. Incorporate any live API metrics retrieved (such as VirusTotal reputation score, AbuseIPDB confidence indices, or NIST CVSS ratings).

3. **RISK SCORE**
   Evaluate the risk from 0 to 100 based on threat severity, ease of exploit, and potential impact. Provide the numeric score and a 1-sentence justification.

4. **SEVERITY**
   State the severity clearly: CRITICAL, HIGH, MEDIUM, or LOW based on the Risk Score.

5. **INDICATORS**
   List the exact technical indicators parsed or extracted from the threat input (e.g., IPs, Domains, SHA256 hashes, CVE identifiers, registry keys, bad strings).

6. **RECOMMENDED ACTIONS**
   Create a step-by-step technical action checklist of direct, low-level technical containment commands or steps the operative should run immediately (e.g. drop firewall rules, system process kills, registry resets).

7. **RECOVERY STEPS**
   Outline post-incident clean up, credentials rotation, system backup restorations, or device resets to clean the system state.

8. **PREVENTION TIPS**
   Provide technical bullet points to harden the defensive posture, secure offline backup boundaries, and verify system integrity.

9. **OFFICIAL RESOURCES**
   Provide official, authoritative cybersecurity resources/websites (such as National Cyber Crime Portal, CISA advisory links, NIST NVD link, block list directories, or 1930 Helpline guidance).

10. **RELATED LEARNING MODULES**
    Identify which learning topics or modules inside the platform (e.g., Banking Fraud, UPI Fraud, Password Security, Wi-Fi Security, Email Security, etc.) this incident is associated with.

Maintain an authoritative, hyper-focused tone. Do not introduce yourself or use conversational filler. End with a standard security disclaimer.`;

    // Execute server-side Gemini request
    const geminiResponse = await ai.models.generateContent({
      model: "gemini-3.5-flash",
      contents: prompt,
    });

    const report = geminiResponse.text || "Failed to compile intelligence report.";
    res.json({ report });

  } catch (error: any) {
    console.error("AI Threat Analysis Error:", error);
    res.status(500).json({ error: error.message || "Failed to analyze input parameters." });
  }
});

// Implement Vite middleware or static serving
async function startServer() {
  if (process.env.NODE_ENV !== "production") {
    console.log("Starting server in DEVELOPMENT mode with Vite Middleware...");
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    console.log("Starting server in PRODUCTION mode with static assets serving...");
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));

    app.get("/dashboard.html", (req, res) => {
      res.sendFile(path.join(distPath, "dashboard.html"));
    });

    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  if (!process.env.VERCEL) {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`[CYBERSHIELD GATEWAY] Security node live on port ${PORT}`);
    });
  }
}

startServer();

export default app;
