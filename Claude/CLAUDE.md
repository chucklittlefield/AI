# Memory — Chuck Littlefield
**Last updated:** 2026-04-23

## Me
Chuck Littlefield — IT / Network Admin / Security at SIFP, embedded with FCTG (the MSP).
30 years IT experience. Current focus: **Cybersecurity**.
Certs: OSCP, CISSP, Security+, Pentest+ (CCNA expired)
Proficient: all Windows versions, Linux
Location: 22F Cotton Road, Nashua, NH 03063 | 603-881-3700 x251
Admin account: `FCTGNET\charles.t1.littlefie`

→ Full org context: memory/context/company.md

## Organizations (OpCos)
| Abbr | Full Name | Subnet |
|------|-----------|--------|
| **SIFP** | Seaboard International Forest Products, LLC | 10.30.0.0/16 |
| **FCTG** | Forest City Trading Group | 10.1.0.0/16 |
| **FCTGHQ** | Forest City Trading Group HQ | 10.0.0.0/16 |
| **AIFP** | American International Forest Products, LLC | 10.4.0.0/16 |
| **BIFP** | Birmingham International Forest Products, LLC | 10.8.0.0/16 |
| **BP** | Buckeye Pacific, LLC | 10.10.0.0/16 |
| **SMT** | Southern Mississippi Trading, LLC | 10.14.0.0/16 |
| **OI** | Olympic Industries, ULC | 10.18.0.0/16 |
| **TIFP** | Tampa International Forest Products, LLC | 10.20.0.0/16 |
| **PFP** | Plateau Forest Products, LLC | 10.24.0.0/16 |
| **VFP** | Viking Forest Products, LLC | 10.26.0.0/16 |
| **RIFP** | Richmond International Forest Products, LLC | 10.28.0.0/16 |
| **AR** | Affiliated Resources, LLC | 10.75.0.0/16 |
→ OU names, contacts, timezones: memory/context/opcos.md

## FCTG IT Team (MSP colleagues)
| Who | Role / Notes |
|-----|--------------|
| **Conrad** | Conrad Palmer — IT Manager/Director, Conrad.Palmer@fctg.com, runs all IT meetings |
| **Ben / Benjamin** | Benjamin Sanchez — Infrastructure, benjamin.sanchez@fctg.com, VMware/ESXi/Nimble |
| **Josh / Joshua** | Joshua Rosales — Security & systems, Joshua.Rosales@fctg.com, MFA/YubiKey/SOC |
| **Lance** | Lance Means — IT lead, Lance.Means@fctg.com, runs Security & Infra meeting |
| **James / Wells** | James Wells — IT, james.wells@fctg.com |
| **Albert** | Albert Arias — IT, albert.arias@fctg.com |
| **Chris C** | Chris Capper — IT, chris.capper@fctg.com |
| **Jane** | Jane Weinberg — IT, Jane.Weinberg@fctg.com |
| **Mike N** | Mike Nelson — IT, Mike.Nelson@fctg.com |
| **Aaron** | Aaron Burge — IT, Aaron.Burge@fctg.com |
| **Kerry** | Kerry Cakebread — IT, Kerry.Cakebread@fctg.com |
| **Austin** | Austin Wood — FCTG leadership, Austin.Wood@fctg.com |
→ Full team + more members: memory/people/fctg-team.md

## SIFP Staff (my users)
| Who | Role / Notes |
|-----|--------------|
| **Jennifer** | Jennifer Littlefield — Chuck's wife |
| **Jenlian** | Jenlian Chadwick — **President, SIFP**, jenlian.chadwick@sifp.com |
| **Andrew** | Andrew Waples — **Controller, SIFP**, andrew.waples@sifp.com (runs morning meeting) |
| **Janice** | Janice Clark — **Network Admin, SIFP**, janice.clark@sifp.com, 603-913-3484 |
| **Jim D** | Jim Dermody — SIFP staff, jim.dermody@sifp.com |
| **Yvette** | Yvette Nelson — SIFP staff |
| **Brittany A** | Brittany Acone — SIFP staff, brittany.acone@sifp.com |
| **Emma** | Emma Pretorius — SIFP staff, emma.pretorius@sifp.com |
| **Chris F** | Chris Fitzgerald — SIFP staff, chris.fitzgerald@sifp.com |
| **Andrew G** | Andrew Gorey — SIFP staff, andrew.gorey@sifp.com |
| **Liam** | Liam Nye — SIFP staff, liam.nye@sifp.com |
→ Full staff list: memory/people/sifp-staff.md

## Key External Contacts
| Who | Notes |
|-----|-------|
| **Lula** | Lula @ vikingforest.com — VFP contact |
| **Kevin C** | Kevin Curtis @ lumber.com |
| **Sean** | Sean Scoggins @ smtmiss.com — SMT IT |
| **Chris at OI** | Chris Irwin @ olympicind.com — Olympic Industries IT |
| **Harrison** | Harrison Womack @ newfathom.com — vendor support |
| **CyberMaxx** | ddehaven@cybermaxx.com — SOC vendor, weekly call |
| **Bobby** | Bobby Bui @ rifp.com — RIFP |
| **David G** | David Garnica @ tifp.com — TIFP |
| **Keaton** | Keaton Russell @ bifp.com — BIFP |

## Terms & Acronyms
| Term | Meaning |
|------|---------|
| OpCo | Operating Company (each has its own subnet/FortiGate) |
| FCTGNET | Active Directory domain for all companies |
| EC | Endpoint Central (ManageEngine — patch/endpoint mgmt) |
| GPO | Group Policy Object |
| OU | Organizational Unit (Active Directory) |
| RSoP | Resultant Set of Policy |
| DA | Delegated Admin (AD delegated permissions) |
| SOC | Security Operations Center (via CyberMaxx) |
| P1 / P2 | Alert severity: P1=critical, P2=warning (from Datadog) |
| DTDG | Datadog (monitoring platform, alert@dtdg.co) |
| SNMP | Simple Network Management Protocol (Datadog monitoring) |
| CIS | Center for Internet Security (compliance benchmarks L1/L2) |
| RCA | Root Cause Analysis |
| MFA | Multi-Factor Authentication |
| RBAC | Role-Based Access Control |
| IPSEC | VPN tunnel type between sites |
| vMotion | VMware live VM migration |
| iSCSI | Storage protocol (Nimble SAN) |
| RAS | Parallels Remote Access Server |
| ESXi | VMware hypervisor (hosts at 10.1.1.200–.203) |
| Sales Assist | SIFP's ERP/reporting system |
| Trade Central | Business app used by clients (VFP, etc.) |
| Secret Server | Password manager (fctg.secretservercloud.com) |
| circuit | An ISP internet connection at an OpCo site |
| tunnel | IPSEC VPN between sites |
| conf file | FortiGate full configuration export (.conf) |
| the morning meeting | SIFP staff weekly standup @8:45am, Andrew runs |
| kickoff | IT Ops Weekly Kickoff — Mon ~1pm ET, Conrad runs |
| change board | IT Ops Change Management — Tue, FCTG conf room |
| project status | Weekly project review — Thu, FCTG conf room |
| vuln/patch | Weekly vuln/patch meeting with Josh |
| sec & infra | Security & Infrastructure meeting — Thu, Lance leads |
| network admin mtg | Monthly multi-company network admin meeting |
→ Full glossary: memory/glossary.md

## Active Projects
| Project | What |
|---------|------|
| **Datadog/SNMP** | Configuring SNMP monitoring for FortiGate devices across all OpCos |
| **Firewall Policies** | FortiGate policy review, CIS compliance, traffic analysis |
| **Group Policy** | CIS L1 compliance checks, GPO consolidation across OUs |
| **Delegated Admin Audit** | AD delegated permissions audit across all OpCos |
| **ESXi Migration** | Moving VMs to hosts .202/.203, fixed Nimble iSCSI path binding |
| **GPO Hardening** | CIS benchmark GPOs rolling out to all OUs |
| **MFA Rollout** | Getting remaining users onto MS Authenticator / YubiKey |
| **Power BI Reports** | Replacing slow Sales Assist queries (Jenlian's ManagementDetailByBuyer) |
| **EC Update Script** | Post-update PowerShell script for Endpoint Central (Ben leading) |
→ Details: memory/projects/

## Recurring Meetings
| Meeting | When |
|---------|------|
| IT Ops Kickoff | Mon ~1pm ET, FCTG conf room, Conrad runs |
| Change Management | Tue, FCTG conf room, Conrad runs |
| CyberMaxx Weekly | Tue ~3:30pm ET, Teams |
| SIFP Morning Meeting | Wed ~8:45am, open staff area, Andrew runs |
| Vuln/Patch Meeting | Wed, Teams, Josh runs |
| Security & Infrastructure | Thu, Teams, Lance runs |
| Project Status | Thu, FCTG conf room, Conrad runs |
| Network Admin Monthly | Monthly, Teams, Conrad runs (all OpCos) |
| Andrew & Chuck Catch-Up | Monthly, Andrew's office |

## Software Stack
- Windows / Active Directory / Group Policy
- Microsoft 365 / Office / Power BI
- VS Code / Python / PowerShell
- FortiGate / FortiCloud
- Datadog (monitoring)
- Veeam + Wasabi (backup)
- Delinea Secret Server
- SentinelOne (EDR, via CyberSafe Solutions)
- Mimecast (email security)
- Endpoint Central (EC)
- Parallels RAS
- HPE Nimble / VMware ESXi
- Obsidian

## Preferences
- Think before acting; read existing files before writing code
- Be concise in output, thorough in reasoning
- Prefer editing over rewriting whole files
- No sycophantic openers or closing fluff
- Keep solutions simple and direct
- User instructions always override this file
- Preferred formats: `.md` (Obsidian style), `.docx` for formal docs, `.html` for dashboards, `.pptx` for presentations
- For security content: include CVE numbers, CVSS scores, affected products
- Prioritize actionable recommendations — what should the team actually *do*?
- Structure longer reports with an Executive Summary at top
- Always cite sources in research documents

## Personal Schedule Notes
- **Pick Up Kids** — blocked daily ~4:30–5:30pm ET (do not schedule over this)
- **Lunch** — blocked daily ~12–1pm ET (red calendar category)
