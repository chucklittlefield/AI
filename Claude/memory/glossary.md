# Glossary — Chuck Littlefield's Workplace Decoder Ring

## Companies & Organizations
| Name | Full Name | Notes |
|------|-----------|-------|
| FCTG | Forest City Trading Group | IT MSP, Chuck's IT employer, fctg.com |
| SIFP | Seaboard International Forest Products | Chuck's end-user company, sifp.com |
| RIFP | (rifp.com) | Related forest products company, Bobby Bui |
| TIFP | (tifp.com) | Related company, David Garnica |
| BIFP | (bifp.com) | Related company, Keaton Russell |
| VF | Viking Forest | Client company, vikingforest.com |
| OI | Olympic Industries | Client company, olympicind.com, Chris Irwin |
| SMT | (smtmiss.com) | Client, Sean Scoggins |
| FCTGNET | Forest City Trading Group Network | Active Directory domain name |
| CyberMaxx | CyberMaxx | Security vendor (SOC, threat monitoring) |
| CyberSafe | CyberSafe Solutions | Manages SentinelOne (sa@cybersafesolutions.com) |
| Park Place | Park Place Technologies | VMware vendor |
| Newfathom | Newfathom | IT vendor/support (Harrison Womack) |

## Systems & Tools
| Term | Full Name / Meaning | Notes |
|------|---------------------|-------|
| ESXi | VMware ESXi hypervisor | Hosts at 10.1.1.200, .201, .202, .203 |
| Nimble | HPE Nimble Storage | iSCSI SAN storage array |
| Veeam | Veeam Backup & Replication | Backup solution (SureBackup + WasabiBackup jobs) |
| Wasabi | Wasabi Cloud Storage | Off-site backup target |
| Mimecast | Mimecast | Email security/filtering, spam quarantine |
| SentinelOne | SentinelOne | EDR endpoint security (managed by CyberSafe) |
| Datadog / DTDG | Datadog | Infrastructure monitoring (alert@dtdg.co) |
| Secret Server | Delinea Secret Server | Password manager at fctg.secretservercloud.com |
| EC | Endpoint Central | Patch management & endpoint tool (ManageEngine) |
| Parallels RAS | Parallels Remote Application Server | Remote access server |
| Trade Central | Trade Central | Business app used by client companies (VF etc.) |
| Sales Assist | Sales Assist | SIFP's ERP/reporting system |
| RightFax | RightFax | Fax server (Rightfax-test OU in AD) |
| Netwrix | Netwrix | AD auditing tool |
| YubiKey | YubiKey | Hardware MFA security keys |
| Power BI | Power BI | Microsoft data visualization/reporting |
| LiteLLM | LiteLLM | AI proxy tool (had security advisory Mar 2026) |

## IT Acronyms & Jargon
| Term | Meaning |
|------|---------|
| GPO | Group Policy Object (applied to AD OUs for settings/security) |
| OU | Organizational Unit (Active Directory container) |
| MFA | Multi-Factor Authentication |
| SOC | Security Operations Center |
| RCA | Root Cause Analysis |
| P1 / P2 | Alert priority: P1 = critical, P2 = warning (Datadog) |
| EDR | Endpoint Detection & Response |
| iSCSI | Internet Small Computer Systems Interface (storage protocol) |
| vMotion | VMware live VM migration between hosts |
| SAML | Security Assertion Markup Language (SSO protocol) |
| RDP | Remote Desktop Protocol |
| SSH | Secure Shell |
| AD | Active Directory |
| CIS | Center for Internet Security (security benchmarks Chuck applies) |
| NIC | Network Interface Card |
| RAS | Remote Access Server (Parallels) |
| HyperV | Microsoft Hyper-V (also being migrated at OI) |

## Internal Meeting Names
| Term | Meaning |
|------|---------|
| kickoff / the kickoff | IT Operations Weekly Kickoff — Mon ~1pm, Conrad runs |
| change board / change mgmt | IT Operations Change Management — Tue, FCTG conf room |
| project status / project review | Weekly Project Status [In-person] — Thu, FCTG conf room |
| vuln/patch | Weekly Vulnerability/Patch Meeting — Wed, Josh & Chuck |
| sec & infra | Security and Infrastructure meeting — Thu, Lance leads |
| morning meeting | SIFP Staff Weekly Morning Meeting — Wed ~8:45am, Andrew runs |
| network admin mtg | Monthly Network Admin Meeting — all companies, Conrad runs |
| cybermaxx weekly | FCTG/CyberMaxx Weekly Deployment Status — Tue ~3:30pm |
| andrew & chuck | Monthly catch-up with Andrew Waples |

## Internal Jargon
| Term | Meaning |
|------|---------|
| the migration | ESXi host VM migration project (moving to .202/.203 hosts) |
| nimble fix | Fixed iSCSI path binding on Nimble SAN |
| the hardening | GPO CIS benchmark security hardening rollout |
| ManagementDetailByBuyer | Slow report Jenlian runs in Sales Assist |
| ITOps | ITOps@fctg.com — IT operations email list |
| NA-alerts | na-alerts@fctg.com — North America security alerts list |
| ##NetworkAdmins | ##NetworkAdministrators@fctg.com — network admin DL |
| cybersecurity | cybersecurity@fctg.com — security team DL |
| helpdesk | Helpdesk@fctg.com / sdmonitor@fctg.com |
| SIFP_Everyone | SIFP_Everyone@sifp.com — all-staff distribution list |

## People Nicknames → Full Names
| Nickname | Full Name |
|----------|-----------|
| Chuck | Chuck Littlefield (me) |
| Conrad | Conrad Palmer, FCTG IT Manager |
| Ben / Benjamin | Benjamin Sanchez, FCTG Infrastructure |
| Josh / Joshua | Joshua Rosales, FCTG Security |
| Lance | Lance Means, FCTG IT Lead |
| James / Wells | James Wells, FCTG IT |
| Albert | Albert Arias, FCTG IT |
| Chris C | Chris Capper, FCTG IT |
| Jane | Jane Weinberg, FCTG IT |
| Mike N | Mike Nelson, FCTG IT |
| Aaron | Aaron Burge, FCTG IT |
| Kerry | Kerry Cakebread, FCTG IT |
| Crystal | Crystal Hunter, FCTG IT |
| Casey R | Casey Rush, FCTG IT |
| Steven M | Steven Meisinger, FCTG IT |
| Gavin | Gavin Rees, FCTG IT |
| Jeff H | Jeff Harris, FCTG IT |
| Mike T | Mike Turner, FCTG IT |
| Stu | Stu Hansen, FCTG IT |
| Geoff / Zak | Geoffrey Zak, FCTG IT |
| Kevin P | Kevin Poff, FCTG IT |
| Jordan | Jordan Staples, FCTG IT |
| Andrew | Andrew Waples, SIFP supervisor |
| Jenlian | Jenlian Chadwick, SIFP user |
| Chris at OI | Chris Irwin @ olympicind.com |
| Lula | Lula @ vikingforest.com |
| Kevin C | Kevin Curtis @ lumber.com |
| Harrison | Harrison Womack @ newfathom.com |
| Bobby | Bobby Bui @ rifp.com |
| David G | David Garnica @ tifp.com |
| Keaton | Keaton Russell @ bifp.com |
| Sean S | Sean Scoggins @ smtmiss.com |
| Austin | Austin Wood @ fctg.com (FCTG leadership) |
