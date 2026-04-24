# Company & Org Context

## Chuck's Position
Chuck Littlefield is the IT Systems Administrator for SIFP, embedded with FCTG (The parent company).
He wears two hats:
1. **SIFP IT** — IT contact for Seaboard International Forest Products staff along with Janice Clark
2. **FCTG IT** — collaborates with FCTG team on shared infrastructure, security, and projects

## The FCTG Family of Companies
FCTG manages IT for a group of forest products and related companies. Chuck is the IT Network Administrator for SIFP.

| Company | Domain | IT Rep / Contact |
|---------|--------|-----------------|
| FCTG | fctg.com | Conrad Palmer (IT Manager) |
| SIFP | sifp.com | Chuck Littlefield |
| RIFP | rifp.com | Bobby Bui |
| TIFP | tifp.com | David Garnica |
| BIFP | bifp.com | Keaton Russell |
| Viking Forest | vikingforest.com | Lula, GarrettM, bens@ |
| Olympic Industries (OI) | olympicind.com | Chris Irwin |
| lumber.com | lumber.com | Kevin Curtis, Thomson |
| SMT | smtmiss.com | Sean Scoggins | Jordan Staples |
| BP | buckeyepacific.com |

All companies share the **FCTGNET** Active Directory domain and the FCTG-managed infrastructure.

## Infrastructure Overview
- **Hypervisor**: VMware ESXi hosts at 10.1.1.200, .201, .202, .203
- **Storage**: HPE Nimble iSCSI SAN (connected to ESXi via iSCSI NICs on ISCSI VLAN)
- **Backup**: Veeam (SureBackup + WasabiBackup to Wasabi cloud)
- **Email Security**: Mimecast (filtering, quarantine, phishing reporting)
- **Endpoint Security**: SentinelOne (managed by CyberSafe Solutions)
- **Monitoring**: Datadog (P1/P2 alerts to email and Teams #teams-infra.warnings)
- **Password Mgmt**: Delinea Secret Server (fctg.secretservercloud.com)
- **Patch/Endpoints**: Endpoint Central (EC)
- **Remote Access**: Parallels RAS (Remote Application Server)
- **Identity**: Microsoft 365 + AD (FCTGNET domain) + MFA via MS Authenticator / YubiKey
- **Security Operations**: CyberMaxx (SOC, weekly call Tue)

## Key Tools Chuck Uses Daily
- **Mimecast** — releasing quarantined emails, investigating phishing
- **SentinelOne** — threat response, agent management
- **Secret Server** — password retrieval for servers/services
- **Datadog** — checking P1/P2 alerts on ESXi, services
- **EC (Endpoint Central)** — pushing patches, GPO-adjacent endpoint tasks
- **GPO / Active Directory** — applying CIS security hardening settings to OUs
- **Power BI** — building reports for SIFP users

## Vendors / External Partners
| Vendor | What They Do | Contact |
|--------|--------------|---------|
| CyberMaxx | SOC / security monitoring | ddehaven@cybermaxx.com |
| CyberSafe Solutions | Manages SentinelOne | sa@cybersafesolutions.com |
| Newfathom | IT support vendor for PFP| Harrison Womack (harrison@newfathom.com) |
| Park Place Technologies | HArdware support vendor | bwhitney@parkplacetech.com |
| Mimecast | Email security | support@mimecastsupport.zendesk.com |


