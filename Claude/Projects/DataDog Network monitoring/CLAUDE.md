This project aims to configure Datadog snmp monitoring for Fortigates

All WAN interfaces and IPSEC interfaces should be configured with bandwidth

All wan interfaces should be taged Primary, Secondary, Tertiary based on speed

Ipsec tunnels should be tagged with a Friendly name that list the source and destination site

All Interfaces should be tagged with provider information

Each device should be tagged with an OpCo tag

Below lists the OpCO and Subnet
- SIFP subnet is 10.30.0.0/16
- AIFP subnet is 10.4.0.0/16
- BP subnet is 10.10.0.0/16
- SMT subnet is 10.14.0.0/16
- OI subnet is 10.18.0.0/16
- TIFP subnet is 10.20.0.0/16
- PFP subnet is 10.24.0.0/16
- RIFP subnet is 10.28.0.0/16
- AR subnet is 10.75.0.0/16
- FCTGHQ subnet is 10.0.0.0/16
- OPUS subnet is 10.1.0.0/16

Here is a breakdown of each OpCos Internet circuits
AIFP-AR (two sub-sites: AIFP Trader Office & AR Operations Office)
- Ziply — 500 Mbps
- Comcast — 100 Mbps (AIFP) / 200 Mbps (AR)

BIFP:
- Comcast ENS & 
- PRI — 10 Mbps, 
- Zayo/AllStream — 500 Mbps
-  Ziply — 1 Gbps
BP: 
- ACC Business — 500 Mbps
-  Spectrum — 500 Mbps
OI: 
- Telus — 1 Gbps
- Shaw — 1 Gbps
PFP: 
- Zayo — 10 Mbps
- Lumen — 100 Mbps
RIFP: 
Lumen: 
- (Inet & PRI) — 50 Mbps
- Verizon — 500 Mbps, 
- Comcast — 500 Mbps
SIFP:
- FirstLight — 100 Mbps
- Comcast — 500 Mbps
SMT:
- Lumen (Inet & PRI) — 20 Mbps
- AT&T — 100 Mbps
- DE Fastlink — bandwidth not listed (notes say 1 Gbps fiber, primary data line; AT&T is backup)
TIFP:
- Lumen (Inet & PRI) — 100 Mbps
- Frontier FIOS — 1 Gbps
VFP
- Zayo/AllStream — 500 Mbps
- Comcast — 1 Gbps

Excel spreadsheet output rules for full config file analysis
- There should be a sheet for all firewall policies with settings as column
- there should be a physical interface sheet with with settings as columns
- there should be a sheet for tunnel Interfaces with with with settings as columns
- there should be a sheet with IPSEC tunnels and there settings as columns
- there should be a sheet with all static routes with settings as columns
-a sheet with Vlan settings including DHCP scopes
- there should be a sheet with address objects 
- there should be a sheet with address groups
- there should be a users sheet 
- there should be a sheet for services
- there should be a sheet for servic groups

Approach
- Think before acting. Read existing files before writing code.
- Be concise in output but thorough in reasoning.
- Prefer editing over rewriting whole files.
- Do not re-read files you have already read unless the file may have changed.
- Test your code before declaring done.
- No sycophantic openers or closing fluff.
- Keep solutions simple and direct.
- User instructions always override this file.



