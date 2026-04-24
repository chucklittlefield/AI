# Project: GPO Security Hardening

**Status**: Active — rolling out to all OUs
**Owner**: Chuck Littlefield
**Audience**: ITOps@fctg.com, ##NetworkAdministrators@fctg.com

## What It Is
Applying CIS benchmark security settings via Group Policy Objects to all OUs
in the FCTGNET domain. Chuck communicates each rollout to ITOps.

## OUs Completed (as of April 2026)
- FCTG Workstation OU
- SIFP Workstations OU
- FCTG IT Workstations OU
- Netwrix OU
- Rightfax-test OU
- TFSbuild OU
- SalesAssist-DEV OU
- All OUs (network GPO)

## Key Settings Being Applied
- Disable lock screen camera & slideshow
- Disable online speech recognition
- Disable RPC Locator, Routing & Remote Access, SSDP Discovery services
- Network security: NTLM computer identity settings
- Chrome auto-login to Microsoft Office (via GPO)

## Vendor Coordination
- Harrison Womack (Newfathom) — notified before enabling certain GPO settings
