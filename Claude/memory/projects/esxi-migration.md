# Project: ESXi Host VM Migration

**Status**: Active — in progress as of April 23, 2026
**Also called**: "the migration"
**Owner**: Benjamin Sanchez (FCTG Infrastructure)
**Participants**: Ben, Conrad, Chuck, Lance, James

## What It Is
Migrating VMs from ESXi hosts .200 and .201 over to newer hosts .202 and .203.
Root cause of prior issues: Nimble iSCSI was locked to host IPs instead of iSCSI VLAN IPs.
Ben fixed the Nimble path binding — latency dramatically improved on .203.

## ESXi Hosts
| Host IP | Status |
|---------|--------|
| 10.1.1.200 | Old host, SSHing in has password issues |
| 10.1.1.201 | Old host |
| 10.1.1.202 | New host — migrated to, good latency |
| 10.1.1.203 | New host — low latency, low load, production ready |

## VMs Migrated / In Progress (Apr 23, 2026)
- FCTGMileageRail → .203 ✓
- HQDEVSQL1 → .203 ✓
- FCTGAzureDF1, FCTGFAXTEST1, FCTGFTP1 → .203 (in progress)
- fctgfs1 → .203 (next, pending latency confirmation)

## Notes
- Conrad asks for project updates 10 min before project status meetings
- RDP issues cropped up day-of (April 23) — likely unrelated to migration
- iSCSI NICs confirmed passing real traffic on both paths after fix
