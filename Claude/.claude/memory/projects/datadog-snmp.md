# Project: Datadog SNMP Monitoring

**Status:** Active

## Goal

Configure Datadog SNMP monitoring for FortiGate devices across all OpCos.

## Requirements

- All WAN and IPSEC interfaces configured with bandwidth metrics
- WAN interfaces tagged: Primary, Secondary, Tertiary (by speed)
- IPSEC tunnels tagged with friendly name showing source → destination site
- All interfaces tagged with provider info
- Each device tagged with OpCo tag

## Key Files

- `Projects/DataDog Network monitoring/conf.yaml` — Datadog SNMP config
- `Projects/DataDog Network monitoring/SNMP_Interface_Inventory.xlsx` — Interface inventory
- `Projects/DataDog Network monitoring/xlsx_to_yaml.py` — Converts inventory to YAML
- `Projects/DataDog Network monitoring/parse_full_config.py` — Parses FortiGate .conf files
