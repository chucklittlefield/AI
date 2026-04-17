init_config:
  loader: "core"
  mibs_folder: "C:\\ProgramData\\Datadog\\conf.d\\snmp.d"
  ping:
    count: 2
    enabled: true
    interval: 20
    timeout: 3000
  use_device_id_as_hostname: true
instances:
  - interface_configs:
      - in_speed: 500000000
        match_field: "name"
        match_value: "wan2"
        out_speed: 500000000
        tags:
          - "Criticality:Non-Critical"
          - "InterfaceZone:Wan"
          - "Trusted:False"
          - "InterfaceFunction:Internet"
          - "InterfaceRank:Secondary"
          - "Provider:Unknown"
      - in_speed: 1000000000
        match_field: "name"
        match_value: "wan1"
        out_speed: 1000000000
        tags:
          - "Criticality:Critical"
          - "InterfaceZone:Wan"
          - "Trusted:False"
          - "InterfaceFunction:Internet"
          - "InterfaceRank:Primary"
          - "Provider:Unknown"
      - in_speed: 1000000000
        match_field: "index"
        match_value: "41"
        out_speed: 1000000000
        tags:
          - "FriendlyName:Opus_to_SMT"
          - "Criticality:Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:Opus"
          - "InterfaceRank:Primary"
          - "Provider:Unknown"
      - in_speed: 500000000
        match_field: "index"
        match_value: "42"
        out_speed: 500000000
        tags:
          - "FriendlyName:Opus_to_SMT_2"
          - "Criticality:Non-Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:Opus"
          - "InterfaceRank:Secondary"
          - "Provider:Unknown"
      - in_speed: 500000000
        match_field: "index"
        match_value: "60"
        out_speed: 500000000
        tags:
          - "FriendlyName:SMT_to_BI2"
          - "Criticality:Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:BIFP"
          - "InterfaceRank:Secondary"
          - "Provider:Unknown"
      - in_speed: 1000000000
        match_field: "index"
        match_value: "39"
        out_speed: 1000000000
        tags:
          - "FriendlyName:SMT_to_BIFP"
          - "Criticality:Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:BIFP"
          - "InterfaceRank:Primary"
          - "Provider:Unknown"
      - in_speed: 1000000000
        match_field: "index"
        match_value: "139"
        out_speed: 1000000000
        tags:
          - "FriendlyName:BP-OpCo"
          - "Criticality:Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:BP"
          - "InterfaceRank:Primary"
          - "Provider:Unknown"
      - in_speed: 500000000
        match_field: "index"
        match_value: "51"
        out_speed: 500000000
        tags:
          - "FriendlyName:BP-Opco2"
          - "Criticality:Non-Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:BP"
          - "InterfaceRank:Secondary"
          - "Provider:Unknown"
      - in_speed: 1000000000
        match_field: "index"
        match_value: "35"
        out_speed: 1000000000
        tags:
          - "FriendlyName:SMT-Azure"
          - "Criticality:Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:Azure"
          - "InterfaceRank:Primary"
          - "Provider:Unknown"
      - in_speed: 500000000
        match_field: "index"
        match_value: "37"
        out_speed: 500000000
        tags:
          - "FriendlyName:Azure2"
          - "Criticality:Non-Critical"
          - "InterfaceZone:VPN"
          - "Trusted:False"
          - "InterfaceFunction:IPSECVPN"
          - "VPNDestination:Azure"
          - "InterfaceRank:Secondary"
          - "Provider:Unknown"
    ip_address: "10.14.1.2"
    loader: "core"
    name: "FCTG-FORTINET:10.14.1.2"
    snmp_version: 3
    use_device_id_as_hostname: true
    user: "DataDog"
