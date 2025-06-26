# NGAPAD Datasets
**Normal dataset**: The normal dataset comprises NGAP signaling compliant with 3GPP specifications, where follow protocol procedures and parameter constraints for intercomponent interactions. We simulated the mobility behaviors of 300 UE using UERANSIM to collect NGAP signaling, including UE registration, PDU session management, UE mobility management and UE de-registration. In addition, network configurations of UE and the 5GC were modified to generate comprehensive samples, such as supported security algorithms prioritization and timers settings. Commercial smartphones and programmable SIM cards were integrated into the 5G simulation platform to capture signaling traces.

**Malicious dataset**: The malicious dataset simulate adversarial behaviors on N2 interface to collect anomaly samples. We modified the source code of the srsRAN Project and Open5GS to construct malicious NGAP sessions. We simulated attacks targeting NGAP and NAS vulnerabilities to reflect real-world 5G edge threats. The malicious dataset contains 6 attack types: Identity Spoofing, Denial of Service, Privacy Leakage, Session Hijacking, Resource Abuse and Signaling Manipulation.

```shell
├── datasets_slice # CSV files group by slice length
│   ├── slice_10
│   ├── slice_11
│   ├── slice_12
│   ├── slice_13
│   ├── slice_14
│   ├── slice_15
│   ├── slice_16
│   ├── slice_17
│   ├── slice_18
│   ├── slice_6
│   ├── slice_7
│   ├── slice_8
│   └── slice_9
├── ngap_parser
│   ├── constant.py
│   ├── ngap_parser.py # NGAP message pareser
│   ├── ngap_ue.py # NGAP Telemetry
│   └── pcap2json.py
└── README.md
```

# Publication
```
@inproceedings{NGAPAD,
  title     = {NGAP Features Fusion Hybrid Network Attack Detection for 5G Edge Security},
  author    = {Shaocong Feng, Baojiang Cui, Shengjia Chang, Haoran Yu and Yuqi Huo},
}
```
