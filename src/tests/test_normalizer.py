from __future__ import annotations

import json
from pathlib import Path
import pytest

from src.threatfusion.normalizer import normalize_otrf, normalize_cicids, auto_normalize

ROOT = Path(__file__).resolve().parents[2]


def test_normalize_otrf_process_creation():
    otrf_event = {
        "EventID": 1,
        "SourceName": "Microsoft-Windows-Sysmon",
        "TimeCreated": "2026-09-18T14:15:30.124Z",
        "Computer": "ENG-WKS17",
        "EventData": {
            "RuleName": "technique_id=T1059.001,technique_name=PowerShell",
            "ProcessId": 4824,
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc JABzAD0A...",
            "User": "DEFENCE\\jsharma",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        },
    }
    canonical = normalize_otrf(otrf_event)
    assert canonical["source"] == "endpoint"
    assert canonical["host"] == "ENG-WKS17"
    assert canonical["user"] == "jsharma"
    assert canonical["process"] == "powershell.exe"
    assert canonical["parent_process"] == "WINWORD.EXE"
    assert canonical["attack_id_hint"] == "T1059.001"
    assert canonical["rule_technique_hint"] == "T1059.001"
    assert canonical["origin"] == "OTRF Security Datasets"
    assert canonical["provenance_type"] == "real_sample"
    assert canonical["dataset_name"] == "OTRF Security Datasets"


def test_normalize_otrf_lsass_access():
    otrf_event = {
        "EventID": 10,
        "SourceName": "Microsoft-Windows-Sysmon",
        "TimeCreated": "2026-09-18T14:22:15.890Z",
        "Computer": "ENG-WKS17",
        "EventData": {
            "RuleName": "technique_id=T1003.001,technique_name=LSASS Memory",
            "SourceImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
        },
    }
    canonical = normalize_otrf(otrf_event)
    assert canonical["event_type"] == "process_access"
    assert canonical["attack_id_hint"] == "T1003.001"
    assert canonical["rule_technique_hint"] == "T1003.001"
    assert canonical["provenance_type"] == "real_sample"
    assert "lsass.exe" in canonical["detail"]


def test_normalize_cicids_flow():
    flow = {
        "FlowID": "10.40.2.15-185.214.66.91-51234-443-6",
        "SourceIp": "10.40.2.15",
        "SourcePort": 51234,
        "DestinationIp": "185.214.66.91",
        "DestinationPort": 443,
        "Protocol": "TCP",
        "Timestamp": "2026-09-18T14:28:40Z",
        "Label": "Botnet-C2-Beaconing",
        "SensorHost": "NET-PROBE-CORE01",
    }
    canonical = normalize_cicids(flow)
    assert canonical["source"] == "network_sensor"
    assert canonical["src_ip"] == "10.40.2.15"
    assert canonical["dst_ip"] == "185.214.66.91"
    assert canonical["dst_port"] == 443
    assert canonical["protocol"] == "TCP"
    assert canonical["origin"] == "CIC-IDS2017 Dataset"
    assert canonical["provenance_type"] == "real_sample"
    assert canonical["dataset_name"] == "CIC-IDS2017"


def test_auto_normalize():
    raw_otrf = {"EventID": 1, "Computer": "HOST1", "EventData": {}}
    res_otrf = auto_normalize(raw_otrf)
    assert res_otrf["origin"] == "OTRF Security Datasets"
    assert res_otrf["provenance_type"] == "real_sample"

    raw_cic = {"FlowID": "flow-123", "SourceIp": "1.1.1.1", "DestinationIp": "2.2.2.2"}
    res_cic = auto_normalize(raw_cic)
    assert res_cic["origin"] == "CIC-IDS2017 Dataset"
    assert res_cic["provenance_type"] == "real_sample"

    raw_std = {"source": "siem", "host": "HOST-X", "event_type": "login"}
    res_std = auto_normalize(raw_std)
    assert res_std["host"] == "HOST-X"
    assert res_std["provenance_type"] == "synthetic"
    assert res_std["dataset_name"] == "Synthetic Benchmark"
