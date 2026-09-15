"""
Generates a deliberately messy, multi-source alert feed for the D2
(Threat Intelligence Correlation & Alert Prioritisation) demo.

Two real incidents are seeded inside the noise:
  INC-A: phishing -> PowerShell execution -> credential dumping -> lateral
         movement (technique chain modeled on a real APT38-style pattern,
         using real MITRE ATT&CK technique IDs)
  INC-B: a smaller, lower-confidence single-host anomaly (mostly noise)

Everything else is unrelated single-source noise / false positives, so a
correlation engine actually has something to prove: it should compress
~N raw records down to a handful of real incidents.

Run: python3 generate_demo_data.py
Outputs: demo_alerts.json (all records, four different schemas, source-tagged)
         ground_truth.json (which record ids belong to which incident, for
         scoring/demo narration only — don't feed this to your pipeline)
"""
import json, random, datetime

random.seed(7)
BASE = datetime.datetime(2026, 9, 15, 8, 0, 0)

def ts(offset_min):
    return (BASE + datetime.timedelta(minutes=offset_min)).isoformat() + "Z"

records = []
ground_truth = {"INC-A": [], "INC-B": []}

def add(rec, incident=None):
    rec["_id"] = f"REC-{len(records)+1:04d}"
    records.append(rec)
    if incident:
        ground_truth[incident].append(rec["_id"])

# ---------- INC-A: multi-stage intrusion, real ATT&CK chain ----------
host, user, ip = "ENG-WKS17", "jsharma", "185.214.66.91"

add({"source": "threat_intel_report", "format": "text",
     "timestamp": ts(0),
     "text": f"Campaign report: infrastructure {ip} linked to a financially "
             f"motivated intrusion set observed targeting engineering "
             f"contractors via spear-phishing attachments.",
     "attack_id_hint": "T1566.001"}, "INC-A")

add({"source": "siem", "format": "json", "timestamp": ts(2),
     "event_type": "email_attachment_opened", "user": user, "host": host,
     "detail": "winword.exe opened attachment invoice_Q3.docm"}, "INC-A")

add({"source": "endpoint", "format": "json", "timestamp": ts(3),
     "host": host, "process": "powershell.exe", "parent_process": "winword.exe",
     "cmdline": "-enc JAB..."}, "INC-A")

add({"source": "network_sensor", "format": "json", "timestamp": ts(4),
     "src_ip": "10.10.20.14", "dst_ip": ip, "dst_port": 443,
     "protocol": "HTTPS", "host": host}, "INC-A")

add({"source": "endpoint", "format": "json", "timestamp": ts(9),
     "host": host, "process": "lsass_dump_tool.exe",
     "detail": "credential access attempt against lsass.exe"}, "INC-A")

add({"source": "siem", "format": "json", "timestamp": ts(14),
     "event_type": "remote_logon", "user": user,
     "src_host": host, "dst_host": "ENG-DB01", "protocol": "RDP", "dst_port": 3389,
     "detail": "unexpected interactive RDP logon using service account credentials"}, "INC-A")

add({"source": "threat_intel_report", "format": "text", "timestamp": ts(15),
     "text": f"IOC match: {ip} flagged in commercial reputation feed, "
             f"confidence high, category: C2 infrastructure.",
     "attack_id_hint": None}, "INC-A")

# ---------- INC-B: smaller, ambiguous, lower-confidence ----------
host_b = "FIN-LT22"
add({"source": "siem", "format": "json", "timestamp": ts(40),
     "event_type": "suspicious_login", "user": "kpatel", "host": host_b,
     "detail": "login from new geolocation"}, "INC-B")
add({"source": "endpoint", "format": "json", "timestamp": ts(41),
     "host": host_b, "process": "powershell.exe", "parent_process": "explorer.exe",
     "cmdline": "-Command Get-Process"}, "INC-B")

# ---------- Noise: unrelated single-source, low-signal events ----------
noise_users = ["rverma", "abasu", "sgowda", "tnair", "pmenon", "vshah"]
noise_hosts = [f"CORP-{i:03d}" for i in range(1, 25)]
for i in range(28):
    src = random.choice(["siem", "endpoint", "network_sensor"])
    if src == "siem":
        add({"source": "siem", "format": "json", "timestamp": ts(random.randint(-120, 300)),
             "event_type": random.choice(["password_reset", "vpn_connect", "file_download",
                                           "badge_swipe_anomaly", "antivirus_scan_clean"]),
             "user": random.choice(noise_users), "host": random.choice(noise_hosts)})
    elif src == "endpoint":
        add({"source": "endpoint", "format": "json", "timestamp": ts(random.randint(-120, 300)),
             "host": random.choice(noise_hosts),
             "process": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "excel.exe"]),
             "parent_process": "explorer.exe"})
    else:
        add({"source": "network_sensor", "format": "json", "timestamp": ts(random.randint(-120, 300)),
             "src_ip": f"10.10.{random.randint(1,30)}.{random.randint(2,254)}",
             "dst_ip": f"52.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
             "dst_port": random.choice([443, 80, 22, 3389]), "protocol": "TCP"})

random.shuffle(records)  # arrival order is not incident order — that's the point

with open("demo_alerts.json", "w") as f:
    json.dump(records, f, indent=2)
with open("ground_truth.json", "w") as f:
    json.dump(ground_truth, f, indent=2)

print(f"{len(records)} raw records generated -> demo_alerts.json")
print(f"2 seeded incidents (INC-A: {len(ground_truth['INC-A'])} records, "
      f"INC-B: {len(ground_truth['INC-B'])} records) -> ground_truth.json")
