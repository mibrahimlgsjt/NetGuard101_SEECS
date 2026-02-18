import random
import datetime

def generate_mock_log():
    """Generate a mock security log entry matching the app's log schema.
    Returns a dict with keys: timestamp, event_type, source, ip, reason.
    """
    event_type = random.choice(["PACKET_ANALYSIS", "RULE_BLOCK", "IPS_DETECTION"])
    source = random.choice(["simulation", "live"])
    ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    reason = random.choice([
        "Suspicious payload detected",
        "Port scan detected",
        "Malware signature match",
        "Anomaly in traffic volume",
        "Blocked by firewall rule"
    ])
    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "event_type": event_type,
        "source": source,
        "ip": ip,
        "reason": reason,
    }

def generate_mock_threat():
    """Generate a mock threat entry for the cloud threat feed.
    Returns a dict with keys: id, ip, severity, description.
    """
    severity = random.choice(["low", "medium", "high", "critical"])
    ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    description = random.choice([
        "Botnet command and control server",
        "Phishing site hosting",
        "Known malicious IP",
        "DDoS source",
        "Credential stuffing source"
    ])
    return {
        "id": random.randint(1000, 9999),
        "ip": ip,
        "severity": severity,
        "description": description,
    }
