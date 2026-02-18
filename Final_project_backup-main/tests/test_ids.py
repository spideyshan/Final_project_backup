from src.detection import SimpleIDS

def test_port_scan_detection():
    ids = SimpleIDS()

    # simulate connections from attacker
    ip = "192.168.1.10"
    alerts = []

    for port in [22, 80, 443, 8080, 3306]:  # common ports
        alert = ids.detect(ip, port)
        if alert:
            alerts.append(alert)

    # The last connection should trigger the alert
    assert "[ALERT]" in alerts[-1]

