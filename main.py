import datetime

print("AI Multi-Cloud Cyber Defence")
print("AWS & Azure Security Monitor")
print("System started:", datetime.datetime.now())

import json

with open("cloud_logs.json", "r") as f:
    logs = json.load(f)

for log in logs:
    if log["status"] in ["FAILED", "DENIED"]:
        print("SECURITY ALERT:", log)
    else:
        print("NORMAL:", log)

aws_alerts = 0
azure_alerts = 0

for log in logs:
    if log["status"] in ["FAILED", "DENIED"]:
        if log["cloud"] == "AWS":
            aws_alerts += 1
        elif log["cloud"] == "Azure":
            azure_alerts += 1
print("\n--- Threat Report ---")
print("AWS Alerts:", aws_alerts)
print("Azure Alrets:", azure_alerts)

risk_score = 0

for log in logs:
    if log["status"] == "FAILED":
        risk_score += 30
    elif log["status"] == "DENIED":
        risk_score += 50

risk_score = min(risk_score, 100)

if risk_score >= 80:
    level = "CRITICAL"
elif risk_score >= 60:
    level = "HIGH"
elif risk_score >= 30:
    level ="MIDIUM"
else:
    level = "LOW"

print("\n--- Risk Analysis ---")
print("Risk Score:", risk_score)
print("Threat Level:", level)

print("\n--- Cross-Cloud Analysis ---")

if aws_alerts > 0 and azure_alerts > 0:
    print("WARING: Multi-Cloud Threat")
    print("AWS and Azure anomalies detected")
    print("Further investigation required")
else:
    print("No multi-cloud threat detected")

print("\n--- Attack Correlation ---")

for a in logs:
    for b in logs:
        if a["cloud"] == "Azure" and b["cloud"] == "AWS":
            if a["ip"] == b["ip"] and a["user"] == b["user"]:
               if a["status"] == "FAILED" and b["status"] == "DENIED":
                  print("CRITICAL: Correlated Threat")
                  print("Source: ip:", a["ip"])
                  print("Target User:", a["user"])
                  print("Attack Path: Azure -> AWS")

print("\n--- Time Correlation ---")

for a in logs:
    for b in logs:
        if a["cloud"] == "Azure" and b["cloud"] == "AWS":
           if a["ip"] == b["ip"] and a["user"] == b["user"]:
              if a["status"] == "FAILED" and b["status"] == "DENIED":
                 t1 = datetime.datetime.strptime(a["time"], "%H:%M:%S")
                 t2 = datetime.datetime.strptime(b["time"], "%H:%M:%S")

                 gap = (t2 - t1).total_seconds()

                 if 0 <= gap <= 300:
                    print("ALERT: Possible Attack Chain")
                    print("Time Gap:", gap, "seconds")
                    print("Attack Path: Azure -> AWS")

                    print("Detection Reasons:")
                    print("- Matching IP address")
                    print("- Matching user ID")
                    print("- Failed Azure login")
                    print("- AWS access denied")
                    print("- Events within 5 minutes")

                    

                