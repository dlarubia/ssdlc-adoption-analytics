import random
import names
import json


# CONST
REPOSITORIES = 500
BUSINESS_UNITS = 5
MAX_VULNERABILITIES = 200
MIN_VULNERABILITIES = 0
SEVERITIES_DISTRIBUTION = {
    "info": (0.4, 0.6), 
    "low": (0.3, 0.5), 
    "medium": (0.2, 0.4), 
    "high": (0.1, 0.3), 
    "critical": (0.01, 0.2)
}    

bus = [names.get_last_name() for _ in range(BUSINESS_UNITS)]

data = []
for i in range(REPOSITORIES):
    amount_vulnerabilities = random.randint(0, MAX_VULNERABILITIES)
    critical = random.randint(int(SEVERITIES_DISTRIBUTION["critical"][0]*amount_vulnerabilities), int(SEVERITIES_DISTRIBUTION["critical"][1]*amount_vulnerabilities))
    high = random.randint(int(SEVERITIES_DISTRIBUTION["high"][0]*amount_vulnerabilities), int(SEVERITIES_DISTRIBUTION["high"][1]*amount_vulnerabilities))
    medium = random.randint(int(SEVERITIES_DISTRIBUTION["medium"][0]*amount_vulnerabilities), int(SEVERITIES_DISTRIBUTION["medium"][1]*amount_vulnerabilities))
    low = random.randint(int(SEVERITIES_DISTRIBUTION["low"][0]*amount_vulnerabilities), int(SEVERITIES_DISTRIBUTION["low"][1]*amount_vulnerabilities))
    info = random.randint(int(SEVERITIES_DISTRIBUTION["info"][0]*amount_vulnerabilities), int(SEVERITIES_DISTRIBUTION["info"][1]*amount_vulnerabilities))
   
    repository_name = names.get_first_name()
    bu_name = bus[random.randint(0, BUSINESS_UNITS - 1)]
    
    data.append({
        "bu": bu_name,
        "repository": repository_name,
        "severity": "critical",
        "quantity": critical
    })

    data.append({
        "bu": bu_name,
        "repository": repository_name,
        "severity": "high",
        "quantity": high,
    })

    data.append({
        "bu": bu_name,
        "repository": repository_name,
        "severity": "medium",
        "quantity": medium,
    })

    data.append({
        "bu": bu_name,
        "repository": repository_name,
        "severity": "low",
        "quantity": low,
    })

    data.append({
        "bu": bu_name,
        "repository": repository_name,
        "severity": "info",
        "quantity": info,
    })
        

with open("data.json", "w", encoding="utf-8") as f:
    json.dump(data, f)
