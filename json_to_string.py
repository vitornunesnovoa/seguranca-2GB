import json

    
def json_to_cvss_string(json_data):
    mapping = {
        "attackVector": "AV",
        "attackComplexity": "AC",
        "privilegesRequired": "PR",
        "userInteraction": "UI",
        "scope": "S",
        "confidentiality": "C",
        "integrity": "I",
        "availability": "A",
        "exploitCodeMaturity": "E",
        "remediationLevel": "RL",
        "reportConfidence": "RC",
        "confidentialityRequirement": "CR",
        "integrityRequirement": "IR",
        "availabilityRequirement": "AR",
        "modifiedAttackVector": "MAV",
        "modifiedAttackComplexity": "MAC",
        "modifiedPrivilegesRequired": "MPR",
        "modifiedUserInteraction": "MUI",
        "modifiedScope": "MS",
        "modifiedConfidentiality": "MC",
        "modifiedIntegrity": "MI",
        "modifiedAvailability": "MA"
    }

    cvss_string = "CVSS:3.0/"
    
    for key, value in json_data.items():
        key_prefix = mapping.get(key)
        if key_prefix and value:
            cvss_string += f"{key_prefix}:{value}/"
    
    return cvss_string.rstrip("/")