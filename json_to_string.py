
def validate_input(json_data):
    valid_values = {
        "attackVector": ["N", "A", "L", "P"],
        "attackComplexity": ["L", "H"],
        "privilegesRequired": ["N", "L", "H"],
        "userInteraction": ["N", "R"],
        "scope": ["U", "C"],
        "confidentiality": ["N", "L", "H"],
        "integrity": ["N", "L", "H"],
        "availability": ["N", "L", "H"],
        "exploitCodeMaturity": ["X", "H", "F", "P", "U"],
        "remediationLevel": ["X", "O", "T", "W", "U"],
        "reportConfidence": ["X", "H", "R", "C", "U"],
        "confidentialityRequirement": ["X", "L", "M", "H"],
        "integrityRequirement": ["X", "L", "M", "H"],
        "availabilityRequirement": ["X", "L", "M", "H"],
        "modifiedAttackVector": ["X", "N", "A", "L", "P"],
        "modifiedAttackComplexity": ["X", "L", "H"],
        "modifiedPrivilegesRequired": ["X", "N", "L", "H"],
        "modifiedUserInteraction": ["X", "N", "R"],
        "modifiedScope": ["X", "U", "C"],
        "modifiedConfidentiality": ["X", "N", "L", "H"],
        "modifiedIntegrity": ["X", "N", "L", "H"],
        "modifiedAvailability": ["X", "N", "L", "H"]
    }

    for key, value in json_data.items():
        if key not in valid_values:
            raise ValueError(f"Invalid key: {key}")

        if value not in valid_values[key]:
            raise ValueError(f"Invalid value for {key}: {value}")


def json_to_cvss_string(json_data):
    try:
        validate_input(json_data)
    except ValueError as e:
        raise ValueError(e)

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
