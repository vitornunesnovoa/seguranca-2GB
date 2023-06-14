
def validate_input(json_data):
    # Dicionário que contém os valores válidos para cada chave do JSON
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
    # Verifica se as chaves e valores do JSON estão de acordo com os valores válidos
    for key, value in json_data.items():
        if key not in valid_values:
            raise ValueError(f"Invalid key: {key}")

        if value not in valid_values[key]:
            raise ValueError(f"Invalid value for {key}: {value}")


def json_to_cvss_string(json_data):
    try:
        # Chama a função validate_input() para validar o JSON
        validate_input(json_data)
    except ValueError as e:
        raise ValueError(e)
    # Chama a função validate_input() para validar o JSON
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
    # Cria a string CVSS inicial com a versão 3.0
    cvss_string = "CVSS:3.0/"
    # Itera sobre as chaves e valores do JSON
    for key, value in json_data.items():
        key_prefix = mapping.get(key)
        # Verifica se a chave possui um prefixo mapeado e se o valor não é vazio
        if key_prefix and value:
            # Adiciona o prefixo e valor à string CVSS
            cvss_string += f"{key_prefix}:{value}/"
    # Adiciona o prefixo e valor à string CVSS
    return cvss_string.rstrip("/")
