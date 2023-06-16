Essa é uma API desenvolvida em Python que realiza cálculos das CVSS. Ela recebe um JSON de entrada contendo os valores das métricas e retorna um JSON de saída com as métricas calculadas.

Observações:

- Possui validações no JSON de entrada para garantir a integridade dos parametros;
- Possuir a linguagem Python instalada na máquina para que seja possível utilizar a aplicação;
- Possuir o VS Code ou similar para abrir a aplicação.

Modo de usar:  
- Clonar o repositório;  
- Abrir a aplicação;  
- Executar um terminal na da pasta seguranca-2GB e caso não esteja navegar até o caminho;  
- Digitar o comando para instalar as dependências necessárias: "pip install cvss flask pyopenssl".  
- Digitar o comando para subir a aplicação: "python cvss_api.py".

Requisição exemplo:  
````json
{
  "attackVector": "A",  
  "attackComplexity": "H",  
  "privilegesRequired": "L",  
  "userInteraction": "R",  
  "scope": "C",  
  "confidentiality": "L",  
  "integrity": "L",  
  "availability": "L",  
  "exploitCodeMaturity": "H",  
  "remediationLevel": "W",  
  "reportConfidence": "X",  
  "confidentialityRequirement": "X",  
  "integrityRequirement": "X",  
  "availabilityRequirement": "X",  
  "modifiedAttackVector": "X",  
  "modifiedAttackComplexity": "X",  
  "modifiedPrivilegesRequired": "X", 
  "modifiedUserInteraction": "X",  
  "modifiedScope": "X",  
  "modifiedConfidentiality": "X",  
  "modifiedIntegrity": "X",  
  "modifiedAvailability": "X"  
}
````

Resposta exemplo:
````json
{
    "base_score": 5.1,  
    "base_severity": "Medium",  
    "environmental_score": 5.0,  
    "environmental_severity": "Medium",  
    "temporal_score": 5.0,  
    "temporal_severity": "Medium"  
}
````  

Parâmetros aceitos no JSON de entrada conforme o campo:
````json
{
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
````
