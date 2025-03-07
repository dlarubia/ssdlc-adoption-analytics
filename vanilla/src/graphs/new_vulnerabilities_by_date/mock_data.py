import json
import random
import names
import numpy as np
from datetime import datetime

def convert_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')

print(convert_timestamp(1609459200))

# Configurações
NUM_BUS = 5  # Número de BUs
NUM_REPOS = 300  # Número total de repositórios
NUM_VULNS = 4000  # Número total de vulnerabilidades

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CRITICALITY_VALUES = [0, 1, 2, 3, None]

# Geração das BUs
bus = [names.get_last_name() for _ in range(NUM_BUS)]

# Distribuição dos repositórios entre as BUs
repo_distribution = np.random.multinomial(NUM_REPOS, [1/NUM_BUS] * NUM_BUS)
repos_by_bu = {}
repo_list = []

for i, count in enumerate(repo_distribution):
    repos = [names.get_first_name() for _ in range(count)]
    repos_by_bu[bus[i]] = repos
    repo_list.extend([(bus[i], repo) for repo in repos])

# Gerar vulnerabilidades respeitando os limites
vulnerabilities = []
for _ in range(NUM_VULNS):
    bu, repo = random.choice(repo_list)
    severity = random.choices(SEVERITIES, weights=[0.05, 0.1, 0.2, 0.4, 0.25])[0]  # Lognormal-like distribution
    quantity = int(np.random.lognormal(mean=2, sigma=1))  # Lognormal distribution
    quantity = max(1, quantity)  # Garantir que seja pelo menos 1
    criticality = random.choice(CRITICALITY_VALUES)
    date = convert_timestamp(random.randint(1609459200, 1672444800))

    vulnerabilities.append({
        "date": date,  # Timestamp entre 2021 e 2023
        "bu": bu,
        "repository": repo,
        "criticality": criticality,
        "severity": severity,
        "quantity": quantity
    })

# Salvar no arquivo JSON
with open("data.json", "w") as f:
    json.dump(vulnerabilities, f, indent=4)

print("Arquivo 'data.json' gerado com sucesso!")
