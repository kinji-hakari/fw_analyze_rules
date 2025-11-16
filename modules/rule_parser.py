"""
Module de parsing des règles de firewall
Supporte les formats CSV et JSON
"""

import json
import csv
from typing import List, Dict


def parse_rules(file_path: str) -> List[Dict]:
    """
    Parse un fichier de règles firewall (CSV ou JSON)

    Args:
        file_path: Chemin vers le fichier de règles

    Returns:
        Liste de dictionnaires représentant les règles
    """
    if file_path.endswith('.json'):
        return parse_json_rules(file_path)
    elif file_path.endswith('.csv'):
        return parse_csv_rules(file_path)
    else:
        raise ValueError("Format de fichier non supporté. Utilisez CSV ou JSON.")


def parse_json_rules(file_path: str) -> List[Dict]:
    """Parse un fichier JSON contenant les règles"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if isinstance(data, list):
        rules = data
    elif isinstance(data, dict) and 'rules' in data:
        rules = data['rules']
    else:
        raise ValueError("Format JSON invalide. Attendu: liste de règles ou {'rules': [...]}")

    return normalize_rules(rules)


def parse_csv_rules(file_path: str) -> List[Dict]:
    """Parse un fichier CSV contenant les règles"""
    rules = []

    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)

    return normalize_rules(rules)


def normalize_rules(rules: List[Dict]) -> List[Dict]:
    """
    Normalise les règles pour assurer une structure cohérente

    Champs attendus:
    - id: identifiant unique
    - name: nom de la règle
    - source: adresse IP ou réseau source (ou '*' pour any)
    - destination: adresse IP ou réseau destination (ou '*' pour any)
    - port: port ou plage de ports (ou '*' pour any)
    - protocol: tcp, udp, icmp, any, etc.
    - action: allow ou deny
    - priority: ordre de priorité (nombre, plus petit = prioritaire)
    - hit_count: nombre de fois que la règle a été utilisée (optionnel)
    """
    normalized = []

    for i, rule in enumerate(rules):
        normalized_rule = {
            'id': rule.get('id', str(i + 1)),
            'name': rule.get('name', f'Rule {i + 1}'),
            'source': rule.get('source', '*').strip(),
            'destination': rule.get('destination', '*').strip(),
            'port': rule.get('port', '*').strip(),
            'protocol': rule.get('protocol', 'any').strip().lower(),
            'action': rule.get('action', 'allow').strip().lower(),
            'priority': int(rule.get('priority', i + 1)),
            'hit_count': int(rule.get('hit_count', 0))
        }

        if normalized_rule['source'] == '':
            normalized_rule['source'] = '*'
        if normalized_rule['destination'] == '':
            normalized_rule['destination'] = '*'
        if normalized_rule['port'] == '':
            normalized_rule['port'] = '*'

        normalized.append(normalized_rule)

    normalized.sort(key=lambda x: x['priority'])

    return normalized
