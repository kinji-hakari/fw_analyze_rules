"""
Module de détection des anomalies dans les règles de firewall
"""

from typing import List, Dict
import ipaddress


def detect_all_anomalies(rules: List[Dict], verbose: bool = False) -> Dict[str, List]:
    """
    Détecte toutes les anomalies dans les règles

    Args:
        rules: Liste des règles normalisées
        verbose: Afficher les détails de l'analyse

    Returns:
        Dictionnaire contenant les anomalies par type
    """
    anomalies = {
        'shadowed': detect_shadowed_rules(rules, verbose),
        'redundant': detect_redundant_rules(rules, verbose),
        'permissive': detect_permissive_rules(rules, verbose),
        'unused': detect_unused_rules(rules, verbose)
    }

    return anomalies


def detect_shadowed_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    """
    Détecte les règles cachées (shadowed)
    Une règle est cachée si une règle de priorité supérieure (plus petite)
    couvre le même trafic avec une action différente ou plus restrictive
    """
    shadowed = []

    for i, rule in enumerate(rules):
        for j, other_rule in enumerate(rules[:i]):
            if is_rule_shadowed(rule, other_rule):
                shadowed.append({
                    'rule': rule,
                    'shadowed_by': other_rule,
                    'description': (
                        f"Règle '{rule['name']}' (priorité {rule['priority']}) "
                        f"est cachée par '{other_rule['name']}' (priorité {other_rule['priority']})"
                    )
                })

                if verbose:
                    print(f"  ⚠️  Règle cachée détectée: {rule['name']} par {other_rule['name']}")

                break

    return shadowed


def is_rule_shadowed(rule: Dict, other_rule: Dict) -> bool:
    """
    Vérifie si une règle est cachée par une autre
    """
    if other_rule['priority'] >= rule['priority']:
        return False

    if not is_subset_or_equal(rule['source'], other_rule['source']):
        return False

    if not is_subset_or_equal(rule['destination'], other_rule['destination']):
        return False

    if not is_subset_or_equal(rule['port'], other_rule['port']):
        return False

    if not is_protocol_match(rule['protocol'], other_rule['protocol']):
        return False

    return True


def detect_redundant_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    """
    Détecte les règles redondantes (identiques ou quasi-identiques)
    """
    redundant = []
    seen = []

    for rule in rules:
        for seen_rule in seen:
            if are_rules_redundant(rule, seen_rule):
                redundant.append({
                    'rule': rule,
                    'duplicate_of': seen_rule,
                    'description': (
                        f"Règle '{rule['name']}' est redondante avec '{seen_rule['name']}'"
                    )
                })

                if verbose:
                    print(f"  ⚠️  Règle redondante détectée: {rule['name']}")

                break

        seen.append(rule)

    return redundant


def are_rules_redundant(rule1: Dict, rule2: Dict) -> bool:
    """
    Vérifie si deux règles sont redondantes
    """
    return (
        rule1['source'] == rule2['source'] and
        rule1['destination'] == rule2['destination'] and
        rule1['port'] == rule2['port'] and
        rule1['protocol'] == rule2['protocol'] and
        rule1['action'] == rule2['action']
    )


def detect_permissive_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    """
    Détecte les règles trop permissives
    - Source = any (*) et destination = any (*)
    - Ports sensibles ouverts à tous
    - Protocoles any avec action allow
    """
    permissive = []

    sensitive_ports = ['22', '23', '3389', '445', '139', '21', '3306', '5432', '1433']

    for rule in rules:
        issues = []

        if rule['action'] != 'allow':
            continue

        if rule['source'] == '*' and rule['destination'] == '*':
            issues.append("autorisant tout trafic (any → any)")

        if rule['source'] == '*' and rule['port'] in sensitive_ports:
            issues.append(f"port sensible {rule['port']} ouvert à tous")

        if rule['protocol'] == 'any' and rule['source'] == '*':
            issues.append("tous les protocoles autorisés depuis n'importe où")

        if rule['port'] == '*' and rule['source'] == '*':
            issues.append("tous les ports ouverts depuis n'importe où")

        if issues:
            permissive.append({
                'rule': rule,
                'issues': issues,
                'description': f"Règle '{rule['name']}' trop permissive: {', '.join(issues)}"
            })

            if verbose:
                print(f"  ⚠️  Règle permissive détectée: {rule['name']}")

    return permissive


def detect_unused_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    """
    Détecte les règles jamais utilisées (hit_count = 0)
    """
    unused = []

    for rule in rules:
        if rule['hit_count'] == 0:
            unused.append({
                'rule': rule,
                'description': f"Règle '{rule['name']}' jamais utilisée (0 hits)"
            })

            if verbose:
                print(f"  ⚠️  Règle inutilisée détectée: {rule['name']}")

    return unused


def is_subset_or_equal(value: str, superset: str) -> bool:
    """
    Vérifie si une valeur est un sous-ensemble ou égale à un superset
    Supporte les adresses IP, réseaux CIDR et wildcards
    """
    if superset == '*' or superset == 'any':
        return True

    if value == superset:
        return True

    if value == '*' or value == 'any':
        return False

    try:
        value_net = ipaddress.ip_network(value, strict=False)
        superset_net = ipaddress.ip_network(superset, strict=False)
        return value_net.subnet_of(superset_net) or value_net == superset_net
    except ValueError:
        return value == superset


def is_protocol_match(protocol: str, other_protocol: str) -> bool:
    """
    Vérifie si un protocole correspond à un autre
    """
    if other_protocol == 'any':
        return True

    return protocol == other_protocol or protocol == 'any'
