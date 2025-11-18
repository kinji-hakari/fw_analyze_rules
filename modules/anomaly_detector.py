"""
Module de détection des anomalies dans les règles de firewall.
Améliorations :
- Shadowing stricte (priorité plus haute + action différente + couverture complète)
- Redondance : doublon exact vs inclusion, en évitant les règles trop génériques
- Règles permissives avec criticité
- Services non sécurisés
- Règles de généralisation (parapluie)
- Vue corrélée des anomalies
"""

from typing import List, Dict, Tuple, Iterable
import ipaddress

UNSAFE_SERVICES = {
    "21": "FTP non chiffré",
    "23": "Telnet en clair",
    "80": "HTTP non chiffré",
    "139": "NetBIOS",
    "445": "SMB",
    "3306": "MySQL",
    "3389": "RDP",
    "5900": "VNC",
}

SEVERITY_LABEL = {
    "high": "🔥 Haute",
    "medium": "⚠️ Moyenne",
    "low": "🟦 Faible",
}


def detect_all_anomalies(rules: List[Dict], verbose: bool = False) -> Dict[str, List]:
    """
    Orchestration de la détection.
    """
    shadowed = detect_shadowed_rules(rules, verbose)
    redundant = detect_redundant_rules(rules, verbose)
    permissive = detect_permissive_rules(rules, verbose)
    unused = detect_unused_rules(rules, verbose)
    unsafe_services = detect_unsafe_services(rules, verbose)
    generalized = detect_generalized_rules(rules, verbose)

    anomalies = {
        "shadowed": shadowed,
        "redundant": redundant,
        "permissive": permissive,
        "unused": unused,
        "unsafe_services": unsafe_services,
        "generalized": generalized,
    }

    anomalies["correlated"] = build_correlation(rules, anomalies)
    anomalies["severity_counts"] = count_severities(anomalies)
    return anomalies


# -----------------------------
# Helpers de couverture
# -----------------------------
def parse_ports(port_str: str) -> List[Tuple[int, int]]:
    """Retourne une liste d'intervalles (start, end). '*' ou 'any' couvrent tout 1-65535."""
    if port_str in ("*", "any", ""):
        return [(1, 65535)]
    parts: Iterable[str] = (p.strip() for p in port_str.split(","))
    ranges = []
    for part in parts:
        if "-" in part:
            start, end = part.split("-", 1)
            ranges.append((int(start), int(end)))
        else:
            num = int(part)
            ranges.append((num, num))
    return ranges


def is_port_subset(port_a: str, port_b: str) -> bool:
    """True si port_a est inclus dans port_b (gestion plage et liste)."""
    a_ranges = parse_ports(port_a)
    b_ranges = parse_ports(port_b)
    for a_start, a_end in a_ranges:
        covered = any(a_start >= b_start and a_end <= b_end for b_start, b_end in b_ranges)
        if not covered:
            return False
    return True


def is_ip_subset(value: str, superset: str) -> bool:
    """Gère IP/CIDR/*/any."""
    if superset in ("*", "any"):
        return True
    if value in ("*", "any"):
        return False
    if value == superset:
        return True
    try:
        return ipaddress.ip_network(value, strict=False).subnet_of(
            ipaddress.ip_network(superset, strict=False)
        )
    except ValueError:
        return value == superset


def is_protocol_subset(proto: str, superset_proto: str) -> bool:
    if superset_proto == "any":
        return True
    if proto == "any":
        return False
    return proto == superset_proto


def traffic_subset(rule_a: Dict, rule_b: Dict) -> bool:
    """True si le trafic de rule_a est inclus dans rule_b (source/dest/port/proto)."""
    return (
        is_ip_subset(rule_a["source"], rule_b["source"])
        and is_ip_subset(rule_a["destination"], rule_b["destination"])
        and is_port_subset(rule_a["port"], rule_b["port"])
        and is_protocol_subset(rule_a["protocol"], rule_b["protocol"])
    )


def is_overly_generic(rule: Dict) -> bool:
    """Règle trop générique: any sur source/dest/port ou protocole any."""
    return (
        rule["source"] in ("*", "any")
        or rule["destination"] in ("*", "any")
        or rule["port"] in ("*", "any")
        or rule["protocol"] == "any"
    )


def highest_severity(severities: List[str]) -> str:
    order = {"high": 3, "medium": 2, "low": 1}
    if not severities:
        return "low"
    return max(severities, key=lambda s: order.get(s, 0))


def max_severity(a: str, b: str) -> str:
    return highest_severity([a, b])


# -----------------------------
# Shadowed
# -----------------------------
def detect_shadowed_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    shadowed = []
    for i, rule in enumerate(rules):
        for other_rule in rules[:i]:
            if other_rule["priority"] >= rule["priority"]:
                continue
            if rule["action"] == other_rule["action"]:
                continue
            if traffic_subset(rule, other_rule):
                item = {
                    "rule": rule,
                    "by_rule": other_rule,
                    "description": (
                        f"La règle #{rule['id']} '{rule['name']}' (prio {rule['priority']}, {rule['action']}) "
                        f"est cachée par la règle #{other_rule['id']} '{other_rule['name']}' "
                        f"(prio {other_rule['priority']}, {other_rule['action']})."
                    ),
                    "impact": "Trafic bloqué ou autorisé avant d’atteindre la règle (conflit allow/deny).",
                    "recommendation": "Supprimer ou déplacer la règle masquée, ou aligner les actions.",
                    "severity": "high",
                }
                shadowed.append(item)
                if verbose:
                    print(f"[shadowed] {item['description']}")
                break
    return shadowed


# -----------------------------
# Redundant
# -----------------------------
def detect_redundant_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    redundant = []
    for i, rule in enumerate(rules):
        for other_rule in rules[i + 1 :]:
            if rule["action"] != other_rule["action"]:
                continue
            # doublon exact
            if traffic_subset(rule, other_rule) and traffic_subset(other_rule, rule):
                redundant.append(
                    {
                        "rule": other_rule,
                        "reference": rule,
                        "kind": "duplicate",
                        "description": (
                            f"Règle #{other_rule['id']} '{other_rule['name']}' est un doublon exact "
                            f"de la règle #{rule['id']} '{rule['name']}'."
                        ),
                        "impact": "Complexité inutile, aucun effet fonctionnel.",
                        "recommendation": "Supprimer le doublon et conserver une seule règle.",
                        "severity": "low",
                    }
                )
                if verbose:
                    print(f"[redundant-duplicate] {redundant[-1]['description']}")
                continue

            # subset redondant : la règle other_rule est incluse dans rule
            if traffic_subset(other_rule, rule) and not is_overly_generic(rule):
                redundant.append(
                    {
                        "rule": other_rule,
                        "reference": rule,
                        "kind": "subset",
                        "description": (
                            f"Règle #{other_rule['id']} '{other_rule['name']}' est incluse "
                            f"dans la règle #{rule['id']} '{rule['name']}'."
                        ),
                        "impact": "Règle spécifique probablement inutile car déjà couverte.",
                        "recommendation": "Supprimer ou restreindre la règle incluse pour clarifier la policy.",
                        "severity": "low",
                    }
                )
                if verbose:
                    print(f"[redundant-subset] {redundant[-1]['description']}")
    return redundant


# -----------------------------
# Permissive
# -----------------------------
def detect_permissive_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    permissive = []
    sensitive_ports = {"22", "23", "3389", "445", "139", "21", "3306", "5432", "1433"}

    for rule in rules:
        if rule["action"] != "allow":
            continue

        issues = []
        severity = "low"

        if rule["source"] == "*" and rule["destination"] == "*":
            issues.append("Autorise tout trafic (any vers any).")
            severity = "high"

        if rule["source"] == "*" and rule["port"] in sensitive_ports:
            issues.append(f"Port sensible {rule['port']} ouvert à tous.")
            severity = max_severity(severity, "medium")

        if rule["protocol"] == "any" and rule["source"] == "*":
            issues.append("Tous les protocoles autorisés depuis n'importe où.")
            severity = max_severity(severity, "medium")

        if rule["port"] == "*" and rule["source"] == "*":
            issues.append("Tous les ports ouverts depuis n'importe où.")
            severity = max_severity(severity, "medium")

        if issues:
            item = {
                "rule": rule,
                "issues": issues,
                "description": f"Règle #{rule['id']} '{rule['name']}' trop permissive.",
                "impact": "Surface d'attaque élargie et exposition non contrôlée.",
                "recommendation": "Restreindre source/destination/port/protocole ou segmenter par zone.",
                "severity": severity,
            }
            permissive.append(item)
            if verbose:
                print(f"[permissive] {item['description']}")
    return permissive


# -----------------------------
# Services non sécurisés
# -----------------------------
def detect_unsafe_services(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    findings = []
    for rule in rules:
        if rule["action"] != "allow":
            continue
        for port, service in UNSAFE_SERVICES.items():
            if is_port_subset(port, rule["port"]) or is_port_subset(rule["port"], port):
                severity = "high" if rule["source"] in ("*", "any") else "medium"
                item = {
                    "rule": rule,
                    "service": service,
                    "description": (
                        f"Règle #{rule['id']} '{rule['name']}' autorise le service non sécurisé "
                        f"{service} (port {port})."
                    ),
                    "impact": "Trafic non chiffré ou vulnérable (brute force, exfiltration, pivot).",
                    "recommendation": "Utiliser l'équivalent chiffré ou restreindre les IP sources/VLANs.",
                    "severity": severity,
                }
                findings.append(item)
                if verbose:
                    print(f"[unsafe] {item['description']}")
                break
    return findings


# -----------------------------
# Unused
# -----------------------------
def detect_unused_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    unused = []
    for rule in rules:
        if rule.get("hit_count", 0) == 0:
            item = {
                "rule": rule,
                "description": f"Règle #{rule['id']} '{rule['name']}' jamais utilisée (0 hits).",
                "impact": "Complexité inutile, risque d’obsolescence.",
                "recommendation": "Valider le besoin ; sinon, archiver ou supprimer.",
                "severity": "low",
            }
            unused.append(item)
            if verbose:
                print(f"[unused] {item['description']}")
    return unused


# -----------------------------
# Règles de généralisation
# -----------------------------
def detect_generalized_rules(rules: List[Dict], verbose: bool = False) -> List[Dict]:
    generalized = []
    for rule in rules:
        covered = []
        for other in rules:
            if other is rule:
                continue
            if rule["action"] != other["action"]:
                continue
            if traffic_subset(other, rule) and not traffic_subset(rule, other):
                covered.append(other)
        if covered:
            severity = "medium" if not is_overly_generic(rule) else "high"
            generalized.append(
                {
                    "rule": rule,
                    "covered_rules": covered,
                    "count": len(covered),
                    "description": (
                        f"Règle #{rule['id']} '{rule['name']}' couvre {len(covered)} règle(s) plus spécifiques."
                    ),
                    "impact": "Règle parapluie qui peut masquer des erreurs ou rendre l’analyse difficile.",
                    "recommendation": "Restreindre son périmètre ou la déplacer plus bas dans la policy.",
                    "severity": severity,
                }
            )
            if verbose:
                print(f"[generalized] {generalized[-1]['description']}")
    return generalized


# -----------------------------
# Corrélation et criticité
# -----------------------------
def build_correlation(rules: List[Dict], anomalies: Dict[str, List]) -> List[Dict]:
    corr_map: Dict[str, Dict] = {
        rule["id"]: {"rule": rule, "tags": [], "severities": []} for rule in rules
    }

    for key, items in anomalies.items():
        if key in ("correlated", "severity_counts"):
            continue
        for item in items:
            rule_id = item["rule"]["id"]
            corr_map[rule_id]["tags"].append(key)
            corr_map[rule_id]["severities"].append(item.get("severity", "low"))
            # lier les autres règles impliquées
            for linked in ("by_rule", "reference"):
                if linked in item:
                    lr = item[linked]
                    corr_map[lr["id"]]["tags"].append(key)
                    corr_map[lr["id"]]["severities"].append(item.get("severity", "low"))
            if "covered_rules" in item:
                for cr in item["covered_rules"]:
                    corr_map[cr["id"]]["tags"].append("covered")
                    corr_map[cr["id"]]["severities"].append(item.get("severity", "low"))

    correlated = []
    for value in corr_map.values():
        tags = sorted(set(value["tags"]))
        sev = highest_severity(value["severities"]) if value["severities"] else None
        correlated.append({"rule": value["rule"], "tags": tags, "severity": sev})
    return correlated


def count_severities(anomalies: Dict[str, List]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for key, items in anomalies.items():
        if key in ("correlated", "severity_counts"):
            continue
        for item in items:
            sev = item.get("severity", "low")
            if sev in counts:
                counts[sev] += 1
    return counts
