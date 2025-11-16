# 🔒 Firewall Audit Tool

Outil d'audit professionnel pour analyser les règles de firewall et détecter les anomalies de configuration.

## 🎯 Fonctionnalités

Cet outil détecte automatiquement 4 types d'anomalies dans vos règles de firewall :

- **🔴 Règles cachées (Shadowed)** : Règles rendues inutiles par des règles de priorité supérieure
- **🟡 Règles redondantes (Redundant)** : Règles dupliquées ou identiques
- **🟠 Règles trop permissives (Permissive)** : Règles autorisant trop de trafic (any → any, ports sensibles ouverts, etc.)
- **⚪ Règles inutilisées (Unused)** : Règles jamais déclenchées (hit_count = 0)

## 📋 Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

## 🚀 Installation

### 1. Cloner ou télécharger le projet

```bash
cd firewall-audit-tool
```

### 2. (Recommandé) Créer un environnement virtuel

```bash
python3 -m venv venv
source venv/bin/activate  # Sur Linux/macOS
# ou
venv\Scripts\activate  # Sur Windows
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Rendre le script exécutable (Linux/macOS)

```bash
chmod +x firewall_audit.py
```

## 📝 Format des fichiers d'entrée

L'outil supporte deux formats : **CSV** et **JSON**.

### Format CSV

Le fichier CSV doit contenir les colonnes suivantes (avec en-tête) :

```csv
id,name,source,destination,port,protocol,action,priority,hit_count
1,Allow Web Traffic,*,192.168.1.100,80,tcp,allow,10,1523
2,Allow HTTPS,*,192.168.1.100,443,tcp,allow,20,2845
3,Block Telnet,*,*,23,tcp,deny,5,0
```

### Format JSON

Le fichier JSON doit contenir un objet avec une clé `rules` contenant un tableau de règles :

```json
{
  "rules": [
    {
      "id": "1",
      "name": "Allow Web Traffic",
      "source": "*",
      "destination": "192.168.1.100",
      "port": "80",
      "protocol": "tcp",
      "action": "allow",
      "priority": 10,
      "hit_count": 1523
    }
  ]
}
```

### Description des champs

| Champ | Description | Valeurs possibles |
|-------|-------------|-------------------|
| `id` | Identifiant unique de la règle | Chaîne ou nombre |
| `name` | Nom descriptif de la règle | Texte libre |
| `source` | Adresse IP/réseau source | IP, CIDR (ex: `10.0.0.0/8`), ou `*` pour any |
| `destination` | Adresse IP/réseau destination | IP, CIDR, ou `*` |
| `port` | Port ou plage de ports | Numéro, plage, ou `*` |
| `protocol` | Protocole réseau | `tcp`, `udp`, `icmp`, `any` |
| `action` | Action à effectuer | `allow` ou `deny` |
| `priority` | Ordre de priorité (plus petit = prioritaire) | Nombre entier |
| `hit_count` | Nombre de fois que la règle a été déclenchée | Nombre entier (≥ 0) |

## 🎮 Utilisation

### Syntaxe de base

```bash
python3 firewall_audit.py <fichier_entrée> [options]
```

### Options disponibles

| Option | Description | Défaut |
|--------|-------------|--------|
| `-o, --output-dir DIR` | Répertoire de sortie pour les rapports | `reports` |
| `-v, --verbose` | Afficher les détails de l'analyse | Désactivé |
| `--format FORMAT` | Format du rapport : `both`, `html`, ou `pdf` | `both` |
| `-h, --help` | Afficher l'aide | - |

### Exemples de commandes

#### 1. Analyse simple avec fichier CSV

```bash
python3 firewall_audit.py examples/rules_sample.csv
```

#### 2. Analyse avec fichier JSON et sortie personnalisée

```bash
python3 firewall_audit.py examples/rules_sample.json --output-dir ./my_reports
```

#### 3. Analyse en mode verbose (affiche les détails)

```bash
python3 firewall_audit.py examples/rules_sample.csv --verbose
```

#### 4. Générer uniquement un rapport HTML

```bash
python3 firewall_audit.py examples/rules_sample.csv --format html
```

#### 5. Commande complète avec toutes les options

```bash
python3 firewall_audit.py examples/rules_sample.json -o ./reports -v --format both
```

## 📊 Rapports générés

L'outil génère automatiquement des rapports professionnels au format **HTML** et **PDF** contenant :

- **Résumé exécutif** : Vue d'ensemble des anomalies détectées
- **Détails des anomalies** : Description complète de chaque problème avec les règles concernées
- **Tableau récapitulatif** : Liste complète de toutes les règles analysées

Les rapports sont enregistrés dans le répertoire spécifié (par défaut : `./reports/`) avec un timestamp :

```
reports/
├── firewall_audit_20250116_143052.html
└── firewall_audit_20250116_143052.pdf
```

## 📁 Structure du projet

```
firewall-audit-tool/
├── firewall_audit.py          # Script principal (CLI)
├── requirements.txt            # Dépendances Python
├── README.md                   # Documentation
├── modules/                    # Modules d'analyse
│   ├── __init__.py
│   ├── rule_parser.py          # Parsing des fichiers CSV/JSON
│   ├── anomaly_detector.py     # Détection des anomalies
│   └── report_generator.py     # Génération des rapports
├── examples/                   # Exemples de fichiers d'entrée
│   ├── rules_sample.csv
│   └── rules_sample.json
└── reports/                    # Rapports générés (créé automatiquement)
```

## 🧪 Tester l'outil

Des fichiers d'exemple sont fournis dans le dossier `examples/` :

```bash
# Test avec CSV
python3 firewall_audit.py examples/rules_sample.csv --verbose

# Test avec JSON
python3 firewall_audit.py examples/rules_sample.json --verbose
```

Ces fichiers contiennent volontairement des anomalies pour tester les capacités de détection.

## 🔍 Logique de détection

### Règles cachées (Shadowed)
Une règle est considérée comme "cachée" si une règle de priorité supérieure (numéro plus petit) couvre le même trafic. Par exemple :

```
Priorité 10: Allow 10.0.0.0/8 → 192.168.1.0/24 [any]
Priorité 50: Allow 10.0.1.5 → 192.168.1.100 [tcp:22]  ← Cachée !
```

La deuxième règle ne sera jamais appliquée car la première la couvre déjà.

### Règles redondantes
Deux règles sont redondantes si elles ont exactement les mêmes paramètres (source, destination, port, protocole, action).

### Règles trop permissives
Une règle est considérée comme trop permissive si :
- Elle autorise tout trafic (`source=*`, `destination=*`, `action=allow`)
- Elle ouvre des ports sensibles à tous (22, 23, 3389, 445, 3306, etc.)
- Elle autorise tous les protocoles depuis n'importe où

### Règles inutilisées
Une règle est inutilisée si son compteur d'utilisation (`hit_count`) est à 0.

## ⚙️ Dépendances

Les bibliothèques Python utilisées :

- **jinja2** : Génération des templates HTML
- **weasyprint** : Conversion HTML vers PDF
- **MarkupSafe** : Sécurité des templates

## 🐛 Dépannage

### Erreur : "ModuleNotFoundError: No module named 'xxx'"

```bash
# Réinstallez les dépendances
pip install -r requirements.txt
```

### Erreur : "Permission denied"

```bash
# Rendez le script exécutable (Linux/macOS)
chmod +x firewall_audit.py
```

### WeasyPrint ne fonctionne pas

WeasyPrint nécessite des dépendances système. Installez-les selon votre OS :

**Ubuntu/Debian :**
```bash
sudo apt-get install python3-pip python3-cffi python3-brotli libpango-1.0-0 libpangoft2-1.0-0
```

**macOS :**
```bash
brew install pango
```

**Windows :**
Téléchargez GTK3 depuis : https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer

## 📄 Licence

Ce projet est fourni à des fins éducatives et professionnelles.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir des issues ou proposer des améliorations.

## 📧 Support

Pour toute question ou problème, consultez la documentation ou ouvrez une issue sur le dépôt du projet.

---

**Développé avec ❤️ pour améliorer la sécurité des réseaux**
