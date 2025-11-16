"""
Module de génération de rapports (HTML et PDF)
"""

import os
from datetime import datetime
from typing import List, Dict
from jinja2 import Template
from weasyprint import HTML


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit Firewall</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        header {
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }

        h1 {
            color: #2c3e50;
            font-size: 32px;
            margin-bottom: 10px;
        }

        .meta {
            color: #7f8c8d;
            font-size: 14px;
        }

        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }

        .summary-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }

        .summary-card.warning {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .summary-card.success {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .summary-card h3 {
            font-size: 14px;
            margin-bottom: 10px;
            opacity: 0.9;
        }

        .summary-card .number {
            font-size: 36px;
            font-weight: bold;
        }

        .section {
            margin: 40px 0;
        }

        h2 {
            color: #2c3e50;
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }

        .anomaly {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-left: 4px solid #e74c3c;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }

        .anomaly.shadowed {
            border-left-color: #e74c3c;
        }

        .anomaly.redundant {
            border-left-color: #f39c12;
        }

        .anomaly.permissive {
            border-left-color: #e67e22;
        }

        .anomaly.unused {
            border-left-color: #95a5a6;
        }

        .anomaly h3 {
            color: #2c3e50;
            font-size: 18px;
            margin-bottom: 10px;
        }

        .anomaly-description {
            color: #555;
            margin-bottom: 15px;
            font-size: 14px;
        }

        .rule-details {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }

        .rule-details dt {
            font-weight: bold;
            color: #2c3e50;
            display: inline-block;
            width: 120px;
        }

        .rule-details dd {
            display: inline;
            margin-left: 10px;
            color: #555;
        }

        .rule-details dd::after {
            content: "";
            display: block;
            margin-bottom: 8px;
        }

        .no-anomalies {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }

        th {
            background: #2c3e50;
            color: white;
            font-weight: 600;
        }

        tr:hover {
            background: #f8f9fa;
        }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }

        .badge.allow {
            background: #d4edda;
            color: #155724;
        }

        .badge.deny {
            background: #f8d7da;
            color: #721c24;
        }

        footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Rapport d'Audit Firewall</h1>
            <div class="meta">
                Généré le {{ timestamp }} | {{ total_rules }} règle(s) analysée(s)
            </div>
        </header>

        <div class="summary">
            <div class="summary-card {% if total_anomalies == 0 %}success{% else %}warning{% endif %}">
                <h3>Total Anomalies</h3>
                <div class="number">{{ total_anomalies }}</div>
            </div>
            <div class="summary-card shadowed">
                <h3>Règles Cachées</h3>
                <div class="number">{{ anomalies.shadowed|length }}</div>
            </div>
            <div class="summary-card redundant">
                <h3>Règles Redondantes</h3>
                <div class="number">{{ anomalies.redundant|length }}</div>
            </div>
            <div class="summary-card permissive">
                <h3>Règles Permissives</h3>
                <div class="number">{{ anomalies.permissive|length }}</div>
            </div>
            <div class="summary-card unused">
                <h3>Règles Inutilisées</h3>
                <div class="number">{{ anomalies.unused|length }}</div>
            </div>
        </div>

        {% if total_anomalies > 0 %}
            {% if anomalies.shadowed %}
            <div class="section">
                <h2>🔴 Règles Cachées (Shadowed)</h2>
                {% for item in anomalies.shadowed %}
                <div class="anomaly shadowed">
                    <h3>{{ item.rule.name }}</h3>
                    <div class="anomaly-description">
                        {{ item.description }}
                    </div>
                    <dl class="rule-details">
                        <dt>Source:</dt>
                        <dd>{{ item.rule.source }}</dd>
                        <dt>Destination:</dt>
                        <dd>{{ item.rule.destination }}</dd>
                        <dt>Port:</dt>
                        <dd>{{ item.rule.port }}</dd>
                        <dt>Protocole:</dt>
                        <dd>{{ item.rule.protocol }}</dd>
                        <dt>Action:</dt>
                        <dd><span class="badge {{ item.rule.action }}">{{ item.rule.action }}</span></dd>
                        <dt>Priorité:</dt>
                        <dd>{{ item.rule.priority }}</dd>
                    </dl>
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% if anomalies.redundant %}
            <div class="section">
                <h2>🟡 Règles Redondantes</h2>
                {% for item in anomalies.redundant %}
                <div class="anomaly redundant">
                    <h3>{{ item.rule.name }}</h3>
                    <div class="anomaly-description">
                        {{ item.description }}
                    </div>
                    <dl class="rule-details">
                        <dt>Source:</dt>
                        <dd>{{ item.rule.source }}</dd>
                        <dt>Destination:</dt>
                        <dd>{{ item.rule.destination }}</dd>
                        <dt>Port:</dt>
                        <dd>{{ item.rule.port }}</dd>
                        <dt>Protocole:</dt>
                        <dd>{{ item.rule.protocol }}</dd>
                        <dt>Action:</dt>
                        <dd><span class="badge {{ item.rule.action }}">{{ item.rule.action }}</span></dd>
                    </dl>
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% if anomalies.permissive %}
            <div class="section">
                <h2>🟠 Règles Trop Permissives</h2>
                {% for item in anomalies.permissive %}
                <div class="anomaly permissive">
                    <h3>{{ item.rule.name }}</h3>
                    <div class="anomaly-description">
                        {{ item.description }}
                    </div>
                    <dl class="rule-details">
                        <dt>Source:</dt>
                        <dd>{{ item.rule.source }}</dd>
                        <dt>Destination:</dt>
                        <dd>{{ item.rule.destination }}</dd>
                        <dt>Port:</dt>
                        <dd>{{ item.rule.port }}</dd>
                        <dt>Protocole:</dt>
                        <dd>{{ item.rule.protocol }}</dd>
                        <dt>Action:</dt>
                        <dd><span class="badge {{ item.rule.action }}">{{ item.rule.action }}</span></dd>
                    </dl>
                </div>
                {% endfor %}
            </div>
            {% endif %}

            {% if anomalies.unused %}
            <div class="section">
                <h2>⚪ Règles Inutilisées</h2>
                {% for item in anomalies.unused %}
                <div class="anomaly unused">
                    <h3>{{ item.rule.name }}</h3>
                    <div class="anomaly-description">
                        {{ item.description }}
                    </div>
                    <dl class="rule-details">
                        <dt>Source:</dt>
                        <dd>{{ item.rule.source }}</dd>
                        <dt>Destination:</dt>
                        <dd>{{ item.rule.destination }}</dd>
                        <dt>Port:</dt>
                        <dd>{{ item.rule.port }}</dd>
                        <dt>Hit Count:</dt>
                        <dd>{{ item.rule.hit_count }}</dd>
                    </dl>
                </div>
                {% endfor %}
            </div>
            {% endif %}
        {% else %}
            <div class="section">
                <div class="no-anomalies">
                    ✅ Aucune anomalie détectée ! Les règles de firewall semblent correctes.
                </div>
            </div>
        {% endif %}

        <div class="section">
            <h2>📋 Toutes les Règles</h2>
            <table>
                <thead>
                    <tr>
                        <th>Nom</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Port</th>
                        <th>Protocole</th>
                        <th>Action</th>
                        <th>Priorité</th>
                        <th>Hits</th>
                    </tr>
                </thead>
                <tbody>
                    {% for rule in rules %}
                    <tr>
                        <td>{{ rule.name }}</td>
                        <td>{{ rule.source }}</td>
                        <td>{{ rule.destination }}</td>
                        <td>{{ rule.port }}</td>
                        <td>{{ rule.protocol }}</td>
                        <td><span class="badge {{ rule.action }}">{{ rule.action }}</span></td>
                        <td>{{ rule.priority }}</td>
                        <td>{{ rule.hit_count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <footer>
            Généré par Firewall Audit Tool | {{ timestamp }}
        </footer>
    </div>
</body>
</html>
"""


def generate_reports(rules: List[Dict], anomalies: Dict[str, List],
                     output_dir: str, format_type: str = 'both') -> List[str]:
    """
    Génère les rapports d'audit au format HTML et/ou PDF

    Args:
        rules: Liste des règles analysées
        anomalies: Dictionnaire des anomalies détectées
        output_dir: Répertoire de sortie
        format_type: Type de format ('html', 'pdf', ou 'both')

    Returns:
        Liste des chemins des fichiers générés
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_anomalies = sum(len(v) for v in anomalies.values())

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        rules=rules,
        anomalies=anomalies,
        total_anomalies=total_anomalies,
        total_rules=len(rules),
        timestamp=timestamp
    )

    generated_files = []

    if format_type in ['html', 'both']:
        html_path = os.path.join(output_dir, f'firewall_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        generated_files.append(html_path)

    if format_type in ['pdf', 'both']:
        pdf_path = os.path.join(output_dir, f'firewall_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
        HTML(string=html_content).write_pdf(pdf_path)
        generated_files.append(pdf_path)

    return generated_files
