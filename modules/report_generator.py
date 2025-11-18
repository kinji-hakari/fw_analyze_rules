"""
Module de génération de rapports (HTML et PDF).
Nouveau template : sommaire, badges de criticité, sections détaillées,
vue corrélée, services non sécurisés, règles de généralisation.
"""

import os
from datetime import datetime
from typing import List, Dict
from jinja2 import Template
from weasyprint import HTML

# Libellés de criticité utilisés dans les badges. Duplication légère pour
# éviter une dépendance directe vers anomaly_detector (pas de cycle).
SEVERITY_LABEL = {
    "high": "🔥 Haute",
    "medium": "⚠️ Moyenne",
    "low": "🟦 Faible",
}

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit Firewall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Roboto, Arial, sans-serif; line-height: 1.6; color: #2c3e50; background: #f5f7fb; padding: 24px; }
        .container { max-width: 1250px; margin: 0 auto; background: #fff; padding: 32px; border-radius: 10px; box-shadow: 0 6px 18px rgba(0,0,0,0.08); }
        header { border-bottom: 3px solid #34495e; padding-bottom: 16px; margin-bottom: 24px; }
        h1 { font-size: 32px; margin-bottom: 6px; }
        h2 { font-size: 24px; margin: 22px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #ecf0f1; }
        h3 { font-size: 18px; margin-bottom: 8px; }
        .meta { color: #7f8c8d; font-size: 13px; }
        a { color: #2980b9; text-decoration: none; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr)); gap: 12px; margin: 16px 0 24px; }
        .card { border-radius: 8px; padding: 16px; color: #fff; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
        .c1 { background: linear-gradient(135deg, #667eea, #764ba2); }
        .c2 { background: linear-gradient(135deg, #f093fb, #f5576c); }
        .c3 { background: linear-gradient(135deg, #f6d365, #fda085); color: #473c2d; }
        .c4 { background: linear-gradient(135deg, #4facfe, #00f2fe); }
        .c5 { background: linear-gradient(135deg, #96fbc4, #f9f586); color: #1d3c34; }
        .card .label { font-size: 13px; opacity: 0.9; }
        .card .number { font-size: 32px; font-weight: 700; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
        .badge.allow { background: #e8f7ee; color: #27ae60; }
        .badge.deny { background: #fdecea; color: #c0392b; }
        .badge-sev { padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; }
        .sev-high { background: #fdecea; color: #c0392b; }
        .sev-medium { background: #fff4e5; color: #d35400; }
        .sev-low { background: #ecf5ff; color: #2980b9; }
        .anomaly { border: 1px solid #e1e8f5; border-left: 5px solid #e74c3c; padding: 18px; border-radius: 8px; background: #fff; box-shadow: 0 2px 8px rgba(0,0,0,0.04); margin-bottom: 14px; }
        .anomaly.redundant { border-left-color: #f39c12; }
        .anomaly.permissive { border-left-color: #e67e22; }
        .anomaly.unused { border-left-color: #95a5a6; }
        .anomaly.unsafe { border-left-color: #c0392b; }
        .anomaly.generalized { border-left-color: #8e44ad; }
        .anomaly-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
        .anomaly-type { font-weight: 700; color: #7f8c8d; font-size: 13px; }
        .anomaly-desc { margin: 8px 0; }
        .rule-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin-top: 10px; }
        .rule-box { border: 1px solid #ecf0f1; border-radius: 6px; padding: 10px 12px; background: #fbfcff; }
        dl { display: grid; grid-template-columns: 120px 1fr; row-gap: 6px; column-gap: 8px; font-size: 13px; }
        dt { font-weight: 700; color: #7f8c8d; }
        dd { margin: 0; }
        .summary-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .summary-table th, .summary-table td { border: 1px solid #e1e8f5; padding: 8px; text-align: left; font-size: 13px; }
        .toc { background: #f0f4ff; border: 1px solid #d6e2ff; padding: 12px; border-radius: 8px; margin: 12px 0 20px; }
        .toc a { display: inline-block; margin-right: 10px; font-size: 14px; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { border: 1px solid #e1e8f5; padding: 10px; text-align: left; font-size: 14px; }
        th { background: #f5f7fb; }
        footer { margin-top: 24px; font-size: 12px; color: #7f8c8d; text-align: center; }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Rapport d'Audit Firewall</h1>
        <div class="meta">Généré le {{ timestamp }} – Total règles: {{ total_rules }} – Total anomalies: {{ total_anomalies }}</div>
    </header>

    <div class="toc">
        <a href="#shadowed">🛑 Règles cachées</a>
        <a href="#redundant">🟡 Règles redondantes</a>
        <a href="#permissive">🟠 Règles permissives</a>
        <a href="#unused">⚪ Règles inutilisées</a>
        <a href="#unsafe">🧪 Services non sécurisés</a>
        <a href="#generalized">🧭 Règles de généralisation</a>
        <a href="#correlated">🧩 Vue corrélée</a>
        <a href="#allrules">📋 Toutes les règles</a>
    </div>

    <div class="summary-grid">
        <div class="card c1">
            <div class="label">Toutes anomalies</div>
            <div class="number">{{ total_anomalies }}</div>
        </div>
        <div class="card c2">
            <div class="label">Shadowed</div>
            <div class="number">{{ anomalies.shadowed|length }}</div>
        </div>
        <div class="card c3">
            <div class="label">Redondantes</div>
            <div class="number">{{ anomalies.redundant|length }}</div>
        </div>
        <div class="card c4">
            <div class="label">Permissives</div>
            <div class="number">{{ anomalies.permissive|length }}</div>
        </div>
        <div class="card c4">
            <div class="label">Services non sécurisés</div>
            <div class="number">{{ anomalies.unsafe_services|length }}</div>
        </div>
        <div class="card c5">
            <div class="label">Inutilisées</div>
            <div class="number">{{ anomalies.unused|length }}</div>
        </div>
    </div>

    <table class="summary-table">
        <thead><tr><th>Criticité</th><th>Nombre</th></tr></thead>
        <tbody>
            <tr><td>🔥 Haute</td><td>{{ anomalies.severity_counts.high }}</td></tr>
            <tr><td>⚠️ Moyenne</td><td>{{ anomalies.severity_counts.medium }}</td></tr>
            <tr><td>🟦 Faible</td><td>{{ anomalies.severity_counts.low }}</td></tr>
        </tbody>
    </table>

    {% macro rule_box(title, rule) -%}
    <div class="rule-box">
        <h4>{{ title }}</h4>
        <dl>
            <dt>ID / Nom</dt><dd>#{{ rule.id }} – {{ rule.name }}</dd>
            <dt>Source</dt><dd>{{ rule.source }}</dd>
            <dt>Destination</dt><dd>{{ rule.destination }}</dd>
            <dt>Port</dt><dd>{{ rule.port }}</dd>
            <dt>Protocole</dt><dd>{{ rule.protocol }}</dd>
            <dt>Action</dt><dd><span class="badge {{ rule.action }}">{{ rule.action }}</span></dd>
            <dt>Priorité</dt><dd>{{ rule.priority }}</dd>
            <dt>Hit Count</dt><dd>{{ rule.hit_count }}</dd>
        </dl>
    </div>
    {%- endmacro %}

    {% macro anomaly_block(kind, item) -%}
    <div class="anomaly {{ kind }}">
        <div class="anomaly-header">
            <div>
                <h3>Règle #{{ item.rule.id }} – {{ item.rule.name }}</h3>
                <div class="anomaly-type">{{ kind|capitalize }}</div>
            </div>
            <div>
                {% set sev=item.severity or 'low' %}
                <span class="badge-sev {{ 'sev-' + sev }}"> {{ severity_labels[sev] }} </span>
            </div>
        </div>
        <div class="anomaly-desc">{{ item.description }}</div>
        <div class="rule-grid">
            {{ rule_box("Règle concernée", item.rule) }}
            {% if item.by_rule is defined %}
                {{ rule_box("Règle qui masque", item.by_rule) }}
            {% elif item.reference is defined %}
                {{ rule_box("Règle de référence", item.reference) }}
            {% elif item.covered_rules is defined %}
                <div class="rule-box">
                    <h4>Règles couvertes ({{ item.count }})</h4>
                    <ul>
                        {% for r in item.covered_rules %}
                        <li>#{{ r.id }} – {{ r.name }}</li>
                        {% endfor %}
                    </ul>
                </div>
            {% endif %}
        </div>
        <div><strong>Impact :</strong> {{ item.impact }}</div>
        <div><strong>Recommandation :</strong> {{ item.recommendation }}</div>
    </div>
    {%- endmacro %}

    {% macro render_section(anchor, title, icon, kind, items) -%}
    <div class="section" id="{{ anchor }}">
        <h2>{{ icon }} {{ title }}</h2>
        {% if items %}
            {% for item in items %}
                {{ anomaly_block(kind, item) }}
            {% endfor %}
        {% else %}
            <div class="anomaly unused"><div class="anomaly-desc">Aucune anomalie dans cette section.</div></div>
        {% endif %}
    </div>
    {%- endmacro %}

    {{ render_section("shadowed", "Règles cachées", "🛑", "shadowed", anomalies.shadowed) }}
    {{ render_section("redundant", "Règles redondantes", "🟡", "redundant", anomalies.redundant) }}
    {{ render_section("permissive", "Règles permissives", "🟠", "permissive", anomalies.permissive) }}
    {{ render_section("unsafe", "Services non sécurisés détectés", "🧪", "unsafe", anomalies.unsafe_services) }}
    {{ render_section("generalized", "Règles de généralisation", "🧭", "generalized", anomalies.generalized) }}
    {{ render_section("unused", "Règles inutilisées", "⚪", "unused", anomalies.unused) }}

    <div class="section" id="correlated">
        <h2>🧩 Vue corrélée des anomalies par règle</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th><th>Nom</th><th>Tags</th><th>Criticité la plus élevée</th>
                </tr>
            </thead>
            <tbody>
            {% for item in anomalies.correlated %}
                <tr>
                    <td>{{ item.rule.id }}</td>
                    <td>{{ item.rule.name }}</td>
                    <td>{{ item.tags | join(', ') if item.tags else 'Aucune' }}</td>
                    {% if item.severity %}
                        <td><span class="badge-sev {{ 'sev-' + item.severity }}">{{ severity_labels[item.severity] }}</span></td>
                    {% else %}
                        <td>—</td>
                    {% endif %}
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section" id="allrules">
        <h2>📋 Toutes les règles</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th><th>Nom</th><th>Source</th><th>Destination</th><th>Port</th><th>Protocole</th><th>Action</th><th>Priorité</th><th>Hits</th>
                </tr>
            </thead>
            <tbody>
            {% for rule in rules %}
                <tr>
                    <td>{{ rule.id }}</td>
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

    <footer>Généré par Firewall Audit Tool | {{ timestamp }}</footer>
</div>
</body>
</html>
"""


def generate_reports(rules: List[Dict], anomalies: Dict[str, List], output_dir: str, format_type: str = "both") -> List[str]:
    """
    Génère les rapports d'audit au format HTML et/ou PDF.
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_anomalies = sum(len(v) for k, v in anomalies.items() if k not in ("correlated", "severity_counts"))

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        rules=rules,
        anomalies=anomalies,
        severity_labels=SEVERITY_LABEL,
        total_anomalies=total_anomalies,
        total_rules=len(rules),
        timestamp=timestamp,
    )

    generated_files = []
    fname = f"firewall_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    if format_type in ["html", "both"]:
        html_path = os.path.join(output_dir, f"{fname}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        generated_files.append(html_path)

    if format_type in ["pdf", "both"]:
        pdf_path = os.path.join(output_dir, f"{fname}.pdf")
        try:
            HTML(string=html_content, base_url=os.getcwd()).write_pdf(target=pdf_path)
            generated_files.append(pdf_path)
        except Exception as pdf_err:
            # On échoue proprement sans bloquer le rapport HTML
            print(f"[WARN] Génération PDF échouée: {pdf_err}")

    return generated_files
