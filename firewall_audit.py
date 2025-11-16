#!/usr/bin/env python3
"""
Firewall Audit Tool - CLI
Analyse les règles de firewall pour détecter les anomalies
"""

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

from modules.rule_parser import parse_rules
from modules.anomaly_detector import detect_all_anomalies
from modules.report_generator import generate_reports


def main():
    parser = argparse.ArgumentParser(
        description='Outil d\'audit de règles de firewall',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s rules.csv
  %(prog)s rules.json --output-dir ./my_reports
  %(prog)s rules.csv --verbose
  %(prog)s rules.json -o ./reports -v
        """
    )

    parser.add_argument(
        'input_file',
        help='Fichier d\'entrée contenant les règles (CSV ou JSON)'
    )

    parser.add_argument(
        '-o', '--output-dir',
        default='reports',
        help='Répertoire de sortie pour les rapports (défaut: reports)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Afficher les détails de l\'analyse dans le terminal'
    )

    parser.add_argument(
        '--format',
        choices=['both', 'html', 'pdf'],
        default='both',
        help='Format du rapport: both, html ou pdf (défaut: both)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.input_file):
        print(f"❌ Erreur: Le fichier '{args.input_file}' n'existe pas.")
        sys.exit(1)

    print("🔍 Firewall Audit Tool")
    print("=" * 60)
    print(f"📂 Fichier d'entrée: {args.input_file}")
    print(f"📁 Répertoire de sortie: {args.output_dir}")
    print("=" * 60)

    try:
        print("\n⏳ Chargement des règles...")
        rules = parse_rules(args.input_file)
        print(f"✅ {len(rules)} règles chargées avec succès\n")

        if args.verbose:
            print("📋 Règles chargées:")
            for i, rule in enumerate(rules, 1):
                print(f"  {i}. {rule.get('name', f'Rule {i}')} - "
                      f"{rule.get('source', '*')} → {rule.get('destination', '*')} "
                      f"[{rule.get('action', 'allow')}]")
            print()

        print("🔬 Analyse des anomalies en cours...")
        anomalies = detect_all_anomalies(rules, verbose=args.verbose)

        total_anomalies = sum(len(v) for v in anomalies.values())
        print(f"\n📊 Résultats de l'analyse:")
        print(f"  • Règles cachées (shadowed): {len(anomalies['shadowed'])}")
        print(f"  • Règles redondantes: {len(anomalies['redundant'])}")
        print(f"  • Règles trop permissives: {len(anomalies['permissive'])}")
        print(f"  • Règles inutilisées: {len(anomalies['unused'])}")
        print(f"  → Total: {total_anomalies} anomalie(s) détectée(s)\n")

        if args.verbose and total_anomalies > 0:
            print("📝 Détails des anomalies:")
            for anomaly_type, items in anomalies.items():
                if items:
                    print(f"\n  {anomaly_type.upper()}:")
                    for item in items[:5]:
                        print(f"    - {item.get('description', item)}")
                    if len(items) > 5:
                        print(f"    ... et {len(items) - 5} autres")
            print()

        os.makedirs(args.output_dir, exist_ok=True)

        print("📄 Génération des rapports...")
        report_files = generate_reports(
            rules,
            anomalies,
            args.output_dir,
            format_type=args.format
        )

        print("\n✅ Audit terminé avec succès!")
        print("\n📦 Rapports générés:")
        for report_file in report_files:
            file_size = os.path.getsize(report_file) / 1024
            print(f"  • {report_file} ({file_size:.1f} KB)")

        print("\n" + "=" * 60)
        if total_anomalies > 0:
            print("⚠️  Des anomalies ont été détectées. Consultez les rapports.")
        else:
            print("✅ Aucune anomalie détectée. Les règles semblent correctes.")
        print("=" * 60)

        return 0 if total_anomalies == 0 else 1

    except Exception as e:
        print(f"\n❌ Erreur lors de l'audit: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    sys.exit(main())
