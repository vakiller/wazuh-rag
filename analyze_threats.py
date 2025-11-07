#!/usr/bin/env python3
"""
Threat Analysis CLI - Phase 3

Command-line interface for automated threat analysis using LLM.

Usage:
    python analyze_threats.py --analyze-now          # Analyze last 30 min
    python analyze_threats.py --test-llm             # Test LLM connection
    python analyze_threats.py --report 123           # View report by ID
    python analyze_threats.py --recent 10            # View 10 recent reports
    python analyze_threats.py --stats                # Show statistics
    python analyze_threats.py --window 60            # Analyze last 60 min
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime
import json

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from llm_analysis import ThreatAnalyzer


def setup_logging(log_level: str = "INFO"):
    """Setup logging configuration"""
    # Create logs directory
    log_dir = Path("./logs")
    log_dir.mkdir(exist_ok=True)

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "phase3_analysis.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )


def print_report(report: dict, detailed: bool = False):
    """Pretty print a report (Phase 4 enhanced)"""
    print("\n" + "=" * 80)
    print(f"THREAT ANALYSIS REPORT #{report['id']}")
    print("=" * 80)

    print(f"\nCreated: {report['created_at']}")
    print(f"Window: {report['window_start']} to {report['window_end']}")
    print(f"Alerts Analyzed: {report['alerts_count']}")

    # Phase 4: Show Severity prominently
    severity = report.get('severity', 'N/A')
    severity_icon = {
        'Critical': '🔴',
        'High': '🟠',
        'Medium': '🟡',
        'Low': '🟢'
    }.get(severity, '⚪')
    print(f"Severity: {severity_icon} {severity}")
    print(f"Risk Score: {report['risk_score']}/100")

    if report.get('hosts'):
        print(f"Affected Hosts: {report['hosts']}")
    if report.get('agents'):
        print(f"Affected Agents: {report['agents']}")

    # Phase 4: TL;DR at the top
    tldr = report.get('details', {}).get('tldr')
    if tldr:
        print(f"\n💡 TL;DR: {tldr}")

    print("\n" + "-" * 80)
    print("INCIDENT SUMMARY")
    print("-" * 80)
    print(report.get('summary', 'N/A'))

    # MITRE Techniques
    mitre_list = report.get('mitre_list', [])
    if mitre_list:
        print("\n" + "-" * 80)
        print("MITRE ATT&CK TECHNIQUES")
        print("-" * 80)
        for item in mitre_list:
            if isinstance(item, dict):
                print(f"  - {item.get('technique_id', 'N/A')}: {item.get('technique_name', 'N/A')}")
                print(f"    Tactic: {item.get('tactic', 'N/A')}")
            else:
                print(f"  - {item}")

    # Phase 4: Attack Timeline
    timeline = report.get('details', {}).get('timeline', [])
    if timeline and detailed:
        print("\n" + "-" * 80)
        print("ATTACK TIMELINE (Chronological)")
        print("-" * 80)
        for event in timeline[:10]:  # Show first 10 events
            if isinstance(event, dict):
                timestamp = event.get('timestamp', 'N/A')
                host = event.get('host', 'N/A')
                tactic = event.get('tactic', 'N/A')
                technique = event.get('technique', 'N/A')
                description = event.get('description', 'N/A')
                print(f"  [{timestamp}] {host}")
                print(f"    {tactic} → {technique}")
                print(f"    {description}\n")
        if len(timeline) > 10:
            print(f"  ... and {len(timeline) - 10} more events")

    # Predictions
    predictions = report.get('details', {}).get('predictions', [])
    if predictions:
        print("\n" + "-" * 80)
        print("PREDICTED NEXT ACTIONS")
        print("-" * 80)
        for pred in predictions[:3]:
            if isinstance(pred, dict):
                print(f"  [{pred.get('confidence', 'N/A')}] {pred.get('action', 'N/A')}")
                if detailed and pred.get('reasoning'):
                    print(f"      Reasoning: {pred.get('reasoning')}")
            else:
                print(f"  - {pred}")

    # Phase 4: Incident Response Workflow (Containment/Eradication/Recovery)
    actions = report.get('suggested_actions', {})
    if actions:
        print("\n" + "-" * 80)
        print("INCIDENT RESPONSE WORKFLOW")
        print("-" * 80)

        # Check if it's the new Phase 4 format (dict with phases) or old format (list)
        if isinstance(actions, dict):
            # Phase 4 format
            for phase, phase_actions in [
                ('CONTAINMENT', actions.get('containment', [])),
                ('ERADICATION', actions.get('eradication', [])),
                ('RECOVERY', actions.get('recovery', []))
            ]:
                if phase_actions:
                    print(f"\n  {phase}:")
                    for i, action in enumerate(phase_actions, 1):
                        if isinstance(action, dict):
                            action_text = action.get('action', str(action))
                        else:
                            action_text = str(action)
                        print(f"    {i}. {action_text}")
        else:
            # Old format (list)
            for action in actions:
                if isinstance(action, dict):
                    step = action.get('step', '?')
                    priority = action.get('priority', 'N/A')
                    action_text = action.get('action', 'N/A')
                    print(f"  {step}. [{priority}] {action_text}")
                else:
                    print(f"  - {action}")

    # Phase 4: Business Impact Assessment
    business_impact = report.get('details', {}).get('business_impact', {})
    if business_impact and detailed:
        print("\n" + "-" * 80)
        print("BUSINESS IMPACT ASSESSMENT")
        print("-" * 80)

        affected_systems = business_impact.get('affected_systems', [])
        if affected_systems:
            if isinstance(affected_systems, list):
                print(f"  Affected Systems: {', '.join(str(s) for s in affected_systems)}")
            else:
                print(f"  Affected Systems: {affected_systems}")

        if business_impact.get('operational_risk'):
            print(f"  Operational Risk: {business_impact['operational_risk']}")
        if business_impact.get('data_integrity_risk'):
            print(f"  Data Integrity Risk: {business_impact['data_integrity_risk']}")
        if business_impact.get('domain_wide_risk'):
            print(f"  Domain-Wide Risk: {business_impact['domain_wide_risk']}")

    # Phase 4: Enhanced IOCs (expanded to 8 types)
    iocs = report.get('iocs', {})
    if iocs and detailed:
        print("\n" + "-" * 80)
        print("INDICATORS OF COMPROMISE")
        print("-" * 80)

        # Phase 4 IOC order: ips, users, hashes, domains, file_paths, registry_keys, processes, commands
        ioc_order = ['ips', 'users', 'hashes', 'domains', 'file_paths', 'registry_keys', 'processes', 'commands']
        for ioc_type in ioc_order:
            values = iocs.get(ioc_type, [])
            if values:
                display_name = ioc_type.replace('_', ' ').upper()
                print(f"  {display_name}: {', '.join(str(v) for v in values[:5])}")
                if len(values) > 5:
                    print(f"    ... and {len(values) - 5} more")

    # Phase 4: Evidence Map (link findings to alert IDs, timestamps, hosts)
    evidence_map = report.get('details', {}).get('evidence_map', [])
    # Ensure evidence_map is a list
    if not isinstance(evidence_map, list):
        evidence_map = []
    if evidence_map and detailed:
        print("\n" + "-" * 80)
        print("EVIDENCE MAP")
        print("-" * 80)
        for i, evidence in enumerate(evidence_map[:5], 1):
            if isinstance(evidence, dict):
                finding = evidence.get('finding', 'N/A')
                alert_ids = evidence.get('alert_ids', [])
                timestamps = evidence.get('timestamps', [])
                hosts = evidence.get('hosts', [])
                knowledge_refs = evidence.get('knowledge_refs', [])

                print(f"  {i}. {finding}")
                if alert_ids:
                    print(f"     Alert IDs: {', '.join(str(a) for a in alert_ids[:3])}")
                if timestamps:
                    print(f"     Timestamps: {', '.join(str(t) for t in timestamps[:2])}")
                if hosts:
                    print(f"     Hosts: {', '.join(str(h) for h in hosts[:3])}")
                if knowledge_refs:
                    print(f"     Knowledge: {', '.join(str(k) for k in knowledge_refs[:2])}")
                print()
        if len(evidence_map) > 5:
            print(f"  ... and {len(evidence_map) - 5} more evidence items")

    # Phase 4: Detection Recommendations
    detection_recs = report.get('details', {}).get('detection_recommendations', [])
    if detection_recs and detailed:
        print("\n" + "-" * 80)
        print("DETECTION IMPROVEMENTS")
        print("-" * 80)

        # Handle both formats: list of dicts OR dict with categorized lists
        if isinstance(detection_recs, dict):
            # Format: {sigma_rules: [], wazuh_rules: [], log_sources: []}
            for category, items in detection_recs.items():
                if items:
                    category_name = category.replace('_', ' ').upper()
                    print(f"\n  {category_name}:")
                    for item in items[:3]:
                        print(f"    - {item}")
                    if len(items) > 3:
                        print(f"    ... and {len(items) - 3} more")
        elif isinstance(detection_recs, list):
            # Format: [{"type": "sigma_rule", "description": "..."}]
            for rec in detection_recs[:5]:
                if isinstance(rec, dict):
                    rec_type = rec.get('type', 'unknown').upper()
                    description = rec.get('description', 'N/A')
                    print(f"  [{rec_type}] {description}")
                else:
                    print(f"  - {rec}")
            if len(detection_recs) > 5:
                print(f"  ... and {len(detection_recs) - 5} more recommendations")

    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Automated Threat Analysis using LLM"
    )

    parser.add_argument(
        '--analyze-now',
        action='store_true',
        help='Analyze alerts from last N minutes (default: 30)'
    )

    parser.add_argument(
        '--window',
        type=int,
        help='Analysis window in minutes (default: 30)'
    )

    parser.add_argument(
        '--test-llm',
        action='store_true',
        help='Test LLM connection'
    )

    parser.add_argument(
        '--report',
        type=int,
        metavar='ID',
        help='View specific report by ID'
    )

    parser.add_argument(
        '--recent',
        type=int,
        metavar='N',
        help='View N most recent reports'
    )

    parser.add_argument(
        '--high-risk',
        type=int,
        metavar='THRESHOLD',
        help='Show reports with risk score >= threshold'
    )

    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show report statistics'
    )

    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed report information'
    )

    parser.add_argument(
        '--config',
        default='llm_analysis/config.yaml',
        help='Path to configuration file'
    )

    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        help='Logging level'
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)

    logger.info("=" * 80)
    logger.info("Phase 3: Automated Threat Analysis")
    logger.info("=" * 80)

    try:
        # Initialize analyzer
        analyzer = ThreatAnalyzer(config_path=args.config)

        # Test LLM connection
        if args.test_llm:
            print("\nTesting LLM connection...")
            if analyzer.test_llm_connection():
                print("✓ LLM connection successful")
                return 0
            else:
                print("✗ LLM connection failed")
                return 1

        # Analyze now
        if args.analyze_now:
            window = args.window if args.window else None
            print(f"\nAnalyzing alerts from last {window or 30} minutes...")

            report_id = analyzer.analyze_window(window_minutes=window)

            if report_id:
                print(f"\n✓ Analysis complete! Report ID: {report_id}")
                print(f"\nView report with: python analyze_threats.py --report {report_id}")

                # Optionally display the report
                if args.detailed:
                    report = analyzer.get_report(report_id)
                    if report:
                        print_report(report, detailed=True)
            else:
                print("\n✗ Analysis failed or insufficient alerts")

            return 0

        # View specific report
        if args.report:
            report = analyzer.get_report(args.report)
            if report:
                print_report(report, detailed=args.detailed)
            else:
                print(f"\n✗ Report {args.report} not found")
            return 0

        # View recent reports
        if args.recent:
            reports = analyzer.get_recent_reports(limit=args.recent)
            if reports:
                print(f"\n{len(reports)} Most Recent Reports:\n")
                for report in reports:
                    risk_icon = "🔴" if report['risk_score'] >= 70 else "🟡" if report['risk_score'] >= 40 else "🟢"
                    print(
                        f"  {risk_icon} ID {report['id']:4d} | "
                        f"Risk: {report['risk_score']:3d}/100 | "
                        f"{report['alerts_count']:3d} alerts | "
                        f"{report['created_at']}"
                    )
                print(f"\nView details: python analyze_threats.py --report <ID>")
            else:
                print("\n✗ No reports found")
            return 0

        # High risk reports
        if args.high_risk:
            from llm_analysis.storage import ReportStorage
            storage = ReportStorage(analyzer.config['database']['path'])
            reports = storage.get_high_risk_reports(min_score=args.high_risk)

            if reports:
                print(f"\n{len(reports)} High-Risk Reports (>= {args.high_risk}):\n")
                for report in reports:
                    print(
                        f"  🔴 ID {report['id']:4d} | "
                        f"Risk: {report['risk_score']:3d}/100 | "
                        f"{report['alerts_count']:3d} alerts | "
                        f"{report['created_at']}"
                    )
            else:
                print(f"\n✗ No reports with risk score >= {args.high_risk}")

            storage.close()
            return 0

        # Show statistics
        if args.stats:
            stats = analyzer.get_storage_stats()
            print("\n" + "=" * 60)
            print("THREAT ANALYSIS STATISTICS")
            print("=" * 60)
            print(f"Total Reports: {stats['total_reports']}")
            print(f"Average Risk Score: {stats['avg_risk_score']}/100")
            print(f"Maximum Risk Score: {stats['max_risk_score']}/100")
            print(f"Total Alerts Analyzed: {stats['total_alerts_analyzed']}")
            if stats['first_report']:
                print(f"First Report: {stats['first_report']}")
            if stats['last_report']:
                print(f"Last Report: {stats['last_report']}")
            print("=" * 60)
            return 0

        # No action specified
        parser.print_help()
        return 0

    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        print(f"\n✗ Error: {e}")
        return 1

    finally:
        if 'analyzer' in locals():
            analyzer.close()


if __name__ == '__main__':
    sys.exit(main())
