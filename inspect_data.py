#!/usr/bin/env python3
"""
Inspect raw Wazuh alert structure to understand field mappings.
"""

import sys
import json
from dotenv import load_dotenv

load_dotenv()

from wazuh_retrieval.config import IndexerConfig
from wazuh_retrieval.client import WazuhIndexerClient
from datetime import datetime, timedelta

def inspect_raw_alerts():
    """Fetch and display raw alert structure"""

    config = IndexerConfig.from_env()
    client = WazuhIndexerClient(config)
    client.connect()

    # Get recent alerts
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=1)

    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat() + "Z",
                    "lte": end_time.isoformat() + "Z"
                }
            }
        },
        "size": 20,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    print("="*80)
    print("INSPECTING RAW WAZUH ALERT STRUCTURE")
    print("="*80)

    response = client.search(config.alerts_index_pattern, query)
    hits = response.get('hits', {}).get('hits', [])

    if not hits:
        print("No alerts found in last hour")
        return

    print(f"\nFound {len(hits)} alerts. Analyzing structure...\n")

    # Check what fields are actually present
    field_presence = {}

    for i, hit in enumerate(hits):
        source = hit.get('_source', {})

        if i == 0:
            print("="*80)
            print(f"SAMPLE ALERT #{i+1} (Full Structure)")
            print("="*80)
            print(json.dumps(source, indent=2, default=str))
            print("\n")

        # Check for network fields
        data = source.get('data', {})
        syscheck = source.get('syscheck', {})

        # Track field presence
        fields_to_check = {
            'data.srcip': data.get('srcip'),
            'data.dstip': data.get('dstip'),
            'data.src_ip': data.get('src_ip'),
            'data.dst_ip': data.get('dst_ip'),
            'data.srcport': data.get('srcport'),
            'data.dstport': data.get('dstport'),
            'data.protocol': data.get('protocol'),
            'data.win.eventdata.IpAddress': data.get('win', {}).get('eventdata', {}).get('IpAddress'),
            'data.win.eventdata.IpPort': data.get('win', {}).get('eventdata', {}).get('IpPort'),
            'syscheck.path': syscheck.get('path'),
            'syscheck.sha256_after': syscheck.get('sha256_after'),
            'data.process_name': data.get('process_name'),
            'data.win.eventdata.Image': data.get('win', {}).get('eventdata', {}).get('Image'),
            'data.win.eventdata.ProcessId': data.get('win', {}).get('eventdata', {}).get('ProcessId'),
            'data.command': data.get('command'),
            'data.win.eventdata.CommandLine': data.get('win', {}).get('eventdata', {}).get('CommandLine'),
            'full_log': source.get('full_log'),
        }

        for field, value in fields_to_check.items():
            if field not in field_presence:
                field_presence[field] = {'present': 0, 'null': 0}

            if value:
                field_presence[field]['present'] += 1
            else:
                field_presence[field]['null'] += 1

    # Print summary
    print("="*80)
    print("FIELD PRESENCE SUMMARY")
    print("="*80)
    print(f"Total alerts analyzed: {len(hits)}\n")

    for field, stats in sorted(field_presence.items()):
        presence_rate = (stats['present'] / len(hits)) * 100
        status = "✓" if stats['present'] > 0 else "✗"
        print(f"{status} {field:40s} Present: {stats['present']:2d}/{len(hits)} ({presence_rate:5.1f}%)")

    print("\n")
    print("="*80)
    print("RECOMMENDED MAPPING UPDATES")
    print("="*80)

    # Find which fields actually have data
    common_fields = {k: v for k, v in field_presence.items() if v['present'] > 0}

    if common_fields:
        print("\nFields with data that should be mapped:")
        for field in sorted(common_fields.keys()):
            print(f"  - {field}")
    else:
        print("\nNo optional fields have data in these alerts.")
        print("This might be normal depending on alert types.")

    # Show alert types
    print("\n")
    print("="*80)
    print("ALERT TYPES IN SAMPLE")
    print("="*80)

    rule_counts = {}
    for hit in hits:
        source = hit.get('_source', {})
        rule_id = source.get('rule', {}).get('id')
        rule_desc = source.get('rule', {}).get('description', 'Unknown')

        if rule_id not in rule_counts:
            rule_counts[rule_id] = {'count': 0, 'description': rule_desc}
        rule_counts[rule_id]['count'] += 1

    for rule_id, info in sorted(rule_counts.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"  Rule {rule_id}: {info['description']} ({info['count']} alerts)")

    client.close()

if __name__ == "__main__":
    inspect_raw_alerts()
