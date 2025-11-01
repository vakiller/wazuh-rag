#!/usr/bin/env python3
"""
Check if full_log field exists and how to extract log content.
"""

import sys
import json
from dotenv import load_dotenv

load_dotenv()

from wazuh_retrieval.config import IndexerConfig
from wazuh_retrieval.client import WazuhIndexerClient

def check_fulllog():
    config = IndexerConfig.from_env()
    client = WazuhIndexerClient(config)
    client.connect()

    # Check multiple alert types
    print("="*80)
    print("CHECKING DIFFERENT ALERT TYPES")
    print("="*80)

    # 1. Syscheck alerts
    print("\n1. FILE INTEGRITY MONITORING (Syscheck) Alerts:")
    print("-"*80)
    query = {
        'query': {'exists': {'field': 'syscheck'}},
        'size': 2,
        'sort': [{'@timestamp': {'order': 'desc'}}]
    }
    result = client.search(config.alerts_index_pattern, query)
    hits = result.get('hits', {}).get('hits', [])

    if hits:
        for i, hit in enumerate(hits):
            source = hit['_source']
            print(f"\nSyscheck Alert #{i+1}:")
            print(f"  Rule: {source.get('rule', {}).get('id')} - {source.get('rule', {}).get('description')}")
            print(f"  File: {source.get('syscheck', {}).get('path', 'N/A')}")
            print(f"  SHA256: {source.get('syscheck', {}).get('sha256_after', 'N/A')}")
            print(f"  Has full_log: {'full_log' in source}")

            if 'full_log' in source:
                print(f"  full_log content: {source['full_log'][:200]}...")

            # Check for message field
            if 'data' in source and 'win' in source['data']:
                msg = source['data']['win'].get('system', {}).get('message', '')
                if msg:
                    print(f"  Windows message: {msg[:200]}...")

    # 2. Windows event logs
    print("\n\n2. WINDOWS SECURITY EVENT Alerts:")
    print("-"*80)
    query2 = {
        'query': {
            'bool': {
                'must': [
                    {'exists': {'field': 'data.win'}},
                    {'term': {'data.win.system.channel.keyword': 'Security'}}
                ]
            }
        },
        'size': 2,
        'sort': [{'@timestamp': {'order': 'desc'}}]
    }
    result2 = client.search(config.alerts_index_pattern, query2)
    hits2 = result2.get('hits', {}).get('hits', [])

    if hits2:
        for i, hit in enumerate(hits2):
            source = hit['_source']
            print(f"\nWindows Alert #{i+1}:")
            print(f"  Rule: {source.get('rule', {}).get('id')} - {source.get('rule', {}).get('description')}")
            print(f"  Event ID: {source.get('data', {}).get('win', {}).get('system', {}).get('eventID', 'N/A')}")
            print(f"  Has full_log: {'full_log' in source}")

            if 'full_log' in source:
                print(f"  full_log content: {source['full_log'][:200]}...")

            # Windows message field contains the full event description
            win_system = source.get('data', {}).get('win', {}).get('system', {})
            if 'message' in win_system:
                print(f"  Windows message (first 300 chars):")
                print(f"  {win_system['message'][:300]}...")

    # 3. Check if predecoded logs exist
    print("\n\n3. CHECKING FOR PREDECODED FIELD:")
    print("-"*80)
    query3 = {
        'query': {'exists': {'field': 'predecoder'}},
        'size': 2,
        'sort': [{'@timestamp': {'order': 'desc'}}]
    }
    result3 = client.search(config.alerts_index_pattern, query3)
    hits3 = result3.get('hits', {}).get('hits', [])

    if hits3:
        print(f"Found {result3['hits']['total']['value']} alerts with predecoder field")
        for i, hit in enumerate(hits3):
            source = hit['_source']
            print(f"\nAlert with predecoder #{i+1}:")
            predecoder = source.get('predecoder', {})
            print(f"  Program: {predecoder.get('program_name', 'N/A')}")
            print(f"  Timestamp: {predecoder.get('timestamp', 'N/A')}")
            print(f"  Has full_log: {'full_log' in source}")
            if 'full_log' in source:
                print(f"  full_log: {source['full_log']}")
    else:
        print("No alerts with predecoder field found")

    # 4. Sample all fields in one alert
    print("\n\n4. ALL TOP-LEVEL FIELDS IN RECENT ALERT:")
    print("-"*80)
    query4 = {'query': {'match_all': {}}, 'size': 1, 'sort': [{'@timestamp': {'order': 'desc'}}]}
    result4 = client.search(config.alerts_index_pattern, query4)
    if result4.get('hits', {}).get('hits'):
        source = result4['hits']['hits'][0]['_source']
        print("Top-level fields present:")
        for key in sorted(source.keys()):
            value_type = type(source[key]).__name__
            if isinstance(source[key], (str, int, float, bool)):
                print(f"  - {key}: {value_type} = {str(source[key])[:60]}")
            else:
                print(f"  - {key}: {value_type}")

    client.close()

if __name__ == "__main__":
    check_fulllog()
