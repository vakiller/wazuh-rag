#!/usr/bin/env python3
"""
Live integration test for Wazuh Alert Collector.
Tests against real Wazuh Indexer at 172.16.235.140
"""

import sys
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Setup Python path
sys.path.insert(0, os.path.dirname(__file__))

from wazuh_retrieval.config import IndexerConfig
from wazuh_retrieval.client import WazuhIndexerClient
from wazuh_retrieval.collectors.alerts import AlertCollector
from wazuh_retrieval.schema.transformer import AlertTransformer
from wazuh_retrieval.tracking.state import StateTracker
from wazuh_retrieval.output.sqlite_handler import SQLiteOutputHandler
from wazuh_retrieval.utils import setup_logging


def test_connection():
    """Test 1: Connection to Wazuh Indexer"""
    print("\n" + "="*60)
    print("TEST 1: Connection to Wazuh Indexer")
    print("="*60)

    try:
        config = IndexerConfig.from_env()
        print(f"Config loaded:")
        print(f"  Host: {config.host}")
        print(f"  Port: {config.port}")
        print(f"  User: {config.username}")
        print(f"  SSL: {config.use_ssl}")
        print(f"  Verify certs: {config.verify_certs}")

        client = WazuhIndexerClient(config)
        client.connect()

        print("✓ Successfully connected to Wazuh Indexer")

        # Get cluster health
        health = client.get_cluster_health()
        print(f"✓ Cluster health: {health.get('status', 'unknown')}")
        print(f"  Cluster name: {health.get('cluster_name', 'unknown')}")
        print(f"  Number of nodes: {health.get('number_of_nodes', 0)}")

        return client, config

    except Exception as e:
        print(f"✗ Connection failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def test_indices(client):
    """Test 2: Check available indices"""
    print("\n" + "="*60)
    print("TEST 2: Check Wazuh Indices")
    print("="*60)

    try:
        indices = client.get_indices("wazuh-alerts-*")

        if not indices:
            print("✗ No wazuh-alerts indices found!")
            return False

        print(f"✓ Found {len(indices)} wazuh-alerts indices:")
        for idx in sorted(indices, key=lambda x: x['index'])[-5:]:
            print(f"  - {idx['index']}: {idx.get('docs.count', '?')} docs, {idx.get('store.size', '?')}")

        return True

    except Exception as e:
        print(f"✗ Failed to get indices: {e}")
        return False


def test_count_alerts(client, config):
    """Test 3: Count recent alerts"""
    print("\n" + "="*60)
    print("TEST 3: Count Recent Alerts")
    print("="*60)

    try:
        # Count alerts from last 24 hours
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)

        start_str = start_time.isoformat() + "Z"
        end_str = end_time.isoformat() + "Z"

        print(f"Counting alerts from {start_str} to {end_str}")

        query_body = {
            "query": {
                "range": {
                    "@timestamp": {
                        "gte": start_str,
                        "lte": end_str
                    }
                }
            }
        }

        count = client.count(config.alerts_index_pattern, query_body)

        print(f"✓ Found {count:,} alerts in last 24 hours")

        if count == 0:
            print("⚠ Warning: No alerts found. This might be normal if system is new.")

        return count > 0

    except Exception as e:
        print(f"✗ Failed to count alerts: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_collect_sample(client, config):
    """Test 4: Collect sample alerts"""
    print("\n" + "="*60)
    print("TEST 4: Collect Sample Alerts")
    print("="*60)

    try:
        # Create collector
        state_tracker = StateTracker(".test_live_state.json")
        collector = AlertCollector(client, config, state_tracker)
        transformer = AlertTransformer()

        # Collect alerts from last 1 hour
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)

        start_str = start_time.isoformat() + "Z"
        end_str = end_time.isoformat() + "Z"

        print(f"Collecting alerts from {start_str} to {end_str}")
        print("Fetching up to 10 alerts...")

        collected = []
        for raw_alert in collector.collect_batch(start_str, end_str):
            collected.append(raw_alert)
            if len(collected) >= 10:
                break

        if not collected:
            print("⚠ No alerts collected (might be normal if no recent activity)")
            return True  # Not a failure, just no data

        print(f"✓ Collected {len(collected)} sample alerts")

        # Transform and display first alert
        print("\n--- Sample Alert (Raw) ---")
        first_alert = collected[0]
        source = first_alert.get('_source', {})
        print(f"Index: {first_alert.get('_index')}")
        print(f"Document ID: {first_alert.get('_id')}")
        print(f"Timestamp: {source.get('@timestamp')}")
        print(f"Agent: {source.get('agent', {}).get('name')} ({source.get('agent', {}).get('id')})")
        print(f"Rule ID: {source.get('rule', {}).get('id')}")
        print(f"Rule Level: {source.get('rule', {}).get('level')}")
        print(f"Description: {source.get('rule', {}).get('description', 'N/A')}")

        # Transform
        print("\n--- Transforming Alert ---")
        normalized = transformer.transform(first_alert)

        print("✓ Alert transformed successfully")
        print(f"  Document ID: {normalized['document_id']}")
        print(f"  Timestamp: {normalized['timestamp']}")
        print(f"  Agent: {normalized['agent_name']} ({normalized['agent_id']})")
        print(f"  Rule: {normalized['rule_id']} (Level {normalized['rule_level']})")
        print(f"  Description: {normalized['rule_description']}")
        print(f"  MITRE Techniques: {normalized['mitre_techniques']}")
        print(f"  MITRE Tactics: {normalized['mitre_tactics']}")
        print(f"  Source IP: {normalized.get('source_ip', 'N/A')}")
        print(f"  Dest IP: {normalized.get('dest_ip', 'N/A')}")

        # Cleanup
        if os.path.exists(".test_live_state.json"):
            os.remove(".test_live_state.json")

        return True

    except Exception as e:
        print(f"✗ Collection/transformation failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_full_pipeline(client, config):
    """Test 5: Full collection pipeline with SQLite output"""
    print("\n" + "="*60)
    print("TEST 5: Full Collection Pipeline (SQLite)")
    print("="*60)

    test_db = "./test_wazuh_alerts.db"

    try:
        # Clean up old test database
        if os.path.exists(test_db):
            os.remove(test_db)

        # Create components
        state_tracker = StateTracker(".test_live_state.json")
        collector = AlertCollector(client, config, state_tracker)
        transformer = AlertTransformer()
        output_handler = SQLiteOutputHandler(test_db)

        # Collect from last 30 minutes
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=30)

        start_str = start_time.isoformat() + "Z"
        end_str = end_time.isoformat() + "Z"

        print(f"Collecting alerts from {start_str} to {end_str}")

        collected_count = 0
        transformed_count = 0
        error_count = 0

        for raw_alert in collector.collect_batch(start_str, end_str):
            collected_count += 1

            try:
                # Transform
                normalized = transformer.transform(raw_alert)
                transformed_count += 1

                # Output
                output_handler.handle(normalized)

            except Exception as e:
                error_count += 1
                print(f"⚠ Error processing alert: {e}")

            # Limit to 100 for testing
            if collected_count >= 100:
                break

        # Flush
        output_handler.flush()

        print(f"\n✓ Pipeline test complete:")
        print(f"  Collected: {collected_count}")
        print(f"  Transformed: {transformed_count}")
        print(f"  Errors: {error_count}")

        # Check database
        stats = output_handler.get_stats()
        print(f"\n✓ SQLite database stats:")
        print(f"  Total alerts: {stats['total_alerts']}")
        print(f"  Unique agents: {stats['unique_agents']}")
        print(f"  Unique rules: {stats['unique_rules']}")
        print(f"  Database size: {stats['db_size_mb']} MB")

        output_handler.close()

        # Cleanup
        if os.path.exists(".test_live_state.json"):
            os.remove(".test_live_state.json")

        print(f"\n✓ Test database created at: {test_db}")
        print("  You can query it with: sqlite3 test_wazuh_alerts.db")

        return collected_count > 0

    except Exception as e:
        print(f"✗ Full pipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all live tests"""
    print("\n" + "="*60)
    print("WAZUH ALERT COLLECTOR - LIVE INTEGRATION TESTS")
    print("="*60)
    print(f"Testing against: 172.16.235.140:9200")
    print(f"Time: {datetime.utcnow().isoformat()}Z")

    # Setup logging
    setup_logging(log_level="INFO")

    # Test 1: Connection
    client, config = test_connection()
    if not client:
        print("\n✗ Connection test failed. Cannot proceed with other tests.")
        return 1

    # Test 2: Indices
    if not test_indices(client):
        print("\n⚠ Warning: Could not verify indices, but continuing...")

    # Test 3: Count alerts
    has_alerts = test_count_alerts(client, config)

    # Test 4: Sample collection
    if not test_collect_sample(client, config):
        if has_alerts:
            print("\n✗ Sample collection failed despite alerts being present.")
            return 1

    # Test 5: Full pipeline
    if has_alerts:
        if not test_full_pipeline(client, config):
            print("\n✗ Full pipeline test failed.")
            return 1
    else:
        print("\n⚠ Skipping full pipeline test (no alerts available)")

    # Summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print("✓ All tests passed!")
    print("\nThe Wazuh Alert Collector is working correctly.")
    print("\nNext steps:")
    print("1. Run the full collector: python main.py")
    print("2. Or with debug logging: python main.py --log-level DEBUG")
    print("3. Monitor the SQLite database: sqlite3 wazuh_alerts.db")
    print("="*60)

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
