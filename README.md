# Wazuh Alert Collector

A robust data-retrieval module for collecting and normalizing security alerts from Wazuh Indexer (OpenSearch/Elasticsearch) for threat reporting and analysis.

## Features

- **Near-real-time collection**: Scheduled polling (configurable intervals) with automatic state tracking
- **Resumable**: Checkpoint-based collection prevents duplicate processing
- **Scalable pagination**: Uses `search_after` API for efficient large-volume retrieval
- **Schema normalization**: Transforms nested Wazuh documents to flat, consistent schema
- **MITRE ATT&CK extraction**: Automatic extraction and flattening of MITRE technique/tactic mappings
- **Multiple output formats**: SQLite, JSONL files, or Kafka (extensible)
- **Production-ready**: Error handling, retry logic, graceful shutdown

## Architecture

```
Wazuh Indexer (OpenSearch)
         ↓
   [AlertCollector] ← collects with pagination
         ↓
   [AlertTransformer] ← normalizes schema
         ↓
   [OutputHandler] → SQLite / JSONL / Kafka
         ↓
   Phase 2: Analytics, Enrichment, RAG
```

## Installation

### Prerequisites

- Python 3.8+
- Access to Wazuh Indexer (OpenSearch/Elasticsearch)
- Network connectivity to Wazuh Indexer API (default port 9200)

### Setup

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your Wazuh Indexer credentials
```

4. Verify connection:
```bash
# Test connection (will fail if indexer is not accessible)
python -c "from wazuh_retrieval.client import WazuhIndexerClient; from wazuh_retrieval.config import IndexerConfig; client = WazuhIndexerClient(IndexerConfig.from_env()); client.connect()"
```

## Configuration

All configuration is done via environment variables. See `.env.example` for all available options.

### Key Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | localhost | Wazuh Indexer hostname/IP |
| `WAZUH_INDEXER_PORT` | 9200 | Indexer port |
| `WAZUH_INDEXER_USER` | admin | Username for authentication |
| `WAZUH_INDEXER_PASSWORD` | (required) | Password for authentication |
| `WAZUH_POLL_INTERVAL` | 300 | Polling interval in seconds |
| `WAZUH_BATCH_SIZE` | 1000 | Documents per batch |
| `WAZUH_MIN_ALERT_LEVEL` | 0 | Minimum alert level (0-15) |

## Usage

### Basic Usage

Run with SQLite output (default):
```bash
python main.py
```

Run with JSONL file output:
```bash
python main.py --output file
```

Run with debug logging:
```bash
python main.py --log-level DEBUG
```

### Command-Line Options

```
usage: main.py [-h] [--output {sqlite,file}] [--log-level {DEBUG,INFO,WARNING,ERROR}]
               [--log-file LOG_FILE] [--no-immediate-run]

options:
  --output {sqlite,file}    Output handler type (default: sqlite)
  --log-level LEVEL         Logging level (default: INFO)
  --log-file FILE           Optional log file path
  --no-immediate-run        Skip immediate collection on start
```

### Output Formats

#### SQLite (default)
- **Location**: `./wazuh_alerts.db` (configurable)
- **Use case**: SQL-based querying, reporting, moderate volumes
- **Query example**:
```bash
sqlite3 wazuh_alerts.db "SELECT rule_id, COUNT(*) as count FROM alerts GROUP BY rule_id ORDER BY count DESC LIMIT 10"
```

#### JSONL Files
- **Location**: `./collected_alerts/alerts_YYYY-MM-DD.jsonl` (daily rotation)
- **Use case**: Batch processing, file-based pipelines
- **Read example**:
```bash
cat collected_alerts/alerts_2025-01-15.jsonl | jq '.rule_id' | sort | uniq -c
```

## Normalized Schema

The module transforms Wazuh's nested alert structure into a flat, consistent schema:

```json
{
  "timestamp": "2025-01-15T14:30:22.123Z",
  "document_id": "abc123xyz",
  "index_name": "wazuh-alerts-4.x-2025.01.15",
  "agent_id": "001",
  "agent_name": "web-server-01",
  "agent_ip": "10.0.1.50",
  "rule_id": "5710",
  "rule_description": "sshd: Attempt to login using a non-existent user",
  "rule_level": 5,
  "rule_groups": ["syslog", "sshd", "authentication_failed"],
  "mitre_techniques": ["T1110", "T1078"],
  "mitre_tactics": ["Credential Access", "Initial Access"],
  "source_ip": "192.168.1.100",
  "dest_ip": "10.0.1.50",
  "username": "admin123",
  "full_log": "Jan 15 14:30:22 web-server sshd[12345]: Invalid user admin123 from 192.168.1.100"
}
```

### Guaranteed Fields
Always present: `timestamp`, `document_id`, `index_name`, `agent_id`, `rule_id`, `rule_level`

### Optional Fields
Nullable, depend on alert type:
- **Network**: `source_ip`, `dest_ip`, `source_port`, `dest_port`, `protocol`
- **File**: `file_path`, `file_hash`
- **Process**: `process_name`, `process_id`, `command_line`
- **MITRE**: `mitre_techniques`, `mitre_tactics`

## State Tracking

The collector maintains state in `.wazuh_collector_state.json` (configurable) to:
- Track last processed timestamp
- Enable resume after crashes/restarts
- Prevent duplicate processing

**Note**: Delete this file to reset state and re-collect from beginning.

## Integration with Phase 2+

The normalized data is ready for Phase 2 analytics, enrichment, and RAG:

### Option 1: Query SQLite
```python
import sqlite3
conn = sqlite3.connect('./wazuh_alerts.db')
cursor = conn.execute("""
    SELECT * FROM alerts
    WHERE rule_level >= 7
    AND timestamp >= datetime('now', '-1 day')
""")
for row in cursor:
    # Process high-severity alerts from last 24h
    pass
```

### Option 2: Read JSONL Files
```python
import json
with open('./collected_alerts/alerts_2025-01-15.jsonl') as f:
    for line in f:
        alert = json.loads(line)
        # Process alert
```

### Option 3: Consume from Kafka (future)
```python
from kafka import KafkaConsumer
consumer = KafkaConsumer('wazuh.alerts.normalized')
for message in consumer:
    alert = json.loads(message.value)
    # Process alert in real-time
```

## Troubleshooting

### Connection Issues
```
IndexerConnectionError: Failed to connect to indexer
```
**Solution**: Check `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_PORT`, and network connectivity. Verify SSL settings.

### Authentication Errors
```
TransportError: 401 Unauthorized
```
**Solution**: Verify `WAZUH_INDEXER_USER` and `WAZUH_INDEXER_PASSWORD` are correct.

### No Alerts Collected
```
Collection complete. Total: 0 documents
```
**Solution**:
- Check if alerts exist in the time range: `curl -u admin:password https://indexer:9200/wazuh-alerts-*/_count`
- Verify `WAZUH_MIN_ALERT_LEVEL` is not filtering out all alerts
- Check state file timestamp (delete to reset)

### Performance Issues
For high-volume environments (>10k alerts/min):
- Increase `WAZUH_BATCH_SIZE` (e.g., 5000)
- Decrease `WAZUH_POLL_INTERVAL` (e.g., 60 seconds)
- Consider Kafka output for better scalability
- Use multiple collector instances with time-range sharding

## Development

### Project Structure
```
rag_wazuh/
├── wazuh_retrieval/          # Main module
│   ├── collectors/           # Data collection logic
│   │   ├── base.py          # Base collector class
│   │   └── alerts.py        # Alert collector
│   ├── schema/              # Schema transformation
│   │   ├── mappings.py      # Field mappings
│   │   └── transformer.py   # Transform logic
│   ├── tracking/            # State tracking
│   │   └── state.py         # State management
│   ├── output/              # Output handlers
│   │   ├── file_handler.py  # JSONL output
│   │   ├── sqlite_handler.py # SQLite output
│   │   └── kafka_handler.py  # Kafka output
│   ├── client.py            # OpenSearch client
│   ├── config.py            # Configuration
│   ├── scheduler.py         # Scheduling logic
│   ├── utils.py             # Utilities
│   └── exceptions.py        # Custom exceptions
├── main.py                  # Application entry point
├── requirements.txt         # Dependencies
└── .env.example            # Configuration template
```

### Running Tests (future)
```bash
pytest tests/
```

### Code Style
```bash
black wazuh_retrieval/
flake8 wazuh_retrieval/
```

## Roadmap

- [x] Phase 1: Data collection and normalization
- [ ] Phase 2: Threat intelligence enrichment (OpenCTI integration)
- [ ] Phase 3: RAG-based threat reporting with LLM
- [ ] Phase 4: Real-time alerting and correlation
- [ ] Historical backfill utility
- [ ] Prometheus metrics export
- [ ] Docker containerization

## License

[Your License Here]

## Contributing

Contributions welcome! Please open an issue or PR.

## Support

For issues or questions, please open a GitHub issue or contact [your-contact].
# wazuh-rag
