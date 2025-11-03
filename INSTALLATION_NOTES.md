# Installation Notes & Troubleshooting

## Quick Installation

```bash
pip install -r requirements.txt
```

## Known Issues and Solutions

### Issue 1: sentence-transformers Import Error

**Error:**
```
ImportError: cannot import name 'PreTrainedModel' from 'transformers'
```

**Root Cause:** Old Pillow version incompatible with transformers 4.57.1

**Solution:**
```bash
# Upgrade Pillow
pip install --upgrade Pillow>=12.0.0

# If that doesn't work, reinstall everything:
pip cache purge
pip uninstall -y transformers sentence-transformers Pillow
pip install sentence-transformers==5.1.2 transformers==4.57.1 Pillow>=12.0.0
```

### Issue 2: urllib3 Version Conflict

**Error:**
```
ERROR: opensearch-py 2.3.1 requires urllib3<2,>=1.21.1, but you have urllib3 2.5.0
```

**Solution:**
```bash
pip install "urllib3>=1.26.0,<2.0.0"
```

### Issue 3: OpenCTI GraphQL Error - "Cannot query field 'edges'"

**Error:**
```
GraphQL errors: Cannot query field "edges" on type "KillChainPhase"
```

**Status:** ✅ FIXED in knowledge_ingest/opencti_client.py (line 257-261)

The OpenCTI API structure changed - `killChainPhases` returns a direct list, not edges/node structure.

### Issue 4: OpenCTI Authentication Error

**Error:**
```
GraphQL errors: You must be logged in to do this.
```

**Solution:** Set your OpenCTI API token:

```bash
# Option 1: Environment variable (recommended)
export OPENCTI_TOKEN="your-api-token-here"

# Option 2: Edit config file
nano knowledge_ingest/config.yaml
# Update: api_token: "your-api-token-here"
```

**How to get OpenCTI token:**
1. Login to OpenCTI: http://100.114.206.116:8080
2. Go to Profile → API Access
3. Create new token or copy existing one

## Clean Installation (If All Else Fails)

```bash
# 1. Clear pip cache
pip cache purge

# 2. Uninstall problematic packages
pip uninstall -y sentence-transformers transformers torch Pillow urllib3

# 3. Install from requirements.txt
pip install -r requirements.txt

# 4. Verify installation
python3 -c "from sentence_transformers import SentenceTransformer; print('✓ Success')"
```

## Version Compatibility Matrix

| Package | Version | Notes |
|---------|---------|-------|
| sentence-transformers | 5.1.2 | Exact version required |
| transformers | 4.57.1 | Must match sentence-transformers |
| Pillow | ≥ 12.0.0 | Required for transformers image processing |
| urllib3 | ≥ 1.26, < 2.0 | opensearch-py requires < 2.0 |
| torch | ≥ 2.9.0 | PyTorch backend |
| faiss-cpu | ≥ 1.7.4 | Vector search (or faiss-gpu for CUDA) |
| numpy | ≥ 1.24.0 | Array operations |
| pyyaml | ≥ 6.0.1 | Config parsing |
| opensearch-py | 2.3.1 | Wazuh Indexer client |
| apscheduler | 3.10.4 | Job scheduling |
| python-dotenv | 1.0.0 | Environment variables |

## Testing After Installation

```bash
# Test Phase 1 (Wazuh)
python3 -c "from wazuh_retrieval import WazuhIndexerClient; print('✓ Phase 1 OK')"

# Test Phase 2 (Knowledge Ingestion)
python3 -c "from knowledge_ingest import OpenCTIClient, EmbeddingModel; print('✓ Phase 2 OK')"

# Test sentence-transformers specifically
python3 -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2'); print('✓ Model loads OK')"
```

## System Requirements

- **Python**: 3.8 or higher
- **OS**: Linux (tested on Ubuntu 22.04)
- **RAM**: Minimum 4GB (8GB recommended for embedding model)
- **Disk**: ~2GB for models and dependencies
- **Network**: Access to Wazuh Indexer (172.16.235.140:9200) and OpenCTI (100.114.206.116:8080)

## GPU Support (Optional)

To use GPU acceleration for embeddings:

```bash
# Replace faiss-cpu with faiss-gpu
pip uninstall faiss-cpu
pip install faiss-gpu>=1.7.4

# Update config.yaml
nano knowledge_ingest/config.yaml
# Change: device: "cuda"
```

**Requirements:**
- NVIDIA GPU with CUDA support
- CUDA drivers installed
- Compatible PyTorch with CUDA

## Getting Help

If issues persist:

1. Check logs: `logs/knowledge_ingest.log`
2. Run with debug: `python3 sync_opencti.py --log-level DEBUG`
3. Verify Python version: `python3 --version` (should be ≥ 3.8)
4. Check pip: `pip --version`
5. Review PROJECT.md for architecture details
