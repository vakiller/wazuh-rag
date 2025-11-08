# RAG Wazuh System - Docker Deployment Guide

Complete guide for deploying the RAG-based Threat Analysis System using Docker and Docker Compose.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Deployment](#deployment)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)
9. [Maintenance](#maintenance)

---

## Overview

The dockerized RAG Wazuh System consists of:

- **PostgreSQL Database**: External database for all data storage (alerts, knowledge, reports)
- **RAG Wazuh Application**: Runs all three components via cron:
  - **Phase 1**: Wazuh alert retrieval (every 5 minutes)
  - **Phase 2**: OpenCTI knowledge ingestion (every 7 days)
  - **Phase 3**: LLM-based threat analysis (hourly and daily)
- **pgAdmin** (Optional): Web-based database management interface

### Key Features

✅ **No manual cronjob setup** - All scheduling handled by Docker container
✅ **External PostgreSQL** - Easy database access and backup
✅ **Environment-based configuration** - All settings via `.env` file
✅ **Persistent data** - FAISS index, logs, and database stored in volumes
✅ **Health checks** - Automatic monitoring of service health
✅ **One-command deployment** - `docker-compose up -d`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose Stack                      │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────┐      ┌──────────────────────────┐  │
│  │   PostgreSQL DB     │◄─────┤  RAG Wazuh Application  │  │
│  │   (Port 5432)       │      │  (Cron-based)            │  │
│  │                     │      │                          │  │
│  │  - alerts           │      │  Cron Jobs:              │  │
│  │  - knowledge        │      │  • wazuh_retrieval.py    │  │
│  │  - reports          │      │    (every 5 min)         │  │
│  │  - sync_state       │      │  • sync_opencti.py       │  │
│  └─────────────────────┘      │    (every 7 days)        │  │
│           ▲                   │  • analyze_threats.py    │  │
│           │                   │    (hourly + daily)      │  │
│           │                   └──────────────────────────┘  │
│  ┌─────────────────────┐               │                    │
│  │  pgAdmin (Optional) │◄──────────────┘                    │
│  │  (Port 5050)        │                                    │
│  └─────────────────────┘                                    │
│                                                               │
│  Persistent Volumes:                                          │
│  • postgres_data   - Database files                          │
│  • faiss_data      - FAISS vector index                      │
│  • app_logs        - Application logs                        │
│  • cron_logs       - Cron execution logs                     │
│                                                               │
└───────────────────────────────────────────────────────────────┘

External Services (Not in Docker):
┌────────────────────────────────────────────────────────────┐
│  • Wazuh Indexer     (172.16.235.140:9200)                 │
│  • OpenCTI           (100.114.206.116:8080)                │
│  • Ollama LLM        (192.168.1.11:11434)                  │
└────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### System Requirements

- **Operating System**: Linux, macOS, or Windows with WSL2
- **Docker**: Version 20.10 or higher
- **Docker Compose**: Version 2.0 or higher
- **Memory**: Minimum 4GB RAM (8GB recommended for Phase 2 embedding models)
- **Disk Space**: 10GB minimum (for database, FAISS index, and logs)

### External Services

Ensure the following services are accessible:

1. **Wazuh Indexer** (OpenSearch/Elasticsearch)
   - Host and port accessible from Docker container
   - Valid credentials with read access to `wazuh-alerts-*` indices

2. **OpenCTI** (Threat Intelligence Platform)
   - GraphQL API accessible
   - Valid API token with read permissions

3. **Ollama LLM Service**
   - Running with a suitable model (e.g., llama3.1:8b-instruct-q4_K_M)
   - API accessible from Docker container

### Verify Docker Installation

```bash
docker --version
docker-compose --version
```

---

## Quick Start

### 1. Clone or Navigate to Project Directory

```bash
cd /path/to/rag_wazuh
```

### 2. Create Environment Configuration

Copy the template and edit with your settings:

```bash
cp .env.docker .env
nano .env  # or vim, code, etc.
```

**Required Settings** (update these):

```env
# Database
DB_PASSWORD=your_secure_db_password

# Wazuh Indexer
WAZUH_INDEXER_HOST=your.wazuh.host
WAZUH_INDEXER_PASSWORD=your_wazuh_password

# OpenCTI
OPENCTI_URL=http://your.opencti.host:8080
OPENCTI_TOKEN=your_opencti_token

# LLM
LLM_BASE_URL=http://your.llm.host:11434
```

### 3. Start the Services

```bash
# Start in detached mode
docker-compose up -d

# View logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f wazuh-rag-app
```

### 4. Verify Deployment

```bash
# Check service status
docker-compose ps

# Check health status
docker-compose ps | grep healthy

# View cron logs
docker-compose exec wazuh-rag-app tail -f /var/log/cron/cron.log
```

### 5. Access Database (Optional)

**Via pgAdmin Web UI**:

```bash
# Start with pgAdmin
docker-compose --profile management up -d

# Access at: http://localhost:5050
# Login: admin@wazuh-rag.local / (password from .env)
```

**Via psql**:

```bash
docker-compose exec postgres psql -U wazuh_user -d wazuh_rag

# Example queries:
SELECT COUNT(*) FROM alerts;
SELECT COUNT(*) FROM knowledge;
SELECT * FROM reports ORDER BY created_at DESC LIMIT 5;
```

---

## Configuration

### Environment Variables Reference

See `.env.docker` for all available configuration options.

#### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_HOST` | postgres | PostgreSQL hostname |
| `DB_PORT` | 5432 | PostgreSQL port |
| `DB_NAME` | wazuh_rag | Database name |
| `DB_USER` | wazuh_user | Database user |
| `DB_PASSWORD` | *required* | Database password |

#### Wazuh Indexer

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | *required* | Wazuh Indexer hostname |
| `WAZUH_INDEXER_PORT` | 9200 | Wazuh Indexer port |
| `WAZUH_INDEXER_USER` | admin | Indexer username |
| `WAZUH_INDEXER_PASSWORD` | *required* | Indexer password |
| `WAZUH_INDEXER_SSL` | true | Use SSL/TLS |
| `WAZUH_INDEXER_VERIFY_CERTS` | false | Verify SSL certificates |
| `WAZUH_POLL_INTERVAL` | 300 | Collection interval (seconds) |
| `WAZUH_BATCH_SIZE` | 1000 | Alerts per batch |
| `WAZUH_MIN_ALERT_LEVEL` | 0 | Minimum alert level (0-15) |

#### OpenCTI

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCTI_URL` | *required* | OpenCTI base URL |
| `OPENCTI_TOKEN` | *required* | OpenCTI API token |
| `OPENCTI_VERIFY_SSL` | false | Verify SSL certificates |

#### LLM Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_BASE_URL` | *required* | Ollama API base URL |
| `LLM_MODEL` | llama3.1:8b-instruct-q4_K_M | Model name |
| `LLM_TEMPERATURE` | 0.1 | Sampling temperature |
| `LLM_TIMEOUT` | 120 | Request timeout (seconds) |

### Cron Schedule Reference

**Configured in `docker/crontab`** (requires image rebuild to change):

| Job | Schedule | Description |
|-----|----------|-------------|
| wazuh_retrieval.py | `*/5 * * * *` | Every 5 minutes |
| sync_opencti.py | `0 2 * * 0` | Every Sunday at 2 AM |
| analyze_threats.py (hourly) | `15 * * * *` | Every hour at :15 |
| analyze_threats.py (daily) | `0 3 * * *` | Every day at 3 AM |

**To modify schedules**:

1. Edit `docker/crontab`
2. Rebuild image: `docker-compose build`
3. Restart services: `docker-compose up -d`

---

## Deployment

### Production Deployment

#### Step 1: Prepare Environment

```bash
# Create production directory
mkdir -p /opt/wazuh-rag
cd /opt/wazuh-rag

# Copy files
cp -r /path/to/rag_wazuh/* .

# Set proper permissions
chmod 600 .env
chmod +x docker/entrypoint.sh
```

#### Step 2: Configure Environment

```bash
cp .env.docker .env
# Edit .env with production settings
```

**Security Best Practices**:

- Use strong passwords (minimum 16 characters)
- Set `WAZUH_INDEXER_VERIFY_CERTS=true` in production
- Set `OPENCTI_VERIFY_SSL=true` if using HTTPS
- Restrict database port exposure (remove `ports:` section in docker-compose.yml)

#### Step 3: Initialize Database

```bash
# First startup will run init-db.sql automatically
docker-compose up -d postgres

# Wait for database to be ready
docker-compose logs -f postgres
# Look for: "database system is ready to accept connections"
```

#### Step 4: Start Application

```bash
docker-compose up -d

# Monitor startup
docker-compose logs -f wazuh-rag-app
```

#### Step 5: Verify Operation

```bash
# Check all services are healthy
docker-compose ps

# Verify database tables
docker-compose exec postgres psql -U wazuh_user -d wazuh_rag -c "\dt"

# Should show: alerts, knowledge, reports, sync_state

# Check cron is running
docker-compose exec wazuh-rag-app crontab -l
```

### Scaling Considerations

For high-volume environments:

1. **Increase Poll Interval** (if needed):
   ```env
   WAZUH_POLL_INTERVAL=60  # 1 minute for high-priority
   ```

2. **Increase Batch Size**:
   ```env
   WAZUH_BATCH_SIZE=5000  # For high throughput
   ```

3. **Database Tuning**:
   - Increase PostgreSQL `max_connections`
   - Tune `shared_buffers` and `work_mem`
   - Consider connection pooling (pgBouncer)

4. **Resource Limits** (add to docker-compose.yml):
   ```yaml
   services:
     wazuh-rag-app:
       deploy:
         resources:
           limits:
             cpus: '2'
             memory: 4G
   ```

---

## Monitoring

### Logs

**View all logs**:
```bash
docker-compose logs -f
```

**View specific service**:
```bash
docker-compose logs -f wazuh-rag-app
docker-compose logs -f postgres
```

**View cron execution logs**:
```bash
docker-compose exec wazuh-rag-app tail -f /var/log/cron/cron.log
```

**View application component logs**:
```bash
# Inside container
docker-compose exec wazuh-rag-app ls -lh /app/logs/

# View specific log
docker-compose exec wazuh-rag-app tail -f /app/logs/phase1_wazuh_retrieval.log
docker-compose exec wazuh-rag-app tail -f /app/logs/phase2_knowledge_ingest.log
docker-compose exec wazuh-rag-app tail -f /app/logs/phase3_analysis.log
```

### Health Checks

**Check service health**:
```bash
docker-compose ps
# Look for "healthy" status
```

**Manual health check**:
```bash
# Database
docker-compose exec postgres pg_isready -U wazuh_user

# Cron daemon
docker-compose exec wazuh-rag-app pgrep -f cron
```

### Database Queries

**Alert statistics**:
```sql
SELECT COUNT(*) as total_alerts,
       COUNT(DISTINCT agent_id) as unique_agents,
       MIN(timestamp) as earliest,
       MAX(timestamp) as latest
FROM alerts;
```

**Knowledge base statistics**:
```sql
SELECT entity_type, COUNT(*) as count
FROM knowledge
GROUP BY entity_type
ORDER BY count DESC;
```

**Recent reports**:
```sql
SELECT id, created_at, alerts_count, risk_score, summary
FROM reports
ORDER BY created_at DESC
LIMIT 10;
```

---

## Troubleshooting

### Common Issues

#### 1. Container Won't Start

**Symptoms**: `docker-compose up` fails or exits immediately

**Solutions**:

```bash
# Check logs
docker-compose logs

# Verify environment variables
docker-compose config

# Check for port conflicts
sudo netstat -tulpn | grep 5432
```

#### 2. Database Connection Failed

**Symptoms**: "could not connect to PostgreSQL"

**Solutions**:

```bash
# Verify database is running
docker-compose ps postgres

# Check database logs
docker-compose logs postgres

# Test connection manually
docker-compose exec postgres psql -U wazuh_user -d wazuh_rag

# Verify credentials in .env
cat .env | grep DB_
```

#### 3. Wazuh Indexer Connection Failed

**Symptoms**: "Failed to connect to Wazuh Indexer"

**Solutions**:

```bash
# Test connectivity from container
docker-compose exec wazuh-rag-app curl -k -u admin:password https://WAZUH_HOST:9200

# Verify environment variables
docker-compose exec wazuh-rag-app printenv | grep WAZUH

# Check SSL settings
# If using self-signed certs, set WAZUH_INDEXER_VERIFY_CERTS=false
```

#### 4. Cron Jobs Not Running

**Symptoms**: No data being collected

**Solutions**:

```bash
# Check cron is running
docker-compose exec wazuh-rag-app pgrep cron

# Verify crontab
docker-compose exec wazuh-rag-app crontab -l

# Check cron logs
docker-compose exec wazuh-rag-app tail -100 /var/log/cron/cron.log

# Manually test a job
docker-compose exec wazuh-rag-app python3 /app/wazuh_retrieval.py
```

#### 5. FAISS Index Issues

**Symptoms**: "Failed to load FAISS index"

**Solutions**:

```bash
# Check FAISS index exists
docker-compose exec wazuh-rag-app ls -lh /app/data/faiss_index/

# Remove corrupted index (will rebuild on next sync)
docker-compose exec wazuh-rag-app rm /app/data/faiss_index/knowledge.index

# Manually trigger sync
docker-compose exec wazuh-rag-app python3 /app/sync_opencti.py --full
```

### Debug Mode

Enable debug logging:

```bash
# Stop services
docker-compose down

# Edit .env
LOG_LEVEL=DEBUG

# Restart
docker-compose up -d

# View detailed logs
docker-compose logs -f wazuh-rag-app
```

### Reset Everything

**⚠️ WARNING: This will delete all data**

```bash
# Stop and remove containers, volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all

# Start fresh
docker-compose up -d
```

---

## Maintenance

### Backup

#### Database Backup

```bash
# Create backup
docker-compose exec postgres pg_dump -U wazuh_user wazuh_rag > backup_$(date +%Y%m%d).sql

# Restore backup
docker-compose exec -T postgres psql -U wazuh_user wazuh_rag < backup_20251107.sql
```

#### FAISS Index Backup

```bash
# Backup FAISS data
docker cp wazuh-rag-app:/app/data/faiss_index ./faiss_backup_$(date +%Y%m%d)

# Restore
docker cp ./faiss_backup_20251107 wazuh-rag-app:/app/data/faiss_index
```

### Updates

#### Update Application Code

```bash
# Pull latest code
git pull

# Rebuild image
docker-compose build --no-cache

# Restart services
docker-compose down
docker-compose up -d
```

#### Update Python Dependencies

```bash
# Edit requirements.txt
# Then rebuild
docker-compose build --no-cache wazuh-rag-app
docker-compose up -d wazuh-rag-app
```

### Cleanup

#### Remove Old Logs

```bash
# Inside container
docker-compose exec wazuh-rag-app find /app/logs -name "*.log" -mtime +30 -delete
docker-compose exec wazuh-rag-app find /var/log/cron -name "*.log" -mtime +30 -delete
```

#### Vacuum Database

```bash
docker-compose exec postgres psql -U wazuh_user -d wazuh_rag -c "VACUUM ANALYZE;"
```

---

## Additional Resources

- **Project Documentation**: See `PROJECT.md` for architecture details
- **Installation Notes**: See `INSTALLATION_NOTES.md` for development setup
- **Phase Summaries**: See `PHASE_4.2_SUMMARY.md` for latest updates

---

## Support

For issues, questions, or contributions:

1. Check the troubleshooting section above
2. Review application logs
3. Consult the project documentation
4. Check GitHub issues (if applicable)

---

**Generated**: 2025-11-07
**Version**: 1.0.0
**Docker Compose Version**: 3.8
