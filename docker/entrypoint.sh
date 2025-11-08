#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "RAG Wazuh System - Starting..."
echo "=========================================="

# Wait for PostgreSQL to be ready
echo -e "${YELLOW}Waiting for PostgreSQL...${NC}"
until PGPASSWORD=$DB_PASSWORD psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -c '\q' 2>/dev/null; do
  echo "PostgreSQL is unavailable - sleeping"
  sleep 2
done

echo -e "${GREEN}PostgreSQL is ready!${NC}"

# Verify database tables exist
echo -e "${YELLOW}Verifying database schema...${NC}"
TABLE_COUNT=$(PGPASSWORD=$DB_PASSWORD psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('alerts', 'knowledge', 'reports', 'sync_state')" | tr -d ' ')

if [ "$TABLE_COUNT" -eq "4" ]; then
    echo -e "${GREEN}All database tables exist${NC}"
else
    echo -e "${YELLOW}Database tables not fully initialized. Found $TABLE_COUNT/4 tables${NC}"
    echo -e "${YELLOW}Make sure init-db.sql was executed during first startup${NC}"
fi

# Test Wazuh Indexer connection
echo -e "${YELLOW}Testing Wazuh Indexer connection...${NC}"
if [ -n "$WAZUH_INDEXER_HOST" ]; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -u "${WAZUH_INDEXER_USER}:${WAZUH_INDEXER_PASSWORD}" \
        "https://${WAZUH_INDEXER_HOST}:${WAZUH_INDEXER_PORT}/_cluster/health" || echo "000")

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ]; then
        echo -e "${GREEN}Wazuh Indexer is reachable${NC}"
    else
        echo -e "${RED}WARNING: Cannot reach Wazuh Indexer at ${WAZUH_INDEXER_HOST}:${WAZUH_INDEXER_PORT}${NC}"
        echo -e "${YELLOW}HTTP Code: $HTTP_CODE${NC}"
    fi
else
    echo -e "${YELLOW}WAZUH_INDEXER_HOST not set, skipping connection test${NC}"
fi

# Test OpenCTI connection
echo -e "${YELLOW}Testing OpenCTI connection...${NC}"
if [ -n "$OPENCTI_URL" ] && [ -n "$OPENCTI_TOKEN" ]; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${OPENCTI_TOKEN}" \
        "${OPENCTI_URL}/graphql" || echo "000")

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "400" ]; then
        echo -e "${GREEN}OpenCTI is reachable${NC}"
    else
        echo -e "${RED}WARNING: Cannot reach OpenCTI at ${OPENCTI_URL}${NC}"
        echo -e "${YELLOW}HTTP Code: $HTTP_CODE${NC}"
    fi
else
    echo -e "${YELLOW}OpenCTI configuration not set, skipping connection test${NC}"
fi

# Test LLM connection
echo -e "${YELLOW}Testing LLM connection...${NC}"
if [ -n "$LLM_BASE_URL" ]; then
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${LLM_BASE_URL}/api/tags" || echo "000")

    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "${GREEN}LLM service is reachable${NC}"
    else
        echo -e "${RED}WARNING: Cannot reach LLM at ${LLM_BASE_URL}${NC}"
        echo -e "${YELLOW}HTTP Code: $HTTP_CODE${NC}"
    fi
else
    echo -e "${YELLOW}LLM_BASE_URL not set, skipping connection test${NC}"
fi

# Create cron environment file
echo -e "${YELLOW}Setting up cron environment...${NC}"
printenv | grep -v "no_proxy" | sed 's/^\(.*\)$/export \1/g' > /etc/environment

# Display cron schedule
echo -e "${GREEN}Cron jobs configured:${NC}"
crontab -l

echo "=========================================="
echo -e "${GREEN}Initialization complete!${NC}"
echo "=========================================="
echo ""
echo "Components:"
echo "  - Wazuh Retrieval: Every 5 minutes"
echo "  - Knowledge Ingest: Every 7 days (Sunday 2 AM)"
echo "  - LLM Analysis: Every 5 minutes (testing mode)"
echo ""
echo "Logs:"
echo "  - Cron: /var/log/cron/cron.log"
echo "  - Application: /app/logs/"
echo ""
echo "Starting cron daemon..."
echo "=========================================="

# Execute the main command
exec "$@"
