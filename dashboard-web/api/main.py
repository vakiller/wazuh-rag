#!/usr/bin/env python3
"""
Dashboard API Server
FastAPI backend for RAG Wazuh Dashboard
"""

import os
import json
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import psycopg2.extras
from psycopg2 import pool
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI(
    title="RAG Wazuh Dashboard API",
    description="AI-powered threat analysis dashboard backend",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create connection pool
try:
    connection_pool = psycopg2.pool.SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        host=os.getenv('DB_HOST', 'localhost'),
        port=os.getenv('DB_PORT', '5432'),
        database=os.getenv('DB_NAME', 'wazuh_rag'),
        user=os.getenv('DB_USER', 'wazuh_user'),
        password=os.getenv('DB_PASSWORD', '')
    )
    if connection_pool:
        print("Connection pool created successfully")
except Exception as e:
    print(f"Error creating connection pool: {e}")
    connection_pool = None

# Database connection context manager
@contextmanager
def get_db_connection():
    """Get PostgreSQL database connection from pool"""
    conn = None
    try:
        if connection_pool:
            conn = connection_pool.getconn()
        else:
            # Fallback to direct connection if pool fails
            conn = psycopg2.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                port=os.getenv('DB_PORT', '5432'),
                database=os.getenv('DB_NAME', 'wazuh_rag'),
                user=os.getenv('DB_USER', 'wazuh_user'),
                password=os.getenv('DB_PASSWORD', '')
            )
        yield conn
    finally:
        if conn:
            if connection_pool:
                connection_pool.putconn(conn)
            else:
                conn.close()

# Helper functions
def row_to_dict(row: Dict) -> Dict[str, Any]:
    """Convert database row to dictionary"""
    result = dict(row)
    # PostgreSQL returns arrays and JSONB natively, no parsing needed
    return result

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "RAG Wazuh Dashboard API",
        "version": "1.0.0"
    }

@app.get("/api/health")
async def health_check():
    """Detailed health check"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"error: {str(e)}"

    return {
        "status": "online",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

# IMPORTANT: Specific routes must come BEFORE path parameter routes
# Define /stats, /recent, /high-risk, /timeseries BEFORE /{report_id}

@app.get("/api/reports/stats")
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                # Total reports and average risk score
                cursor.execute("""
                    SELECT
                        COUNT(*) as total_reports,
                        COALESCE(AVG(risk_score), 0)::int as avg_risk_score,
                        COUNT(*) FILTER (WHERE risk_score >= 70) as high_risk_count,
                        COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '24 hours') as recent_24h_count,
                        COUNT(*) FILTER (WHERE LOWER(severity) = 'critical') as critical_count,
                        COUNT(*) FILTER (WHERE LOWER(severity) = 'high') as high_count,
                        COUNT(*) FILTER (WHERE LOWER(severity) = 'medium') as medium_count,
                        COUNT(*) FILTER (WHERE LOWER(severity) = 'low') as low_count
                    FROM reports
                """)
                stats = dict(cursor.fetchone())
            return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/recent")
async def get_recent_reports(limit: int = Query(10, ge=1, le=50)):
    """Get most recent reports"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    "SELECT * FROM reports ORDER BY created_at DESC LIMIT %s",
                    (limit,)
                )
                reports = [row_to_dict(row) for row in cursor.fetchall()]
            return reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/high-risk")
async def get_high_risk_reports(min_score: int = Query(70, ge=0, le=100)):
    """Get high-risk reports"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute(
                    """SELECT * FROM reports
                       WHERE risk_score >= %s
                       ORDER BY risk_score DESC, created_at DESC""",
                    (min_score,)
                )
                reports = [row_to_dict(row) for row in cursor.fetchall()]
            return reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/timeseries")
async def get_timeseries_data(days: int = Query(7, ge=1, le=30)):
    """Get time series data for charts"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    SELECT
                        DATE(created_at) as date,
                        COUNT(*) as reports,
                        COALESCE(AVG(risk_score), 0)::int as avgRisk
                    FROM reports
                    WHERE created_at >= NOW() - INTERVAL '%s days'
                    GROUP BY DATE(created_at)
                    ORDER BY DATE(created_at)
                """, (days,))
                data = [dict(row) for row in cursor.fetchall()]
            return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports")
async def get_reports(
    limit: int = Query(20, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    min_risk_score: Optional[int] = Query(None, ge=0, le=100)
):
    """Get all reports with filtering"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                query = "SELECT * FROM reports WHERE 1=1"
                params = []

                if severity:
                    query += " AND LOWER(severity) = LOWER(%s)"
                    params.append(severity)

                if min_risk_score is not None:
                    query += " AND risk_score >= %s"
                    params.append(min_risk_score)

                query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
                params.extend([limit, offset])

                cursor.execute(query, params)
                reports = [row_to_dict(row) for row in cursor.fetchall()]
            return reports
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/{report_id}")
async def get_report_by_id(report_id: int):
    """Get single report by ID"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("SELECT * FROM reports WHERE id = %s", (report_id,))
                report = cursor.fetchone()

                if not report:
                    raise HTTPException(status_code=404, detail="Report not found")

                result = row_to_dict(report)
            return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Pydantic models
class TelegramConfig(BaseModel):
    bot_token: str
    chat_id: str
    enabled: bool
    min_severity: str = "medium"

class SystemStatus(BaseModel):
    wazuh: Dict[str, Any]
    opencti: Dict[str, Any]
    llm: Dict[str, Any]

# Config endpoints
@app.get("/api/config/status")
async def get_system_status():
    """Get connection status of all services"""
    status = {
        "wazuh": {"status": "unknown", "message": ""},
        "opencti": {"status": "unknown", "message": ""},
        "llm": {"status": "unknown", "message": ""},
        "postgresql": {"status": "unknown", "message": ""}
    }

    # Check Wazuh Indexer
    try:
        wazuh_host = os.getenv('WAZUH_INDEXER_HOST')
        wazuh_port = os.getenv('WAZUH_INDEXER_PORT', '9200')
        wazuh_user = os.getenv('WAZUH_INDEXER_USER', 'admin')

        if not wazuh_host:
            status["wazuh"] = {"status": "disconnected", "message": "Not configured in environment"}
        else:
            # Try to connect to Wazuh Indexer
            wazuh_url = f"https://{wazuh_host}:{wazuh_port}"
            verify_ssl = os.getenv('WAZUH_INDEXER_VERIFY_CERTS', 'false').lower() == 'true'

            response = requests.get(
                wazuh_url,
                auth=(wazuh_user, os.getenv('WAZUH_INDEXER_PASSWORD', '')),
                verify=verify_ssl,
                timeout=5
            )

            if response.status_code == 200:
                cluster_info = response.json()
                status["wazuh"] = {
                    "status": "connected",
                    "host": f"{wazuh_host}:{wazuh_port}",
                    "user": wazuh_user,
                    "cluster_name": cluster_info.get('cluster_name', 'Unknown'),
                    "version": cluster_info.get('version', {}).get('number', 'Unknown'),
                    "message": "Connected successfully"
                }
            else:
                status["wazuh"] = {
                    "status": "error",
                    "host": f"{wazuh_host}:{wazuh_port}",
                    "message": f"HTTP {response.status_code}"
                }
    except requests.exceptions.RequestException as e:
        status["wazuh"] = {
            "status": "error",
            "host": f"{wazuh_host}:{wazuh_port}" if wazuh_host else "Not configured",
            "message": f"Connection failed: {str(e)[:100]}"
        }
    except Exception as e:
        status["wazuh"] = {"status": "error", "message": str(e)[:100]}

    # Check OpenCTI
    try:
        opencti_url = os.getenv('OPENCTI_URL')
        opencti_token = os.getenv('OPENCTI_TOKEN')

        if not opencti_url:
            status["opencti"] = {"status": "disconnected", "message": "Not configured in environment"}
        else:
            # Try to connect to OpenCTI
            headers = {"Authorization": f"Bearer {opencti_token}"} if opencti_token else {}
            verify_ssl = os.getenv('OPENCTI_VERIFY_SSL', 'true').lower() == 'true'

            response = requests.get(
                f"{opencti_url}/graphql",
                headers=headers,
                verify=verify_ssl,
                timeout=5
            )

            if response.status_code in [200, 400, 405]:  # 400/405 means API is reachable
                status["opencti"] = {
                    "status": "connected",
                    "url": opencti_url,
                    "has_token": bool(opencti_token),
                    "message": "Connected successfully"
                }
            else:
                status["opencti"] = {
                    "status": "error",
                    "url": opencti_url,
                    "message": f"HTTP {response.status_code}"
                }
    except requests.exceptions.RequestException as e:
        status["opencti"] = {
            "status": "error",
            "url": opencti_url if opencti_url else "Not configured",
            "message": f"Connection failed: {str(e)[:100]}"
        }
    except Exception as e:
        status["opencti"] = {"status": "error", "message": str(e)[:100]}

    # Check LLM Service (Ollama)
    try:
        llm_url = os.getenv('LLM_BASE_URL')
        llm_model = os.getenv('LLM_MODEL')

        if not llm_url:
            status["llm"] = {"status": "disconnected", "message": "Not configured in environment"}
        else:
            # Try to connect to Ollama API
            response = requests.get(
                f"{llm_url}/api/tags",
                timeout=5
            )

            if response.status_code == 200:
                models_data = response.json()
                available_models = [m.get('name') for m in models_data.get('models', [])]
                model_exists = llm_model in available_models

                status["llm"] = {
                    "status": "connected",
                    "url": llm_url,
                    "model": llm_model,
                    "model_available": model_exists,
                    "available_models_count": len(available_models),
                    "message": "Connected successfully" if model_exists else f"Warning: Model '{llm_model}' not found"
                }
            else:
                status["llm"] = {
                    "status": "error",
                    "url": llm_url,
                    "model": llm_model,
                    "message": f"HTTP {response.status_code}"
                }
    except requests.exceptions.RequestException as e:
        status["llm"] = {
            "status": "error",
            "url": llm_url if llm_url else "Not configured",
            "model": llm_model if llm_model else "Not configured",
            "message": f"Connection failed: {str(e)[:100]}"
        }
    except Exception as e:
        status["llm"] = {"status": "error", "message": str(e)[:100]}

    # Check PostgreSQL
    try:
        db_host = os.getenv('DB_HOST', 'localhost')
        db_port = os.getenv('DB_PORT', '5432')
        db_name = os.getenv('DB_NAME', 'wazuh_rag')
        db_user = os.getenv('DB_USER', 'wazuh_user')

        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Get PostgreSQL version
                cursor.execute("SELECT version()")
                version = cursor.fetchone()[0]
                version_short = version.split(',')[0].replace('PostgreSQL ', '')

                # Get database size
                cursor.execute(f"SELECT pg_database_size('{db_name}')")
                db_size_bytes = cursor.fetchone()[0]
                db_size_mb = round(db_size_bytes / 1024 / 1024, 2)

                # Count reports
                cursor.execute("SELECT COUNT(*) FROM reports")
                reports_count = cursor.fetchone()[0]

        status["postgresql"] = {
            "status": "connected",
            "host": f"{db_host}:{db_port}",
            "database": db_name,
            "user": db_user,
            "version": version_short,
            "size_mb": db_size_mb,
            "reports_count": reports_count,
            "message": "Connected successfully"
        }
    except Exception as e:
        status["postgresql"] = {
            "status": "error",
            "host": f"{db_host}:{db_port}" if db_host else "Not configured",
            "database": db_name if db_name else "Not configured",
            "message": f"Connection failed: {str(e)[:100]}"
        }

    return status

@app.get("/api/config/telegram")
async def get_telegram_config():
    """Get Telegram notification configuration"""
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS telegram_config (
                        id SERIAL PRIMARY KEY,
                        bot_token TEXT,
                        chat_id TEXT,
                        enabled BOOLEAN DEFAULT false,
                        min_severity TEXT DEFAULT 'medium',
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.commit()

                cursor.execute("SELECT * FROM telegram_config ORDER BY id DESC LIMIT 1")
                config = cursor.fetchone()

                if config:
                    return {
                        "bot_token": config['bot_token'] or "",
                        "chat_id": config['chat_id'] or "",
                        "enabled": config['enabled'],
                        "min_severity": config['min_severity']
                    }
                else:
                    return {
                        "bot_token": "",
                        "chat_id": "",
                        "enabled": False,
                        "min_severity": "medium"
                    }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/config/telegram")
async def save_telegram_config(config: TelegramConfig):
    """Save Telegram notification configuration"""
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS telegram_config (
                        id SERIAL PRIMARY KEY,
                        bot_token TEXT,
                        chat_id TEXT,
                        enabled BOOLEAN DEFAULT false,
                        min_severity TEXT DEFAULT 'medium',
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                cursor.execute("""
                    INSERT INTO telegram_config (bot_token, chat_id, enabled, min_severity, updated_at)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
                """, (config.bot_token, config.chat_id, config.enabled, config.min_severity))
                conn.commit()

        return {"success": True, "message": "Configuration saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/config/telegram/test")
async def test_telegram_config(config: TelegramConfig):
    """Test Telegram notification"""
    try:
        if not config.bot_token or not config.chat_id:
            raise HTTPException(status_code=400, detail="Bot token and chat ID are required")

        # Send test message
        url = f"https://api.telegram.org/bot{config.bot_token}/sendMessage"
        message = (
            "🔔 *RAG Wazuh Alert Test*\n\n"
            "This is a test notification from your RAG Wazuh Dashboard.\n\n"
            "✅ Configuration is working correctly!\n"
            f"📊 Minimum Severity: *{config.min_severity.upper()}*\n"
            f"🔗 Dashboard: {os.getenv('DASHBOARD_URL', 'http://localhost:3000')}"
        )

        response = requests.post(url, json={
            "chat_id": config.chat_id,
            "text": message,
            "parse_mode": "Markdown"
        }, timeout=10)

        if response.status_code == 200:
            return {"success": True, "message": "Test message sent successfully"}
        else:
            error_data = response.json()
            raise HTTPException(
                status_code=400,
                detail=f"Telegram API error: {error_data.get('description', 'Unknown error')}"
            )
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Connection error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
