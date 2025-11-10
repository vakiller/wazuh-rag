#!/usr/bin/env python3
"""
Telegram Notification Module
Sends alerts to Telegram when new threat reports are generated
"""

import os
import requests
import psycopg2
import psycopg2.extras
from typing import Dict, Any, Optional
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_telegram_config() -> Optional[Dict[str, Any]]:
    """Fetch Telegram configuration from database"""
    conn = None
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'localhost'),
            port=os.getenv('DB_PORT', '5432'),
            database=os.getenv('DB_NAME', 'wazuh_rag'),
            user=os.getenv('DB_USER', 'wazuh_user'),
            password=os.getenv('DB_PASSWORD', '')
        )

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
            cursor.execute("""
                SELECT bot_token, chat_id, enabled, min_severity
                FROM telegram_config
                ORDER BY id DESC
                LIMIT 1
            """)
            config = cursor.fetchone()

        if config and config['enabled']:
            return dict(config)
        return None

    except Exception as e:
        logger.error(f"Failed to get Telegram config: {e}")
        return None
    finally:
        if conn:
            conn.close()


def should_notify(severity: str, min_severity: str) -> bool:
    """Check if severity level meets minimum threshold"""
    severity_levels = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }

    current_level = severity_levels.get(severity.lower(), 0)
    min_level = severity_levels.get(min_severity.lower(), 2)

    return current_level >= min_level


def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level"""
    severity_emojis = {
        'critical': '🚨',
        'high': '⚠️',
        'medium': '⚡',
        'low': 'ℹ️'
    }
    return severity_emojis.get(severity.lower(), '📊')


def send_telegram_notification(
    report_id: int,
    severity: str,
    risk_score: int,
    summary: str,
    alerts_count: int,
    hosts_count: int
) -> bool:
    """
    Send Telegram notification for new threat report

    Args:
        report_id: Report ID
        severity: Severity level
        risk_score: Risk score (0-100)
        summary: Brief summary of the threat
        alerts_count: Number of alerts
        hosts_count: Number of affected hosts

    Returns:
        True if notification sent successfully, False otherwise
    """
    try:
        # Get Telegram configuration
        config = get_telegram_config()
        if not config:
            logger.debug("Telegram notifications are disabled")
            return False

        # Check if severity meets minimum threshold
        if not should_notify(severity, config['min_severity']):
            logger.debug(f"Severity {severity} below threshold {config['min_severity']}")
            return False

        # Get dashboard URL from environment or use default
        dashboard_url = os.getenv('DASHBOARD_URL', 'http://localhost:3000')
        report_url = f"{dashboard_url}/report/{report_id}"

        # Get emoji for severity
        emoji = get_severity_emoji(severity)

        # Build message
        message = (
            f"{emoji} *New Threat Alert*\n\n"
            f"*Severity:* {severity.upper()}\n"
            f"*Risk Score:* {risk_score}/100\n"
            f"*Alerts:* {alerts_count}\n"
            f"*Affected Hosts:* {hosts_count}\n\n"
            f"*Summary:*\n{summary}\n\n"
            f"[View Full Report]({report_url})"
        )

        # Send to Telegram
        api_url = f"https://api.telegram.org/bot{config['bot_token']}/sendMessage"
        response = requests.post(
            api_url,
            json={
                'chat_id': config['chat_id'],
                'text': message,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': False
            },
            timeout=10
        )

        if response.status_code == 200:
            logger.info(f"Telegram notification sent for report {report_id}")
            return True
        else:
            logger.error(f"Telegram API error: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")
        return False


if __name__ == "__main__":
    # Test notification
    send_telegram_notification(
        report_id=999,
        severity="high",
        risk_score=85,
        summary="Test threat detected on multiple hosts. Potential lateral movement observed.",
        alerts_count=15,
        hosts_count=3
    )
