"""
Pre-Parsing Layer for LLM Analysis

Performs deterministic extraction of IOCs and metadata from alerts
BEFORE sending to LLM. This ensures critical information is captured
even with smaller/quantized models.
"""

import re
import logging
from typing import Dict, List, Any, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class AlertPreprocessor:
    """
    Extracts structured information from alerts using deterministic methods
    """

    # Regex patterns for IOC extraction
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
    MITRE_PATTERN = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')
    EVENT_ID_PATTERN = re.compile(r'\b(?:Event ID|EventID|event_id)[\s:]+(\d+)\b', re.IGNORECASE)

    # Windows registry path pattern
    REGISTRY_PATTERN = re.compile(
        r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)'
        r'(?:\\[^\s<>"|?*]+)+\b',
        re.IGNORECASE
    )

    # File path patterns (Windows and Linux)
    WINDOWS_PATH_PATTERN = re.compile(r'\b[A-Za-z]:\\(?:[^\s<>"|?*]+\\)*[^\s<>"|?*]+\b')
    LINUX_PATH_PATTERN = re.compile(r'\b/(?:[^\s<>"|]+/)*[^\s<>"|]+\b')

    # Username patterns
    USERNAME_PATTERN = re.compile(
        r'\b(?:user|username|account|logon|login)[\s:]+([a-zA-Z0-9_.-]+)\b',
        re.IGNORECASE
    )

    # Process name pattern
    PROCESS_PATTERN = re.compile(r'\b([a-zA-Z0-9_-]+\.(?:exe|dll|sys|ps1|sh|bat|cmd))\b', re.IGNORECASE)

    # Command line patterns
    COMMAND_PATTERN = re.compile(
        r'\b(?:cmd|powershell|bash|sh|python|perl|ruby)(?:\.exe)?\s+.*',
        re.IGNORECASE
    )

    def __init__(self):
        """Initialize preprocessor"""
        pass

    def preprocess_alerts(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Extract structured information from alerts

        Args:
            alerts: List of alert dictionaries from database

        Returns:
            Dict with extracted IOCs and metadata
        """
        logger.info(f"Preprocessing {len(alerts)} alerts for deterministic extraction")

        result = {
            'ioc_ips': set(),
            'ioc_domains': set(),
            'ioc_users': set(),
            'ioc_files': set(),
            'ioc_registry': set(),
            'ioc_processes': set(),
            'ioc_commands': set(),
            'event_ids': set(),
            'mitre_ids': set(),
            'timestamps': [],
            'hosts': set(),
            'alert_ids': []
        }

        for alert in alerts:
            self._extract_from_alert(alert, result)

        # Convert sets to sorted lists for JSON serialization
        processed = {
            'ioc_ips': sorted(list(result['ioc_ips']))[:50],  # Limit to 50 most common
            'ioc_domains': sorted(list(result['ioc_domains']))[:30],
            'ioc_users': sorted(list(result['ioc_users']))[:20],
            'ioc_files': sorted(list(result['ioc_files']))[:30],
            'ioc_registry': sorted(list(result['ioc_registry']))[:20],
            'ioc_processes': sorted(list(result['ioc_processes']))[:30],
            'ioc_commands': sorted(list(result['ioc_commands']))[:20],
            'event_ids': sorted(list(result['event_ids']))[:20],
            'mitre_ids': sorted(list(result['mitre_ids'])),
            'timestamps': sorted(result['timestamps'])[:100],  # First 100 events
            'hosts': sorted(list(result['hosts'])),
            'alert_ids': result['alert_ids'][:100]
        }

        logger.info(
            f"Extracted: {len(processed['ioc_ips'])} IPs, "
            f"{len(processed['ioc_domains'])} domains, "
            f"{len(processed['ioc_users'])} users, "
            f"{len(processed['mitre_ids'])} MITRE techniques"
        )

        return processed

    def _extract_from_alert(self, alert: Dict[str, Any], result: Dict[str, Set]):
        """
        Extract IOCs from a single alert

        Args:
            alert: Alert dictionary
            result: Result dict to populate (mutated in place)
        """
        # Collect all text fields for extraction
        text_fields = []

        # Add structured fields
        if alert.get('rule_description'):
            text_fields.append(alert['rule_description'])
        if alert.get('full_log'):
            text_fields.append(alert['full_log'])
        if alert.get('command_line'):
            text_fields.append(alert['command_line'])
        if alert.get('file_path'):
            text_fields.append(alert['file_path'])
        if alert.get('process_name'):
            text_fields.append(alert['process_name'])

        # Combine all text
        combined_text = ' '.join(str(f) for f in text_fields if f)

        # Extract IPs
        result['ioc_ips'].update(self._extract_ips(alert, combined_text))

        # Extract domains
        result['ioc_domains'].update(self._extract_domains(combined_text))

        # Extract usernames
        result['ioc_users'].update(self._extract_usernames(alert, combined_text))

        # Extract file paths
        result['ioc_files'].update(self._extract_file_paths(alert, combined_text))

        # Extract registry keys
        result['ioc_registry'].update(self._extract_registry_keys(combined_text))

        # Extract processes
        result['ioc_processes'].update(self._extract_processes(alert, combined_text))

        # Extract commands
        result['ioc_commands'].update(self._extract_commands(alert, combined_text))

        # Extract event IDs
        result['event_ids'].update(self._extract_event_ids(combined_text))

        # Extract MITRE techniques
        result['mitre_ids'].update(self._extract_mitre_techniques(alert))

        # Extract timestamp
        if alert.get('timestamp'):
            result['timestamps'].append(alert['timestamp'])

        # Extract host
        if alert.get('agent_name'):
            result['hosts'].add(alert['agent_name'])
        if alert.get('agent_ip'):
            result['hosts'].add(alert['agent_ip'])

        # Extract alert ID
        if alert.get('alert_id'):
            result['alert_ids'].append(str(alert['alert_id']))

    def _extract_ips(self, alert: Dict[str, Any], text: str) -> Set[str]:
        """Extract IP addresses"""
        ips = set()

        # From structured fields
        if alert.get('source_ip'):
            ips.add(alert['source_ip'])
        if alert.get('dest_ip'):
            ips.add(alert['dest_ip'])
        if alert.get('agent_ip'):
            ips.add(alert['agent_ip'])

        # From text using regex
        ips.update(self.IP_PATTERN.findall(text))

        # Filter out common local/private IPs that are less interesting
        filtered = set()
        for ip in ips:
            # Keep all IPs but deprioritize localhost
            if not ip.startswith('127.'):
                filtered.add(ip)

        return filtered

    def _extract_domains(self, text: str) -> Set[str]:
        """Extract domain names"""
        domains = set()

        matches = self.DOMAIN_PATTERN.findall(text)
        for domain in matches:
            # Filter out common false positives
            domain_lower = domain.lower()

            # Skip if it looks like a filename (has common extensions)
            if any(domain_lower.endswith(ext) for ext in [
                '.log', '.dat', '.exe', '.dll', '.sys', '.tmp', '.bak',
                '.ini', '.xml', '.json', '.txt', '.csv', '.zip'
            ]):
                continue

            # Skip common false positive domains
            if any(skip in domain_lower for skip in [
                'example.com', 'localhost', 'test.com', 'microsoft.com',
                'windows.com', 'adobe.com'
            ]):
                continue

            # Must have at least 2 parts (e.g., domain.com)
            parts = domain.split('.')
            if len(parts) < 2:
                continue

            # TLD must be at least 2 characters
            if len(parts[-1]) < 2:
                continue

            # Skip if it looks like a Windows path component
            if '\\' in domain or parts[0].upper() in ['HKEY', 'HKLM', 'HKCU']:
                continue

            domains.add(domain)

        return domains

    def _extract_usernames(self, alert: Dict[str, Any], text: str) -> Set[str]:
        """Extract usernames"""
        users = set()

        # From text using regex
        matches = self.USERNAME_PATTERN.findall(text)
        users.update(m.strip() for m in matches if m.strip())

        # Filter out common system accounts and noise
        filtered = set()
        stopwords = {
            'system', 'local', 'network', 'service', 'anonymous',
            'null', 'nobody', 'root', 'domain', 'success', 'failure',
            'name', 'event', 'guid', 'id', 'ids', 'information',
            'error', 'warning', 'status', 'type', 'data', 'value',
            'key', 'path', 'file', 'user', 'account', 'logon', 'login',
            'process', 'thread', 'handle', 'object', 'security'
        }

        for user in users:
            user_lower = user.lower()
            # Must be at least 3 characters
            if len(user) < 3:
                continue
            # Skip if it's a stopword
            if user_lower in stopwords:
                continue
            # Skip if it contains only digits
            if user.isdigit():
                continue
            # Skip if it looks like a GUID pattern
            if len(user) > 20 and '-' in user:
                continue
            # Must contain at least one letter
            if not any(c.isalpha() for c in user):
                continue

            filtered.add(user)

        return filtered

    def _extract_file_paths(self, alert: Dict[str, Any], text: str) -> Set[str]:
        """Extract file paths"""
        paths = set()

        # From structured field
        if alert.get('file_path'):
            paths.add(alert['file_path'])

        # Windows paths
        paths.update(self.WINDOWS_PATH_PATTERN.findall(text))

        # Linux paths (be more selective to avoid noise)
        linux_paths = self.LINUX_PATH_PATTERN.findall(text)
        for path in linux_paths:
            # Only include paths that look interesting (not just /usr/bin/ls)
            if any(interesting in path.lower() for interesting in [
                '/tmp/', '/var/', '/home/', '/root/', '/opt/',
                '/etc/', 'downloads', 'temp', '.exe', '.dll', '.sh', '.py'
            ]):
                paths.add(path)

        return paths

    def _extract_registry_keys(self, text: str) -> Set[str]:
        """Extract Windows registry keys"""
        return set(self.REGISTRY_PATTERN.findall(text))

    def _extract_processes(self, alert: Dict[str, Any], text: str) -> Set[str]:
        """Extract process names"""
        processes = set()

        # From structured field
        if alert.get('process_name'):
            processes.add(alert['process_name'])

        # From text
        processes.update(self.PROCESS_PATTERN.findall(text))

        return processes

    def _extract_commands(self, alert: Dict[str, Any], text: str) -> Set[str]:
        """Extract command lines"""
        commands = set()

        # From structured field
        if alert.get('command_line'):
            cmd = alert['command_line'].strip()
            if cmd:
                commands.add(cmd[:200])  # Truncate long commands

        # From text
        matches = self.COMMAND_PATTERN.findall(text)
        for cmd in matches:
            cmd = cmd.strip()
            if cmd:
                commands.add(cmd[:200])

        return commands

    def _extract_event_ids(self, text: str) -> Set[str]:
        """Extract Windows Event IDs"""
        event_ids = set()

        matches = self.EVENT_ID_PATTERN.findall(text)
        event_ids.update(matches)

        return event_ids

    def _extract_mitre_techniques(self, alert: Dict[str, Any]) -> Set[str]:
        """Extract MITRE ATT&CK technique IDs"""
        techniques = set()

        # From structured field (JSON array)
        mitre_field = alert.get('mitre_techniques')
        if mitre_field:
            if isinstance(mitre_field, str):
                try:
                    import json
                    mitre_list = json.loads(mitre_field)
                    techniques.update(mitre_list)
                except:
                    # Try regex extraction from string
                    techniques.update(self.MITRE_PATTERN.findall(mitre_field))
            elif isinstance(mitre_field, list):
                techniques.update(str(t) for t in mitre_field)

        # From text fields
        text_fields = [
            alert.get('rule_description', ''),
            alert.get('full_log', '')
        ]
        combined = ' '.join(str(f) for f in text_fields if f)
        techniques.update(self.MITRE_PATTERN.findall(combined))

        return techniques

    def format_preparsed_context(self, preparsed: Dict[str, Any]) -> str:
        """
        Format preparsed data into human-readable text for prompt

        Args:
            preparsed: Dict from preprocess_alerts()

        Returns:
            Formatted string for inclusion in prompt
        """
        lines = []

        lines.append("## PRE-PARSED STRUCTURED CONTEXT")
        lines.append("")
        lines.append("The following information was extracted deterministically from alert logs.")
        lines.append("You MUST use this data to populate your JSON response fields.")
        lines.append("")

        # MITRE Techniques
        if preparsed.get('mitre_ids'):
            lines.append(f"**MITRE Technique IDs**: {', '.join(preparsed['mitre_ids'])}")
            lines.append("")

        # IOCs
        if preparsed.get('ioc_ips'):
            lines.append(f"**IP Addresses**: {', '.join(preparsed['ioc_ips'][:10])}")
            if len(preparsed['ioc_ips']) > 10:
                lines.append(f"  ... and {len(preparsed['ioc_ips']) - 10} more")
            lines.append("")

        if preparsed.get('ioc_users'):
            lines.append(f"**Usernames**: {', '.join(preparsed['ioc_users'][:10])}")
            lines.append("")

        if preparsed.get('ioc_processes'):
            lines.append(f"**Processes**: {', '.join(preparsed['ioc_processes'][:10])}")
            lines.append("")

        if preparsed.get('ioc_files'):
            lines.append(f"**File Paths**: {', '.join(preparsed['ioc_files'][:5])}")
            if len(preparsed['ioc_files']) > 5:
                lines.append(f"  ... and {len(preparsed['ioc_files']) - 5} more")
            lines.append("")

        if preparsed.get('ioc_registry'):
            lines.append(f"**Registry Keys**: {', '.join(preparsed['ioc_registry'][:5])}")
            lines.append("")

        if preparsed.get('ioc_commands'):
            lines.append(f"**Commands**: ")
            for cmd in preparsed['ioc_commands'][:3]:
                lines.append(f"  - {cmd}")
            if len(preparsed['ioc_commands']) > 3:
                lines.append(f"  ... and {len(preparsed['ioc_commands']) - 3} more")
            lines.append("")

        # Timeline info
        if preparsed.get('timestamps'):
            lines.append(f"**Timeline**: {len(preparsed['timestamps'])} events")
            lines.append(f"  First Event: {preparsed['timestamps'][0]}")
            lines.append(f"  Last Event: {preparsed['timestamps'][-1]}")
            lines.append("")

        # Hosts
        if preparsed.get('hosts'):
            lines.append(f"**Affected Hosts**: {', '.join(preparsed['hosts'])}")
            lines.append("")

        # Alert IDs
        if preparsed.get('alert_ids'):
            lines.append(f"**Alert IDs**: {len(preparsed['alert_ids'])} alerts")
            lines.append(f"  Sample IDs: {', '.join(preparsed['alert_ids'][:5])}")
            lines.append("")

        lines.append("---")
        lines.append("")

        return '\n'.join(lines)
