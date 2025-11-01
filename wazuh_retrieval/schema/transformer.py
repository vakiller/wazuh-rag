"""
Document transformation logic for normalizing Wazuh alerts to standard schema.
"""

from typing import Dict, Any, Optional, List, Tuple
import logging
from .mappings import INTEGER_FIELDS
from ..exceptions import TransformationError

logger = logging.getLogger(__name__)


class AlertTransformer:
    """
    Transforms raw Wazuh alert documents to normalized schema.

    Handles:
    - Nested field extraction
    - Type conversions
    - MITRE ATT&CK field flattening
    - File hash prioritization (SHA256 > SHA1 > MD5)
    - Missing field handling
    """

    @staticmethod
    def _get_nested_value(doc: Dict[str, Any], path: str) -> Any:
        """
        Extract value from nested dict using dot notation path.

        Args:
            doc: Dictionary to search
            path: Dot-separated path (e.g., 'rule.mitre.id')

        Returns:
            Value at path, or None if not found

        Example:
            _get_nested_value(doc, 'rule.mitre.id')
        """
        keys = path.split('.')
        value = doc

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None

            if value is None:
                return None

        return value

    @staticmethod
    def _extract_file_hash(source: Dict[str, Any]) -> Optional[str]:
        """
        Extract best available file hash (prefer SHA256 > SHA1 > MD5).

        Args:
            source: Alert source document

        Returns:
            Best available hash string, or None if no hash found
        """
        hash_fields = [
            'syscheck.sha256_after',
            'syscheck.sha1_after',
            'syscheck.md5_after',
            'data.win.eventdata.hashes'  # Windows events
        ]

        for field in hash_fields:
            hash_val = AlertTransformer._get_nested_value(source, field)
            if hash_val:
                # For Windows hashes field, extract SHA256 if present
                hash_str = str(hash_val)
                if 'SHA256=' in hash_str:
                    parts = hash_str.split('SHA256=')
                    if len(parts) > 1:
                        return parts[1].split(',')[0].split()[0].strip()
                elif 'SHA1=' in hash_str:
                    parts = hash_str.split('SHA1=')
                    if len(parts) > 1:
                        return parts[1].split(',')[0].split()[0].strip()
                elif 'MD5=' in hash_str:
                    parts = hash_str.split('MD5=')
                    if len(parts) > 1:
                        return parts[1].split(',')[0].split()[0].strip()
                # If it's just a plain hash value
                return hash_val

        return None

    @staticmethod
    def _extract_log_content(source: Dict[str, Any]) -> Optional[str]:
        """
        Extract full log content from alert.

        Different alert types store log content in different fields:
        - FIM/Syscheck alerts: full_log field
        - Windows EventChannel: data.win.system.message
        - Linux logs: full_log field
        - Other: predecoder or decoder fields

        Args:
            source: Alert source document

        Returns:
            Log content string or None
        """
        # Check for full_log field (FIM, syslog, file-based logs)
        if 'full_log' in source and source['full_log']:
            return source['full_log']

        # For Windows EventChannel logs, use the message field
        win_message = AlertTransformer._get_nested_value(source, 'data.win.system.message')
        if win_message:
            return win_message

        # For predecoder-based alerts
        predecoder = source.get('predecoder', {})
        if predecoder:
            # Reconstruct log line from predecoder fields
            parts = []
            if 'timestamp' in predecoder:
                parts.append(predecoder['timestamp'])
            if 'hostname' in predecoder:
                parts.append(predecoder['hostname'])
            if 'program_name' in predecoder:
                parts.append(predecoder['program_name'])

            if parts:
                return ' '.join(parts)

        return None

    @staticmethod
    def _flatten_mitre(doc: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """
        Extract and flatten MITRE ATT&CK information.

        Wazuh stores MITRE data in various formats:
        - rule.mitre.id (array or string) - MITRE technique IDs (e.g., T1110)
        - rule.mitre.tactic (array or string) - Tactic names
        - rule.mitre.technique (array or string) - Technique names (human-readable)
        - Nested objects

        We prioritize technique IDs (from 'id' field) over technique names.

        Args:
            doc: Alert source document

        Returns:
            Tuple of (technique_ids: List[str], tactics: List[str])
        """
        technique_ids = []
        tactics = []

        rule_mitre = AlertTransformer._get_nested_value(doc, 'rule.mitre')

        if isinstance(rule_mitre, dict):
            # Single MITRE entry as dict
            if 'id' in rule_mitre:
                id_val = rule_mitre['id']
                if isinstance(id_val, list):
                    technique_ids.extend([str(i) for i in id_val])
                else:
                    technique_ids.append(str(id_val))
            if 'tactic' in rule_mitre:
                tactic_val = rule_mitre['tactic']
                if isinstance(tactic_val, list):
                    tactics.extend([str(t) for t in tactic_val])
                else:
                    tactics.append(str(tactic_val))

        elif isinstance(rule_mitre, list):
            # Multiple MITRE entries as list
            for entry in rule_mitre:
                if isinstance(entry, dict):
                    if 'id' in entry:
                        id_val = entry['id']
                        if isinstance(id_val, list):
                            technique_ids.extend([str(i) for i in id_val])
                        else:
                            technique_ids.append(str(id_val))
                    if 'tactic' in entry:
                        tactic_val = entry['tactic']
                        if isinstance(tactic_val, list):
                            tactics.extend([str(t) for t in tactic_val])
                        else:
                            tactics.append(str(tactic_val))

        # Check individual arrays at top level (only if not already processed)
        # 'id' field contains technique IDs (T1110, etc.)
        id_array = AlertTransformer._get_nested_value(doc, 'rule.mitre.id')
        if id_array and not isinstance(rule_mitre, (dict, list)):
            if isinstance(id_array, list):
                technique_ids.extend([str(i) for i in id_array])
            else:
                technique_ids.append(str(id_array))

        # 'tactic' field contains tactic names
        tactic_array = AlertTransformer._get_nested_value(doc, 'rule.mitre.tactic')
        if tactic_array and not isinstance(rule_mitre, (dict, list)):
            if isinstance(tactic_array, list):
                tactics.extend([str(t) for t in tactic_array])
            else:
                tactics.append(str(tactic_array))

        # Deduplicate, clean, and filter out empty strings
        # Only keep IDs that start with 'T' (MITRE technique pattern)
        technique_ids = list(set([
            t.strip() for t in technique_ids
            if t and str(t).strip().startswith('T')
        ]))
        tactics = list(set([t.strip() for t in tactics if t]))

        return technique_ids, tactics

    def transform(self, raw_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transform raw Wazuh alert to normalized schema.

        Args:
            raw_doc: Raw document from OpenSearch (includes _source, _index, etc.)

        Returns:
            Normalized document following NORMALIZED_SCHEMA

        Raises:
            TransformationError: If transformation fails critically
        """
        try:
            source = raw_doc.get('_source', {})

            # Extract MITRE information
            mitre_techniques, mitre_tactics = self._flatten_mitre(source)

            # Build normalized document
            normalized = {
                'timestamp': source.get('@timestamp'),
                'index_name': raw_doc.get('_index'),
                'document_id': raw_doc.get('_id'),
                'agent_id': self._get_nested_value(source, 'agent.id'),
                'agent_name': self._get_nested_value(source, 'agent.name'),
                'agent_ip': self._get_nested_value(source, 'agent.ip'),
                'rule_id': self._get_nested_value(source, 'rule.id'),
                'rule_description': self._get_nested_value(source, 'rule.description'),
                'rule_level': self._get_nested_value(source, 'rule.level'),
                'rule_groups': self._get_nested_value(source, 'rule.groups') or [],
                'mitre_techniques': mitre_techniques,
                'mitre_tactics': mitre_tactics,
                'source_ip': self._get_nested_value(source, 'data.srcip'),
                'dest_ip': self._get_nested_value(source, 'data.dstip'),
                'source_port': self._get_nested_value(source, 'data.srcport'),
                'dest_port': self._get_nested_value(source, 'data.dstport'),
                'protocol': self._get_nested_value(source, 'data.protocol'),
                'file_path': self._get_nested_value(source, 'syscheck.path'),
                'file_hash': self._extract_file_hash(source),
                'process_name': self._get_nested_value(source, 'data.process_name'),
                'process_id': self._get_nested_value(source, 'data.process_id'),
                'command_line': self._get_nested_value(source, 'data.command'),
                'username': (
                    self._get_nested_value(source, 'data.dstuser') or
                    self._get_nested_value(source, 'data.win.eventdata.targetUserName')
                ),
                'win_eventid': self._get_nested_value(source, 'data.win.system.eventID'),
                'full_log': self._extract_log_content(source),
            }

            # Type conversions for integer fields
            for field in INTEGER_FIELDS:
                if field in normalized and normalized[field] is not None:
                    try:
                        normalized[field] = int(normalized[field])
                    except (ValueError, TypeError):
                        logger.warning(
                            f"Failed to convert {field} to int: {normalized[field]} "
                            f"(doc: {normalized.get('document_id')})"
                        )
                        normalized[field] = None

            # Ensure lists for array fields
            if not isinstance(normalized['rule_groups'], list):
                normalized['rule_groups'] = (
                    [normalized['rule_groups']] if normalized['rule_groups'] else []
                )

            # Validation: ensure required fields are present
            required_fields = ['timestamp', 'document_id', 'agent_id', 'rule_id', 'rule_level']
            missing_fields = [f for f in required_fields if not normalized.get(f)]

            if missing_fields:
                logger.warning(
                    f"Document missing required fields {missing_fields}: "
                    f"{normalized.get('document_id', 'unknown')}"
                )

            return normalized

        except Exception as e:
            doc_id = raw_doc.get('_id', 'unknown')
            logger.error(f"Transformation failed for document {doc_id}: {e}", exc_info=True)
            raise TransformationError(f"Failed to transform document {doc_id}: {str(e)}")
