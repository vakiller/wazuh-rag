"""
Knowledge Normalization Layer

Transforms STIX objects from OpenCTI into a unified structure for embedding and storage.
Each entity is converted into a text representation suitable for semantic search.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class KnowledgeNormalizer:
    """
    Normalizes OpenCTI STIX objects into unified structure

    Output schema:
    {
        'id': str,              # OpenCTI internal ID
        'standard_id': str,     # STIX standard ID
        'entity_type': str,     # attack-pattern, malware, etc.
        'name': str,            # Entity name
        'content': str,         # Rich text representation for embedding
        'metadata': dict,       # Type-specific metadata
        'created_at': datetime,
        'updated_at': datetime,
        'confidence': int
    }
    """

    @staticmethod
    def normalize(entity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single entity to unified structure

        Args:
            entity: Raw entity from OpenCTI

        Returns:
            Normalized entity dict

        Raises:
            ValueError: If entity is invalid
        """
        entity_type = entity.get('entity_type', '').lower()

        if not entity_type:
            raise ValueError("Entity missing entity_type field")

        # Dispatch to type-specific normalizer
        normalizers = {
            'attack-pattern': KnowledgeNormalizer._normalize_attack_pattern,
            'malware': KnowledgeNormalizer._normalize_malware,
            'course-of-action': KnowledgeNormalizer._normalize_course_of_action,
            'intrusion-set': KnowledgeNormalizer._normalize_intrusion_set,
            'indicator': KnowledgeNormalizer._normalize_indicator,
            'report': KnowledgeNormalizer._normalize_report,
        }

        normalizer_func = normalizers.get(entity_type)
        if not normalizer_func:
            logger.warning(f"No normalizer for entity type: {entity_type}, using generic")
            return KnowledgeNormalizer._normalize_generic(entity)

        try:
            return normalizer_func(entity)
        except Exception as e:
            logger.error(f"Normalization failed for {entity.get('id')}: {e}")
            # Fallback to generic normalizer
            return KnowledgeNormalizer._normalize_generic(entity)

    @staticmethod
    def _normalize_attack_pattern(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize MITRE ATT&CK technique"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        mitre_id = entity.get('x_mitre_id', '')
        platforms = entity.get('x_mitre_platforms', [])
        detection = entity.get('x_mitre_detection', '')

        # Extract kill chain phases
        kill_chains = []
        kc_phases = entity.get('killChainPhases', [])
        # Handle both direct list and edges format
        if isinstance(kc_phases, list):
            for phase_item in kc_phases:
                if isinstance(phase_item, dict):
                    phase = phase_item.get('phase_name', '')
                    if phase:
                        kill_chains.append(phase)
        elif isinstance(kc_phases, dict):
            # Old format with edges
            for edge in kc_phases.get('edges', []):
                node = edge.get('node', {})
                phase = node.get('phase_name', '')
                if phase:
                    kill_chains.append(phase)

        # Extract external references
        external_refs = []
        ext_edges = entity.get('externalReferences', {}).get('edges', [])
        for edge in ext_edges:
            node = edge.get('node', {})
            source = node.get('source_name', '')
            url = node.get('url', '')
            if source or url:
                external_refs.append(f"{source}: {url}" if url else source)

        # Build rich content for embedding
        content_parts = [
            f"MITRE ATT&CK Technique: {mitre_id} - {name}" if mitre_id else f"Attack Technique: {name}",
        ]

        if description:
            content_parts.append(f"Description: {description}")

        if platforms:
            content_parts.append(f"Platforms: {', '.join(platforms)}")

        if kill_chains:
            content_parts.append(f"Kill Chain Phases: {', '.join(kill_chains)}")

        if detection:
            content_parts.append(f"Detection: {detection}")

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'attack-pattern',
            'name': name,
            'content': content,
            'metadata': {
                'mitre_id': mitre_id,
                'platforms': platforms,
                'kill_chains': kill_chains,
                'external_references': external_refs,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_malware(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize malware entity"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        malware_types = entity.get('malware_types', [])
        is_family = entity.get('is_family', False)
        capabilities = entity.get('capabilities', [])
        first_seen = entity.get('first_seen')
        last_seen = entity.get('last_seen')

        # Build content
        content_parts = [
            f"Malware {'Family' if is_family else 'Variant'}: {name}",
        ]

        if description:
            content_parts.append(f"Description: {description}")

        if malware_types:
            content_parts.append(f"Types: {', '.join(malware_types)}")

        if capabilities:
            content_parts.append(f"Capabilities: {', '.join(capabilities)}")

        if first_seen or last_seen:
            seen_info = []
            if first_seen:
                seen_info.append(f"First seen: {first_seen}")
            if last_seen:
                seen_info.append(f"Last seen: {last_seen}")
            content_parts.append(", ".join(seen_info))

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'malware',
            'name': name,
            'content': content,
            'metadata': {
                'malware_types': malware_types,
                'is_family': is_family,
                'capabilities': capabilities,
                'first_seen': first_seen,
                'last_seen': last_seen,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_course_of_action(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize course of action (mitigation)"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        mitre_id = entity.get('x_mitre_id', '')

        content_parts = [
            f"Mitigation: {mitre_id} - {name}" if mitre_id else f"Mitigation: {name}",
        ]

        if description:
            content_parts.append(f"Description: {description}")

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'course-of-action',
            'name': name,
            'content': content,
            'metadata': {
                'mitre_id': mitre_id,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_intrusion_set(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat actor/APT group"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        aliases = entity.get('aliases', [])
        goals = entity.get('goals', [])
        resource_level = entity.get('resource_level', '')
        primary_motivation = entity.get('primary_motivation', '')
        first_seen = entity.get('first_seen')
        last_seen = entity.get('last_seen')

        content_parts = [
            f"Threat Actor: {name}",
        ]

        if aliases:
            content_parts.append(f"Also known as: {', '.join(aliases)}")

        if description:
            content_parts.append(f"Description: {description}")

        if goals:
            content_parts.append(f"Goals: {', '.join(goals)}")

        if primary_motivation:
            content_parts.append(f"Primary Motivation: {primary_motivation}")

        if resource_level:
            content_parts.append(f"Resource Level: {resource_level}")

        if first_seen or last_seen:
            seen_info = []
            if first_seen:
                seen_info.append(f"First seen: {first_seen}")
            if last_seen:
                seen_info.append(f"Last seen: {last_seen}")
            content_parts.append(", ".join(seen_info))

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'intrusion-set',
            'name': name,
            'content': content,
            'metadata': {
                'aliases': aliases,
                'goals': goals,
                'resource_level': resource_level,
                'primary_motivation': primary_motivation,
                'first_seen': first_seen,
                'last_seen': last_seen,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_indicator(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize IOC indicator"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        pattern = entity.get('pattern', '')
        pattern_type = entity.get('pattern_type', '')
        indicator_types = entity.get('indicator_types', [])
        valid_from = entity.get('valid_from')
        valid_until = entity.get('valid_until')

        content_parts = [
            f"Indicator: {name}",
        ]

        if description:
            content_parts.append(f"Description: {description}")

        if pattern:
            content_parts.append(f"Pattern ({pattern_type}): {pattern}")

        if indicator_types:
            content_parts.append(f"Types: {', '.join(indicator_types)}")

        if valid_from or valid_until:
            validity = []
            if valid_from:
                validity.append(f"Valid from: {valid_from}")
            if valid_until:
                validity.append(f"Valid until: {valid_until}")
            content_parts.append(", ".join(validity))

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'indicator',
            'name': name,
            'content': content,
            'metadata': {
                'pattern': pattern,
                'pattern_type': pattern_type,
                'indicator_types': indicator_types,
                'valid_from': valid_from,
                'valid_until': valid_until,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_report(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat report"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')
        published = entity.get('published', '')
        report_types = entity.get('report_types', [])

        # Extract referenced objects
        referenced_objects = []
        obj_edges = entity.get('object_refs', {}).get('edges', [])
        for edge in obj_edges:
            node = edge.get('node', {})
            obj_type = node.get('entity_type', '')
            obj_name = node.get('name', '')
            if obj_type and obj_name:
                referenced_objects.append(f"{obj_type}: {obj_name}")

        content_parts = [
            f"Threat Report: {name}",
        ]

        if description:
            content_parts.append(f"Description: {description}")

        if report_types:
            content_parts.append(f"Report Types: {', '.join(report_types)}")

        if published:
            content_parts.append(f"Published: {published}")

        if referenced_objects:
            content_parts.append(f"References:\n" + "\n".join(f"- {obj}" for obj in referenced_objects[:20]))

        content = "\n\n".join(content_parts)

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': 'report',
            'name': name,
            'content': content,
            'metadata': {
                'published': published,
                'report_types': report_types,
                'referenced_objects': referenced_objects,
            },
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _normalize_generic(entity: Dict[str, Any]) -> Dict[str, Any]:
        """Generic normalizer for unknown entity types"""
        name = entity.get('name', 'Unknown')
        description = entity.get('description', '')

        content = f"{name}\n\n{description}" if description else name

        return {
            'id': entity.get('id'),
            'standard_id': entity.get('standard_id'),
            'entity_type': entity.get('entity_type', 'unknown'),
            'name': name,
            'content': content,
            'metadata': {},
            'created_at': KnowledgeNormalizer._parse_datetime(entity.get('created_at')),
            'updated_at': KnowledgeNormalizer._parse_datetime(entity.get('updated_at')),
            'confidence': entity.get('confidence', 0),
        }

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """
        Parse ISO datetime string to datetime object

        Args:
            dt_str: ISO format datetime string

        Returns:
            datetime object or None
        """
        if not dt_str:
            return None

        try:
            # Remove 'Z' suffix and parse
            dt_str = dt_str.rstrip('Z')
            return datetime.fromisoformat(dt_str)
        except Exception as e:
            logger.warning(f"Failed to parse datetime: {dt_str} ({e})")
            return None
