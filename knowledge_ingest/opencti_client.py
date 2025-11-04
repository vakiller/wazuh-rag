"""
OpenCTI API Client for Knowledge Ingestion

Connects to OpenCTI GraphQL API to fetch threat intelligence entities:
- attack-pattern (MITRE ATT&CK techniques)
- malware
- course-of-action (mitigations)
- intrusion-set (threat actors/APTs)
- indicator (IOCs)
- report (threat reports)
"""

import logging
from typing import Dict, Any, List, Optional, Generator
from datetime import datetime
import requests

logger = logging.getLogger(__name__)


class OpenCTIClientError(Exception):
    """Base exception for OpenCTI client errors"""
    pass


class OpenCTIClient:
    """
    Client for OpenCTI GraphQL API

    Handles authentication, pagination, and entity queries.
    """

    ENTITY_TYPE_MAPPING = {
        'attack-pattern': 'AttackPattern',
        'malware': 'Malware',
        'course-of-action': 'CourseOfAction',
        'intrusion-set': 'IntrusionSet',
        'indicator': 'Indicator',
        'report': 'Report',
    }

    def __init__(self, url: str, api_token: str, verify_ssl: bool = True):
        """
        Initialize OpenCTI client

        Args:
            url: OpenCTI server URL (e.g., http://100.114.206.116:8080)
            api_token: OpenCTI API token
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url.rstrip('/')
        self.api_token = api_token
        self.verify_ssl = verify_ssl
        self.graphql_endpoint = f"{self.url}/graphql"

        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Content-Type': 'application/json',
        })

        logger.info(f"Initialized OpenCTI client for {self.url}")

    def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to OpenCTI API

        Returns:
            Dict with server version and status

        Raises:
            OpenCTIClientError: If connection fails
        """
        query = """
        query {
            about {
                version
                debugMode
            }
        }
        """

        try:
            response = self._execute_query(query)
            about = response.get('data', {}).get('about', {})
            logger.info(f"Connected to OpenCTI version {about.get('version')}")
            return about
        except Exception as e:
            raise OpenCTIClientError(f"Connection test failed: {e}")

    def fetch_entities(
        self,
        entity_type: str,
        batch_size: int = 100,
        max_items: int = -1,
        modified_after: Optional[datetime] = None
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Fetch entities of a specific type with pagination

        Args:
            entity_type: Type of entity (attack-pattern, malware, etc.)
            batch_size: Number of items per page
            max_items: Maximum number of items to fetch (-1 for unlimited)
            modified_after: Only fetch items modified after this datetime

        Yields:
            Individual entity dictionaries

        Raises:
            OpenCTIClientError: If query fails
        """
        if entity_type not in self.ENTITY_TYPE_MAPPING:
            raise OpenCTIClientError(
                f"Unknown entity type: {entity_type}. "
                f"Valid types: {list(self.ENTITY_TYPE_MAPPING.keys())}"
            )

        graphql_type = self.ENTITY_TYPE_MAPPING[entity_type]
        count = 0
        has_next_page = True
        after_cursor = None

        logger.info(f"Fetching {entity_type} entities (max: {max_items if max_items > 0 else 'unlimited'})")

        while has_next_page:
            # Build filters
            filters = []
            if modified_after:
                filters.append({
                    'key': 'updated_at',
                    'values': [modified_after.isoformat()],
                    'operator': 'gt',
                })

            # Fetch page
            entities, page_info = self._fetch_page(
                graphql_type,
                batch_size,
                after_cursor,
                filters
            )

            # Yield entities
            for entity in entities:
                yield entity
                count += 1

                if max_items > 0 and count >= max_items:
                    logger.info(f"Reached max items limit: {max_items}")
                    return

            # Check if more pages exist
            has_next_page = page_info.get('hasNextPage', False)
            after_cursor = page_info.get('endCursor')

            logger.debug(
                f"Fetched {len(entities)} {entity_type} entities "
                f"(total: {count}, has_next: {has_next_page})"
            )

        logger.info(f"Completed fetching {count} {entity_type} entities")

    def _fetch_page(
        self,
        graphql_type: str,
        first: int,
        after: Optional[str],
        filters: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Fetch a single page of entities

        Args:
            graphql_type: GraphQL type name (e.g., AttackPattern)
            first: Number of items to fetch
            after: Cursor for pagination
            filters: List of filter objects

        Returns:
            Tuple of (entities list, page_info dict)
        """
        # Build filter string
        filter_str = ""
        if filters:
            filter_items = []
            for f in filters:
                filter_items.append(
                    f'{{key: "{f["key"]}", values: {f["values"]}, operator: {f["operator"]}}}'
                )
            filter_str = f'filters: [{", ".join(filter_items)}]'

        # Build query based on entity type
        query = self._build_entity_query(graphql_type, first, after, filter_str)

        try:
            response = self._execute_query(query)
            data = response.get('data', {})

            # Get the connection object (e.g., attackPatterns, malwares, etc.)
            connection_key = self._get_connection_key(graphql_type)
            connection = data.get(connection_key, {})

            edges = connection.get('edges', [])
            page_info = connection.get('pageInfo', {})

            # Extract nodes from edges
            entities = [edge['node'] for edge in edges if 'node' in edge]

            return entities, page_info

        except Exception as e:
            raise OpenCTIClientError(f"Failed to fetch {graphql_type} page: {e}")

    def _build_entity_query(
        self,
        graphql_type: str,
        first: int,
        after: Optional[str],
        filter_str: str
    ) -> str:
        """
        Build GraphQL query for entity type

        Args:
            graphql_type: GraphQL type name
            first: Number of items
            after: Cursor
            filter_str: Filter string

        Returns:
            GraphQL query string
        """
        connection_key = self._get_connection_key(graphql_type)
        after_str = f', after: "{after}"' if after else ''

        # Common fields for all entities
        common_fields = """
            id
            standard_id
            entity_type
            name
            description
            created_at
            updated_at
            confidence
            lang
        """

        # Type-specific fields
        type_fields = {
            'AttackPattern': """
                x_mitre_id
                x_mitre_platforms
                x_mitre_permissions_required
                x_mitre_detection
                killChainPhases {
                    id
                    kill_chain_name
                    phase_name
                }
                externalReferences {
                    edges {
                        node {
                            source_name
                            external_id
                            url
                        }
                    }
                }
            """,
            'Malware': """
                malware_types
                is_family
                first_seen
                last_seen
                architecture_execution_envs
                implementation_languages
                capabilities
            """,
            'CourseOfAction': """
                x_mitre_id
            """,
            'IntrusionSet': """
                aliases
                first_seen
                last_seen
                goals
                resource_level
                primary_motivation
                secondary_motivations
            """,
            'Indicator': """
                pattern
                pattern_type
                valid_from
                valid_until
                indicator_types
            """,
            'Report': """
                published
                report_types
            """,
        }

        entity_fields = common_fields + type_fields.get(graphql_type, '')

        query = f"""
        query {{
            {connection_key}(
                first: {first}
                {after_str}
                {filter_str}
                orderBy: created_at
                orderMode: asc
            ) {{
                edges {{
                    node {{
                        {entity_fields}
                    }}
                }}
                pageInfo {{
                    hasNextPage
                    endCursor
                }}
            }}
        }}
        """

        return query

    def _get_connection_key(self, graphql_type: str) -> str:
        """
        Get GraphQL connection key for entity type

        Args:
            graphql_type: GraphQL type name (e.g., AttackPattern)

        Returns:
            Connection key (e.g., attackPatterns)
        """
        mapping = {
            'AttackPattern': 'attackPatterns',
            'Malware': 'malwares',
            'CourseOfAction': 'coursesOfAction',
            'IntrusionSet': 'intrusionSets',
            'Indicator': 'indicators',
            'Report': 'reports',
        }
        return mapping.get(graphql_type, f"{graphql_type.lower()}s")

    def _execute_query(self, query: str) -> Dict[str, Any]:
        """
        Execute GraphQL query

        Args:
            query: GraphQL query string

        Returns:
            Response JSON

        Raises:
            OpenCTIClientError: If request fails
        """
        try:
            response = self.session.post(
                self.graphql_endpoint,
                json={'query': query},
                verify=self.verify_ssl,
                timeout=30
            )

            response.raise_for_status()

            result = response.json()

            # Check for GraphQL errors
            if 'errors' in result:
                errors = result['errors']
                error_messages = [e.get('message', str(e)) for e in errors]
                raise OpenCTIClientError(f"GraphQL errors: {', '.join(error_messages)}")

            return result

        except requests.exceptions.RequestException as e:
            raise OpenCTIClientError(f"HTTP request failed: {e}")
        except Exception as e:
            raise OpenCTIClientError(f"Query execution failed: {e}")

    def count_entities(self, entity_type: str) -> int:
        """
        Count total entities of a specific type

        Args:
            entity_type: Type of entity

        Returns:
            Total count
        """
        if entity_type not in self.ENTITY_TYPE_MAPPING:
            raise OpenCTIClientError(f"Unknown entity type: {entity_type}")

        graphql_type = self.ENTITY_TYPE_MAPPING[entity_type]
        connection_key = self._get_connection_key(graphql_type)

        query = f"""
        query {{
            {connection_key}(first: 1) {{
                pageInfo {{
                    globalCount
                }}
            }}
        }}
        """

        try:
            response = self._execute_query(query)
            connection = response.get('data', {}).get(connection_key, {})
            count = connection.get('pageInfo', {}).get('globalCount', 0)
            return count
        except Exception as e:
            logger.error(f"Failed to count {entity_type}: {e}")
            return 0
