"""
Main Analysis Orchestrator

Coordinates the full analysis pipeline:
1. Retrieve alerts from time window
2. Retrieve relevant knowledge from FAISS
3. Generate LLM analysis
4. Calculate risk score
5. Store report
"""

import logging
import yaml
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

from .retrieval import AlertRetriever, KnowledgeRetriever
from .llm_client import LLMClient
from .storage import ReportStorage
from .preprocessor import AlertPreprocessor
from .prompt_templates import (
    SYSTEM_PROMPT,
    format_user_prompt,
    format_alert_evidence,
    format_retrieved_knowledge
)

logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """
    Main orchestrator for automated threat analysis
    """

    def __init__(self, config_path: str = "llm_analysis/config.yaml"):
        """
        Initialize threat analyzer

        Args:
            config_path: Path to configuration file
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()

        # Initialize components
        self.alert_retriever = None
        self.knowledge_retriever = None
        self.llm_client = None
        self.report_storage = None
        self.preprocessor = None

        logger.info("Initializing Threat Analyzer")
        self._init_components()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)

        logger.info(f"Loaded configuration from {self.config_path}")
        return config

    def _init_components(self):
        """Initialize all components"""
        # Alert retriever
        db_path = self.config['database']['path']
        self.alert_retriever = AlertRetriever(db_path)

        # Knowledge retriever
        self.knowledge_retriever = KnowledgeRetriever(
            faiss_index_path=self.config['faiss']['index_path'],
            metadata_db_path=self.config['faiss']['metadata_db'],
            embedding_model_name=self.config['embedding']['model_name'],
            device=self.config['embedding']['device']
        )

        # LLM client
        self.llm_client = LLMClient(
            base_url=self.config['llm']['base_url'],
            model=self.config['llm']['model'],
            temperature=self.config['llm']['temperature'],
            timeout=self.config['llm']['timeout'],
            max_retries=self.config['llm']['max_retries']
        )

        # Report storage
        self.report_storage = ReportStorage(db_path)

        # Preprocessor (Phase 4.1)
        self.preprocessor = AlertPreprocessor()

        logger.info("All components initialized successfully")

    def analyze_window(
        self,
        window_minutes: Optional[int] = None,
        end_time: Optional[datetime] = None
    ) -> Optional[int]:
        """
        Analyze alerts from a time window

        Args:
            window_minutes: Minutes to look back (default from config)
            end_time: End of window (default: now)

        Returns:
            Report ID if successful, None if no alerts or error
        """
        if window_minutes is None:
            window_minutes = self.config['analysis']['window_minutes']

        if end_time is None:
            end_time = datetime.utcnow()

        start_time = end_time - timedelta(minutes=window_minutes)

        logger.info(
            f"Starting analysis for window: {start_time.isoformat()} "
            f"to {end_time.isoformat()}"
        )

        try:
            # 1. Retrieve alerts
            alerts = self.alert_retriever.get_alerts_in_window(
                window_minutes=window_minutes,
                end_time=end_time
            )

            if len(alerts) < self.config['analysis']['min_alerts_threshold']:
                logger.info(
                    f"Insufficient alerts ({len(alerts)}) for analysis, "
                    f"threshold: {self.config['analysis']['min_alerts_threshold']}"
                )
                return None

            # 2. Extract metadata
            hosts, agents = self.alert_retriever.extract_hosts_and_agents(alerts)
            mitre_techniques = self.alert_retriever.extract_mitre_techniques(alerts)

            logger.info(
                f"Analyzing {len(alerts)} alerts from {len(hosts)} hosts, "
                f"{len(mitre_techniques)} MITRE techniques"
            )

            # 2.5. Preprocess alerts (Phase 4.1 - deterministic extraction)
            preparsed_data = self.preprocessor.preprocess_alerts(alerts)
            preparsed_text = self.preprocessor.format_preparsed_context(preparsed_data)

            # 3. Retrieve relevant knowledge
            knowledge_items = self.knowledge_retriever.retrieve_context(
                alerts=alerts,
                top_k=self.config['faiss']['top_k'],
                score_threshold=self.config['faiss']['score_threshold']
            )

            # 4. Format prompts
            evidence_text = format_alert_evidence(
                alerts,
                max_chars=self.config['prompts']['max_evidence_chars']
            )

            retrieved_text = format_retrieved_knowledge(
                knowledge_items,
                max_chars=self.config['prompts']['max_context_chars']
            )

            user_prompt = format_user_prompt(
                window_start=start_time.isoformat(),
                window_end=end_time.isoformat(),
                alert_count=len(alerts),
                hosts=hosts,
                agents=agents,
                evidence_text=evidence_text,
                retrieved_text=retrieved_text,
                preparsed_text=preparsed_text
            )

            # 5. Call LLM
            logger.info("Calling LLM for analysis...")
            llm_output = self.llm_client.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt
            )

            # 5.5. Apply fallback logic (Phase 4.1 - fill missing fields)
            llm_output = self._apply_fallback_logic(
                llm_output=llm_output,
                preparsed_data=preparsed_data,
                knowledge_items=knowledge_items,
                alerts=alerts
            )

            # 6. Calculate risk score
            risk_score = self._calculate_risk_score(alerts, mitre_techniques, llm_output)

            logger.info(f"Calculated risk score: {risk_score}/100")

            # 7. Save report
            report_id = self.report_storage.save_report(
                window_start=start_time,
                window_end=end_time,
                alerts_count=len(alerts),
                llm_output=llm_output,
                hosts=hosts,
                agents=agents,
                risk_score=risk_score,
                faiss_context=knowledge_items
            )

            logger.info(f"✓ Analysis complete, saved as report ID {report_id}")

            return report_id

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return None

    def _calculate_risk_score(
        self,
        alerts: list,
        mitre_techniques: set,
        llm_output: Dict[str, Any]
    ) -> int:
        """
        Calculate risk score based on alert severity and context

        Args:
            alerts: List of alert dicts
            mitre_techniques: Set of MITRE technique IDs
            llm_output: LLM analysis output

        Returns:
            Risk score (0-100)
        """
        weights = self.config['risk_scoring']
        score = 0

        # Count alerts by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}

        for alert in alerts:
            level = alert.get('rule_level', 0)
            if level >= 10:  # Critical/High
                severity_counts['high'] += 1
            elif level >= 7:  # Medium
                severity_counts['medium'] += 1
            else:  # Low
                severity_counts['low'] += 1

        # Add severity-based score
        score += severity_counts['high'] * weights['high_severity_weight']
        score += severity_counts['medium'] * weights['medium_severity_weight']
        score += severity_counts['low'] * weights['low_severity_weight']

        # Extract unique MITRE tactics from techniques
        tactics = set()
        mitre_list = llm_output.get('mitre_list', [])
        for item in mitre_list:
            if isinstance(item, dict) and 'tactic' in item:
                tactics.add(item['tactic'].lower())

        # Add tactic diversity score
        score += len(tactics) * weights['unique_tactics_multiplier']

        # Check for high-risk tactics
        high_risk_tactics = {
            'privilege-escalation': weights['privilege_escalation_bonus'],
            'lateral-movement': weights['lateral_movement_bonus'],
            'credential-access': weights['credential_access_bonus']
        }

        for tactic, bonus in high_risk_tactics.items():
            if tactic in tactics:
                score += bonus

        # Factor in LLM confidence
        confidence = llm_output.get('confidence_overall', 50)
        score = int(score * (confidence / 100))

        # Cap at maximum
        score = min(score, weights['max_score'])

        return score

    def _calculate_severity(
        self,
        alerts: list,
        hosts: set,
        mitre_techniques: set,
        llm_output: Dict[str, Any],
        risk_score: int
    ) -> str:
        """
        Calculate incident severity classification (Phase 4)

        Args:
            alerts: List of alert dicts
            hosts: Set of affected hosts
            mitre_techniques: Set of MITRE technique IDs
            llm_output: LLM analysis output
            risk_score: Calculated risk score

        Returns:
            Severity: Low | Medium | High | Critical
        """
        # Start with risk score-based severity
        if risk_score >= 80:
            base_severity = 'Critical'
        elif risk_score >= 60:
            base_severity = 'High'
        elif risk_score >= 30:
            base_severity = 'Medium'
        else:
            base_severity = 'Low'

        # Extract tactics from MITRE techniques
        tactics = set()
        mitre_list = llm_output.get('mitre_list', [])
        for item in mitre_list:
            if isinstance(item, dict) and 'tactic' in item:
                tactics.add(item['tactic'].lower())

        # Check for escalation factors
        escalation_factors = []

        # Factor 1: Multiple hosts (potential lateral movement)
        if len(hosts) >= 5:
            escalation_factors.append('multiple_hosts')

        # Factor 2: Privilege escalation present
        priv_esc_tactics = {'privilege-escalation', 'privilege escalation'}
        if any(t in tactics for t in priv_esc_tactics):
            escalation_factors.append('privilege_escalation')

        # Factor 3: Destructive techniques
        destructive_techniques = {'T1485', 'T1486', 'T1490'}  # Data Destruction, Ransomware, Inhibit Recovery
        if any(tech in mitre_techniques for tech in destructive_techniques):
            escalation_factors.append('destructive')

        # Factor 4: Multiple tactics (sophisticated attack)
        if len(tactics) >= 5:
            escalation_factors.append('multi_tactic')

        # Escalate severity based on factors
        if len(escalation_factors) >= 3 and base_severity != 'Critical':
            # Escalate by one level
            severity_order = ['Low', 'Medium', 'High', 'Critical']
            current_index = severity_order.index(base_severity)
            return severity_order[min(current_index + 1, 3)]
        elif len(escalation_factors) >= 2 and base_severity == 'Low':
            return 'Medium'

        return base_severity

    def _apply_fallback_logic(
        self,
        llm_output: Dict[str, Any],
        preparsed_data: Dict[str, Any],
        knowledge_items: list,
        alerts: list
    ) -> Dict[str, Any]:
        """
        Apply fallback logic to fill missing/incomplete fields (Phase 4.1)

        Args:
            llm_output: LLM-generated output
            preparsed_data: Pre-parsed deterministic data
            knowledge_items: Retrieved knowledge from FAISS
            alerts: Original alert list

        Returns:
            Enhanced LLM output with fallback data
        """
        logger.info("Applying Phase 4.1 fallback logic...")

        # 1. Fill missing IOCs from preparsed data
        if not llm_output.get('iocs') or not isinstance(llm_output['iocs'], dict):
            llm_output['iocs'] = {}

        # Ensure all IOC fields exist and are filled
        ioc_mapping = {
            'ips': 'ioc_ips',
            'users': 'ioc_users',
            'hashes': [],  # Not in preparsed
            'domains': 'ioc_domains',
            'file_paths': 'ioc_files',
            'registry_keys': 'ioc_registry',
            'processes': 'ioc_processes',
            'commands': 'ioc_commands'
        }

        for ioc_key, preparsed_key in ioc_mapping.items():
            if not llm_output['iocs'].get(ioc_key):
                if isinstance(preparsed_key, list):
                    llm_output['iocs'][ioc_key] = preparsed_key
                else:
                    llm_output['iocs'][ioc_key] = preparsed_data.get(preparsed_key, [])
                    if llm_output['iocs'][ioc_key]:
                        logger.info(f"Fallback: Filled {ioc_key} with {len(llm_output['iocs'][ioc_key])} items")

        # 2. Fill missing MITRE techniques using knowledge items
        if not llm_output.get('mitre_list') or len(llm_output['mitre_list']) == 0:
            llm_output['mitre_list'] = []
            logger.warning("LLM returned empty mitre_list, using fallback from knowledge base")

        # Normalize MITRE field names (LLM sometimes uses "id"/"name" instead of "technique_id"/"technique_name")
        for item in llm_output.get('mitre_list', []):
            if isinstance(item, dict):
                if 'id' in item and 'technique_id' not in item:
                    item['technique_id'] = item.pop('id')
                if 'name' in item and 'technique_name' not in item:
                    item['technique_name'] = item.pop('name')

        # Check if MITRE list has placeholder values
        has_placeholder = any(
            item.get('technique_id') == 'N/A' or item.get('technique_name') == 'N/A'
            for item in llm_output.get('mitre_list', [])
            if isinstance(item, dict)
        )

        if has_placeholder or len(llm_output['mitre_list']) == 0:
            # Build MITRE list from knowledge items
            mitre_dict = {}
            for item in knowledge_items:
                if item.get('entity_type') == 'attack-pattern':
                    technique_id = item.get('metadata', {}).get('mitre_id')
                    technique_name = item.get('name')
                    kill_chains = item.get('metadata', {}).get('kill_chains', [])

                    if technique_id and technique_name:
                        # Extract tactic from kill chain
                        tactic = 'Unknown'
                        if kill_chains:
                            # Kill chain format: "mitre-attack:tactic-name"
                            for chain in kill_chains:
                                if 'mitre-attack:' in chain:
                                    tactic = chain.split(':')[-1].replace('-', ' ').title()
                                    break

                        mitre_dict[technique_id] = {
                            'technique_id': technique_id,
                            'technique_name': technique_name,
                            'tactic': tactic
                        }

            if mitre_dict:
                llm_output['mitre_list'] = list(mitre_dict.values())
                logger.info(f"Fallback: Filled mitre_list with {len(llm_output['mitre_list'])} techniques from knowledge base")

        # 3. Fill missing timeline using alert timestamps
        # Normalize timeline field names (LLM sometimes uses different schema)
        for event in llm_output.get('timeline', []):
            if isinstance(event, dict):
                # Ensure all required fields exist
                if 'host' not in event:
                    event['host'] = 'Unknown'
                if 'tactic' not in event:
                    event['tactic'] = 'Unknown'
                if 'technique' not in event:
                    event['technique'] = 'Unknown'
                # If LLM used "event" instead of "description", rename it
                if 'event' in event and 'description' not in event:
                    event['description'] = event.pop('event')

        if not llm_output.get('timeline') or len(llm_output['timeline']) == 0:
            llm_output['timeline'] = []
            logger.warning("LLM returned empty timeline, generating from alerts")

            # Create timeline from first few alerts with MITRE techniques
            timeline_events = []
            for alert in alerts[:10]:  # First 10 alerts
                timestamp = alert.get('timestamp')
                host = alert.get('agent_name', alert.get('agent_ip', 'Unknown'))
                rule_desc = alert.get('rule_description', 'Unknown activity')

                # Try to extract MITRE technique
                mitre_field = alert.get('mitre_techniques')
                technique = 'Unknown'
                if mitre_field:
                    try:
                        import json
                        mitre_list = json.loads(mitre_field) if isinstance(mitre_field, str) else mitre_field
                        if mitre_list and len(mitre_list) > 0:
                            technique = mitre_list[0]
                    except:
                        pass

                # Find technique name from knowledge
                technique_name = technique
                tactic = 'Unknown'
                for item in knowledge_items:
                    if item.get('metadata', {}).get('mitre_id') == technique:
                        technique_name = item.get('name', technique)
                        kill_chains = item.get('metadata', {}).get('kill_chains', [])
                        if kill_chains:
                            for chain in kill_chains:
                                if 'mitre-attack:' in chain:
                                    tactic = chain.split(':')[-1].replace('-', ' ').title()
                                    break
                        break

                timeline_events.append({
                    'timestamp': timestamp,
                    'host': host,
                    'tactic': tactic,
                    'technique': f"{technique} - {technique_name}",
                    'description': rule_desc[:100]
                })

            llm_output['timeline'] = timeline_events[:5]  # Top 5 events
            logger.info(f"Fallback: Generated timeline with {len(llm_output['timeline'])} events")

        # 4. Fill missing evidence_map
        # Normalize evidence_map field names
        for item in llm_output.get('evidence_map', []):
            if isinstance(item, dict):
                # Ensure required fields exist with proper names
                if 'finding' not in item:
                    item['finding'] = 'Unknown finding'
                # Normalize alert_id -> alert_ids (plural)
                if 'alert_id' in item and 'alert_ids' not in item:
                    item['alert_ids'] = [item.pop('alert_id')]
                if 'timestamp' in item and 'timestamps' not in item:
                    item['timestamps'] = [item.pop('timestamp')]
                if 'host' in item and 'hosts' not in item:
                    item['hosts'] = [item.pop('host')]
                # Ensure arrays exist
                if 'alert_ids' not in item:
                    item['alert_ids'] = []
                if 'timestamps' not in item:
                    item['timestamps'] = []
                if 'hosts' not in item:
                    item['hosts'] = []
                if 'knowledge_refs' not in item:
                    item['knowledge_refs'] = []

        if not llm_output.get('evidence_map') or len(llm_output['evidence_map']) == 0:
            llm_output['evidence_map'] = []

            # Check for placeholder values
            has_placeholder = any(
                item.get('finding') == 'N/A' or item.get('finding') == 'Unknown finding'
                for item in llm_output.get('evidence_map', [])
                if isinstance(item, dict)
            )

            if has_placeholder or len(llm_output['evidence_map']) == 0:
                logger.warning("LLM returned empty/placeholder evidence_map, generating from data")

                # Group alerts by MITRE technique
                technique_groups = {}
                for alert in alerts[:20]:  # First 20 alerts
                    mitre_field = alert.get('mitre_techniques')
                    if mitre_field:
                        try:
                            import json
                            mitre_list = json.loads(mitre_field) if isinstance(mitre_field, str) else mitre_field
                            for tech in mitre_list:
                                if tech not in technique_groups:
                                    technique_groups[tech] = []
                                technique_groups[tech].append(alert)
                        except:
                            pass

                # Create evidence map entries
                evidence_map = []
                for technique, technique_alerts in list(technique_groups.items())[:5]:
                    # Find technique name
                    technique_name = technique
                    for item in knowledge_items:
                        if item.get('metadata', {}).get('mitre_id') == technique:
                            technique_name = item.get('name', technique)
                            break

                    evidence_map.append({
                        'finding': f"{technique_name} activity detected",
                        'alert_ids': [str(a.get('alert_id', '')) for a in technique_alerts[:5]],
                        'timestamps': [a.get('timestamp', '') for a in technique_alerts[:3]],
                        'hosts': list(set([a.get('agent_name', 'Unknown') for a in technique_alerts])),
                        'knowledge_refs': [technique]
                    })

                llm_output['evidence_map'] = evidence_map
                logger.info(f"Fallback: Generated evidence_map with {len(evidence_map)} entries")

        logger.info("Fallback logic complete")
        return llm_output

    def test_llm_connection(self) -> bool:
        """
        Test connection to LLM service

        Returns:
            True if connection successful
        """
        logger.info("Testing LLM connection...")
        return self.llm_client.test_connection()

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """
        Get a specific report

        Args:
            report_id: Report ID

        Returns:
            Report dict or None
        """
        return self.report_storage.get_report(report_id)

    def get_recent_reports(self, limit: int = 10) -> list:
        """
        Get recent reports

        Args:
            limit: Number of reports to return

        Returns:
            List of report dicts
        """
        return self.report_storage.get_recent_reports(limit)

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get statistics about stored reports

        Returns:
            Dict with statistics
        """
        return self.report_storage.get_stats()

    def close(self):
        """Clean up resources"""
        if self.alert_retriever:
            self.alert_retriever.close()
        if self.knowledge_retriever:
            self.knowledge_retriever.close()
        if self.report_storage:
            self.report_storage.close()

        logger.info("Threat Analyzer closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
