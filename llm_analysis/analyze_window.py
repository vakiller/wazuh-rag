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
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Use absolute imports instead of relative
from llm_analysis.retrieval import AlertRetriever, KnowledgeRetriever
from llm_analysis.llm_client import LLMClient
from llm_analysis.storage import ReportStorage
from llm_analysis.preprocessor import AlertPreprocessor
from llm_analysis.prompt_templates import (
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

    def _calculate_deterministic_severity(
        self,
        alerts: list,
        hosts: set,
        mitre_techniques: set,
        preparsed_data: Dict[str, Any]
    ) -> str:
        """
        Calculate severity deterministically using rubric (Phase 4.2)

        Rubric:
        - Destructive technique (T1485, T1486, T1490) = +2
        - Domain policy modification (T1484) = +2
        - Multi-host impact (>=3 hosts) = +1
        - High alert volume (>1000) = +1
        - Valid account access (T1078) = +1
        - Privilege escalation present = +1

        Severity scale:
        - 0-1: Low
        - 2-3: Medium
        - 4-5: High
        - 6+: Critical

        Args:
            alerts: List of alert dicts
            hosts: Set of affected hosts
            mitre_techniques: Set of MITRE technique IDs
            preparsed_data: Pre-parsed data from preprocessor

        Returns:
            Severity: Low | Medium | High | Critical
        """
        score = 0

        # Destructive techniques (+2)
        destructive_techniques = {'T1485', 'T1486', 'T1490'}
        if any(tech in mitre_techniques for tech in destructive_techniques):
            score += 2
            logger.info("Severity +2: Destructive technique detected")

        # Domain policy modification (+2)
        if 'T1484' in mitre_techniques:
            score += 2
            logger.info("Severity +2: Domain policy modification detected")

        # Multi-host impact (+1)
        if len(hosts) >= 3:
            score += 1
            logger.info(f"Severity +1: Multi-host impact ({len(hosts)} hosts)")

        # High alert volume (+1)
        if len(alerts) > 1000:
            score += 1
            logger.info(f"Severity +1: High alert volume ({len(alerts)} alerts)")

        # Valid account access (+1)
        if 'T1078' in mitre_techniques:
            score += 1
            logger.info("Severity +1: Valid account access detected")

        # Privilege escalation (+1)
        priv_esc_techniques = {
            'T1068', 'T1134', 'T1484', 'T1543', 'T1546', 'T1547', 'T1548', 'T1549'
        }
        if any(tech in mitre_techniques for tech in priv_esc_techniques):
            score += 1
            logger.info("Severity +1: Privilege escalation technique detected")

        # Map score to severity
        if score >= 6:
            severity = 'Critical'
        elif score >= 4:
            severity = 'High'
        elif score >= 2:
            severity = 'Medium'
        else:
            severity = 'Low'

        logger.info(f"Deterministic severity: {severity} (score: {score})")
        return severity

    def _generate_business_impact(
        self,
        mitre_techniques: set,
        hosts: set,
        preparsed_data: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Generate business impact deterministically (Phase 4.2)

        Args:
            mitre_techniques: Set of MITRE technique IDs
            hosts: Set of affected hosts
            preparsed_data: Pre-parsed data

        Returns:
            Dict with business impact assessment
        """
        impact = {
            'affected_systems': [],
            'operational_risk': '',
            'data_integrity_risk': '',
            'domain_wide_risk': ''
        }

        # Affected systems
        if hosts:
            impact['affected_systems'] = list(hosts)[:5]  # Top 5 hosts

        # Domain-wide risk
        if 'T1484' in mitre_techniques or 'T1485' in mitre_techniques:
            impact['domain_wide_risk'] = 'High - Potential for domain-wide compromise due to policy modification or destructive techniques'
        elif len(hosts) >= 5:
            impact['domain_wide_risk'] = 'Medium - Multiple hosts affected, lateral movement possible'
        else:
            impact['domain_wide_risk'] = 'Low - Limited host impact'

        # Operational risk
        if len(hosts) >= 3:
            impact['operational_risk'] = 'High - Service disruption likely across multiple systems'
        elif 'T1485' in mitre_techniques or 'T1486' in mitre_techniques:
            impact['operational_risk'] = 'Critical - Data destruction or ransomware detected, immediate business impact'
        elif 'T1490' in mitre_techniques:
            impact['operational_risk'] = 'High - System recovery capabilities inhibited'
        else:
            impact['operational_risk'] = 'Medium - Limited operational disruption expected'

        # Data integrity risk
        if 'T1078' in mitre_techniques:
            impact['data_integrity_risk'] = 'High - Valid credentials compromised, unauthorized data access possible'
        elif 'T1485' in mitre_techniques or 'T1565' in mitre_techniques:
            impact['data_integrity_risk'] = 'Critical - Data destruction or manipulation detected'
        elif 'T1003' in mitre_techniques:
            impact['data_integrity_risk'] = 'High - Credential dumping detected, data exfiltration risk'
        else:
            impact['data_integrity_risk'] = 'Medium - Potential for data compromise'

        logger.info(f"Generated business impact: domain_wide={impact['domain_wide_risk'][:20]}, operational={impact['operational_risk'][:20]}")
        return impact

    def _generate_technique_playbooks(
        self,
        mitre_techniques: set,
        existing_actions
    ) -> Dict[str, list]:
        """
        Add technique-specific response playbooks (Phase 4.2)

        Args:
            mitre_techniques: Set of MITRE technique IDs
            existing_actions: Existing suggested actions from LLM (dict or list)

        Returns:
            Enhanced actions dict with technique-specific playbooks
        """
        # Handle both old (list) and new (dict) formats
        if isinstance(existing_actions, dict):
            # Ensure each value is a list
            actions = {}
            for phase in ['containment', 'eradication', 'recovery']:
                value = existing_actions.get(phase, [])
                if isinstance(value, list):
                    actions[phase] = value[:]
                elif isinstance(value, str):
                    actions[phase] = [value] if value else []
                else:
                    actions[phase] = []
        elif isinstance(existing_actions, list):
            # Old format - convert to new format
            actions = {
                'containment': [],
                'eradication': [],
                'recovery': []
            }
            # Try to categorize existing actions
            for action in existing_actions:
                action_text = str(action) if action else ''
                if not action_text:
                    continue
                if any(keyword in action_text.lower() for keyword in ['isolate', 'disable', 'block', 'stop']):
                    actions['containment'].append(action_text)
                elif any(keyword in action_text.lower() for keyword in ['remove', 'delete', 'scan', 'clean']):
                    actions['eradication'].append(action_text)
                else:
                    actions['recovery'].append(action_text)
        else:
            # Empty or invalid format
            actions = {
                'containment': [],
                'eradication': [],
                'recovery': []
            }

        logger.debug(f"Playbook actions after normalization: containment={type(actions['containment'])}, eradication={type(actions['eradication'])}, recovery={type(actions['recovery'])}")

        # T1112 - Modify Registry
        if 'T1112' in mitre_techniques:
            if not any('registry' in a.lower() for a in actions['containment']):
                actions['containment'].append('Enable real-time registry monitoring and alerting')
            if not any('registry' in a.lower() for a in actions['eradication']):
                actions['eradication'].append('Audit and rollback unauthorized registry modifications')
                actions['eradication'].append('Scan for persistence mechanisms in registry Run keys')
            if not any('registry' in a.lower() for a in actions['recovery']):
                actions['recovery'].append('Restore registry from known-good backup')
                actions['recovery'].append('Implement stricter registry access controls')

        # T1078 - Valid Accounts
        if 'T1078' in mitre_techniques:
            if not any('credential' in a.lower() or 'password' in a.lower() for a in actions['containment']):
                actions['containment'].append('Force password reset for all potentially compromised accounts')
                actions['containment'].append('Enable MFA for all administrative accounts')
            if not any('account' in a.lower() for a in actions['eradication']):
                actions['eradication'].append('Review and revoke suspicious authentication sessions')
            if not any('credential' in a.lower() or 'password' in a.lower() for a in actions['recovery']):
                actions['recovery'].append('Implement password policy enhancements')
                actions['recovery'].append('Deploy account anomaly detection')

        # T1485 - Data Destruction
        if 'T1485' in mitre_techniques:
            if not any('backup' in a.lower() for a in actions['containment']):
                actions['containment'].append('Immediately isolate affected systems to prevent further data loss')
            if not any('recover' in a.lower() or 'restore' in a.lower() for a in actions['recovery']):
                actions['recovery'].append('Restore data from Volume Shadow Copies (VSS)')
                actions['recovery'].append('Restore critical files from backup systems')
                actions['recovery'].append('Verify data integrity after restoration')

        # T1484 - Domain Policy Modification
        if 'T1484' in mitre_techniques:
            if not any('policy' in a.lower() or 'gpo' in a.lower() for a in actions['containment']):
                actions['containment'].append('Audit all Group Policy Objects (GPOs) for unauthorized changes')
                actions['containment'].append('Revert malicious GPO modifications immediately')
            if not any('domain' in a.lower() for a in actions['eradication']):
                actions['eradication'].append('Review domain controller logs for unauthorized administrative actions')
            if not any('policy' in a.lower() for a in actions['recovery']):
                actions['recovery'].append('Restore GPOs from known-good backups')
                actions['recovery'].append('Implement GPO change monitoring and approval workflow')

        # T1003 - Credential Dumping
        if 'T1003' in mitre_techniques:
            if not any('credential' in a.lower() for a in actions['containment']):
                actions['containment'].append('Reset all domain administrator credentials immediately')
                actions['containment'].append('Enable Credential Guard on all endpoints')
            if not any('lsass' in a.lower() or 'mimikatz' in a.lower() for a in actions['eradication']):
                actions['eradication'].append('Scan for credential dumping tools (mimikatz, procdump)')
                actions['eradication'].append('Clear LSASS memory and restart affected systems')

        logger.info(f"Enhanced playbooks: {len(actions['containment'])} containment, {len(actions['eradication'])} eradication, {len(actions['recovery'])} recovery actions")
        return actions

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

        # Phase 4.2: Always enhance timeline to eliminate "Unknown" values
        # Build technique lookup map from knowledge base
        technique_map = {}
        for item in knowledge_items:
            if item.get('entity_type') == 'attack-pattern':
                tech_id = item.get('metadata', {}).get('mitre_id')
                if tech_id:
                    technique_map[tech_id] = {
                        'name': item.get('name', tech_id),
                        'tactic': 'Unknown'
                    }
                    # Extract tactic from kill chain
                    kill_chains = item.get('metadata', {}).get('kill_chains', [])
                    for chain in kill_chains:
                        if 'mitre-attack:' in chain:
                            tactic = chain.split(':')[-1].replace('-', ' ').title()
                            technique_map[tech_id]['tactic'] = tactic
                            break

        # If timeline is empty, generate from alerts
        if len(llm_output['timeline']) == 0:
            timeline_events = []
            # Group alerts by technique for better timeline
            alert_groups = {}
            for alert in alerts[:20]:
                mitre_field = alert.get('mitre_techniques')
                if mitre_field:
                    try:
                        import json
                        mitre_list = json.loads(mitre_field) if isinstance(mitre_field, str) else mitre_field
                        for tech in mitre_list:
                            if tech not in alert_groups:
                                alert_groups[tech] = []
                            alert_groups[tech].append(alert)
                    except:
                        pass

            # Create timeline entry for each technique
            for tech_id, tech_alerts in list(alert_groups.items())[:5]:
                first_alert = tech_alerts[0]
                tech_info = technique_map.get(tech_id, {'name': tech_id, 'tactic': 'Unknown'})

                timeline_events.append({
                    'timestamp': first_alert.get('timestamp', 'Unknown'),
                    'host': first_alert.get('agent_name', first_alert.get('agent_ip', 'Unknown')),
                    'tactic': tech_info['tactic'],
                    'technique': f"{tech_id} - {tech_info['name']}",
                    'description': first_alert.get('rule_description', 'Security alert detected')[:100]
                })

            llm_output['timeline'] = timeline_events
            logger.info(f"Fallback: Generated timeline with {len(llm_output['timeline'])} events")

        # Phase 4.2: Check if timeline has "Unknown" placeholders and regenerate if needed
        has_unknown_timeline = any(
            isinstance(event, dict) and (
                event.get('tactic') == 'Unknown' or
                event.get('technique') == 'Unknown' or
                'Unknown' in str(event.get('technique', ''))
            )
            for event in llm_output.get('timeline', [])
        )

        if has_unknown_timeline:
            logger.warning("Timeline contains Unknown values, regenerating from alerts")
            # Regenerate timeline completely
            timeline_events = []
            alert_groups = {}
            for alert in alerts[:20]:
                mitre_field = alert.get('mitre_techniques')
                if mitre_field:
                    try:
                        import json
                        mitre_list = json.loads(mitre_field) if isinstance(mitre_field, str) else mitre_field
                        for tech in mitre_list:
                            if tech not in alert_groups:
                                alert_groups[tech] = []
                            alert_groups[tech].append(alert)
                    except:
                        pass

            for tech_id, tech_alerts in list(alert_groups.items())[:5]:
                first_alert = tech_alerts[0]
                tech_info = technique_map.get(tech_id, {'name': tech_id, 'tactic': 'N/A'})

                timeline_events.append({
                    'timestamp': first_alert.get('timestamp', 'N/A'),
                    'host': first_alert.get('agent_name', first_alert.get('agent_ip', 'N/A')),
                    'tactic': tech_info['tactic'],
                    'technique': f"{tech_id} - {tech_info['name']}",
                    'description': first_alert.get('rule_description', 'Security alert detected')[:100]
                })

            llm_output['timeline'] = timeline_events
            logger.info(f"Timeline regenerated: {len(timeline_events)} events with full context")
        else:
            logger.info("Timeline enhanced: no Unknown values found")

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

                # Phase 4.2: Generate evidence map with detailed findings
                # Build technique lookup from knowledge base
                tech_lookup = {}
                for item in knowledge_items:
                    if item.get('entity_type') == 'attack-pattern':
                        tech_id = item.get('metadata', {}).get('mitre_id')
                        if tech_id:
                            tech_lookup[tech_id] = {
                                'name': item.get('name', tech_id),
                                'description': item.get('content', '')[:200]
                            }

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

                # Create evidence map entries with detailed findings
                evidence_map = []
                for technique, technique_alerts in list(technique_groups.items())[:5]:
                    tech_info = tech_lookup.get(technique, {'name': technique, 'description': ''})
                    technique_name = tech_info['name']

                    # Build detailed finding description
                    host_count = len(set([a.get('agent_name') for a in technique_alerts if a.get('agent_name')]))
                    finding_desc = f"{technique_name} ({technique}) detected on {host_count} host(s)"

                    # Add context from alert rules
                    common_rules = {}
                    for alert in technique_alerts[:5]:
                        rule = alert.get('rule_description', '')
                        if rule:
                            common_rules[rule] = common_rules.get(rule, 0) + 1

                    if common_rules:
                        top_rule = max(common_rules, key=common_rules.get)
                        finding_desc += f" - {top_rule[:80]}"

                    evidence_map.append({
                        'finding': finding_desc,
                        'alert_ids': [str(a.get('alert_id', '')) for a in technique_alerts[:5]],
                        'timestamps': [a.get('timestamp', '') for a in technique_alerts[:3]],
                        'hosts': list(set([a.get('agent_name', 'Unknown') for a in technique_alerts if a.get('agent_name')]))[:5],
                        'knowledge_refs': [technique]
                    })

                llm_output['evidence_map'] = evidence_map
                logger.info(f"Fallback: Generated evidence_map with {len(evidence_map)} entries")

        # 5. Apply deterministic severity (Phase 4.2 - override LLM)
        mitre_ids = set()
        for item in llm_output.get('mitre_list', []):
            if isinstance(item, dict) and item.get('technique_id'):
                mitre_ids.add(item['technique_id'])

        # Extract hosts from alerts for severity calculation
        alert_hosts = set()
        for alert in alerts[:100]:
            if alert.get('agent_name'):
                alert_hosts.add(alert['agent_name'])

        deterministic_severity = self._calculate_deterministic_severity(
            alerts=alerts,
            hosts=alert_hosts,
            mitre_techniques=mitre_ids,
            preparsed_data=preparsed_data
        )

        # Override LLM severity with deterministic calculation
        if deterministic_severity != llm_output.get('severity'):
            logger.warning(f"Overriding LLM severity '{llm_output.get('severity')}' with deterministic '{deterministic_severity}'")
            llm_output['severity'] = deterministic_severity

        # 6. Generate business impact (Phase 4.2)
        if not llm_output.get('business_impact') or not isinstance(llm_output.get('business_impact'), dict):
            llm_output['business_impact'] = {}

        # Check if business impact is incomplete
        impact_fields = ['affected_systems', 'operational_risk', 'data_integrity_risk', 'domain_wide_risk']
        has_incomplete_impact = any(
            not llm_output.get('business_impact', {}).get(field)
            for field in impact_fields
        )

        if has_incomplete_impact:
            logger.info("Generating deterministic business impact")
            generated_impact = self._generate_business_impact(
                mitre_techniques=mitre_ids,
                hosts=alert_hosts,
                preparsed_data=preparsed_data
            )
            # Merge generated impact with any existing LLM output
            for key, value in generated_impact.items():
                if not llm_output['business_impact'].get(key):
                    llm_output['business_impact'][key] = value

        # 7. Enhance suggested actions with technique-specific playbooks (Phase 4.2)
        if llm_output.get('suggested_actions'):
            enhanced_actions = self._generate_technique_playbooks(
                mitre_techniques=mitre_ids,
                existing_actions=llm_output['suggested_actions']
            )
            llm_output['suggested_actions'] = enhanced_actions

        logger.info("Fallback logic complete (Phase 4.2 enhanced)")
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
