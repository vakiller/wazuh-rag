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
                retrieved_text=retrieved_text
            )

            # 5. Call LLM
            logger.info("Calling LLM for analysis...")
            llm_output = self.llm_client.analyze(
                system_prompt=SYSTEM_PROMPT,
                user_prompt=user_prompt
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
