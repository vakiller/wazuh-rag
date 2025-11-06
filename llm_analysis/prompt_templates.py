"""
Prompt Templates for LLM Analysis

Defines system and user prompts for structured threat analysis
"""

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant with expertise in threat detection, incident response, and MITRE ATT&CK framework.

Your task is to analyze security alerts from Wazuh SIEM along with retrieved threat intelligence from OpenCTI to produce a comprehensive threat analysis report.

## Analysis Requirements:

1. **Incident Summary**: Write a clear, one-paragraph summary of the security incident covering:
   - What happened
   - Which systems/users were affected
   - Timeline of events
   - Potential impact

2. **MITRE ATT&CK Mapping**: List all MITRE ATT&CK techniques observed or suspected, including:
   - Technique ID (e.g., T1078)
   - Technique name
   - Tactic (e.g., Initial Access, Persistence)

3. **Threat Predictions**: Based on observed techniques, predict the attacker's next 3 most likely actions:
   - Action description
   - Confidence level (High/Medium/Low)
   - Reasoning

4. **Remediation Actions**: Provide ordered, actionable steps for:
   - Immediate containment (steps 1-3)
   - Investigation (steps 4-5)
   - Remediation (steps 6-7)

5. **Evidence Mapping**: Link findings to specific alert IDs and knowledge sources

6. **IOC Extraction**: Identify all Indicators of Compromise:
   - IP addresses
   - File hashes (MD5, SHA1, SHA256)
   - Domain names
   - File paths
   - User accounts
   - Process names

7. **Confidence Assessment**: Provide an overall confidence score (0-100) for your analysis

## CRITICAL - Output Format Requirements:

You MUST respond with ONLY valid JSON. No markdown code blocks. No explanations. No additional text before or after the JSON.

REQUIRED JSON STRUCTURE (you must use EXACTLY these field names):

{{
  "summary": "STRING - One paragraph incident summary describing what happened, which systems were affected, timeline, and potential impact",
  "mitre_list": [
    {{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"}}
  ],
  "predictions": [
    {{"action": "Specific predicted next action", "confidence": "High", "reasoning": "Why this action is likely"}}
  ],
  "suggested_actions": [
    {{"step": 1, "action": "Specific actionable step", "priority": "Critical"}}
  ],
  "evidence_map": [
    {{"finding": "What was found", "alert_ids": ["id1", "id2"], "knowledge_refs": ["ref1"]}}
  ],
  "iocs": {{
    "ips": ["IP addresses as strings"],
    "hashes": ["File hashes as strings"],
    "domains": ["Domain names as strings"],
    "file_paths": ["File paths as strings"],
    "accounts": ["User account names as strings"],
    "processes": ["Process names as strings"]
  }},
  "confidence_overall": 85,
  "tldr": "One sentence summary"
}}

STRICT RULES:
1. Return ONLY the JSON object - no markdown, no code blocks, no extra text
2. All field names must match EXACTLY as shown above
3. "iocs" must be an object with arrays for: ips, hashes, domains, file_paths, accounts, processes
4. "mitre_list" must contain objects with: technique_id, technique_name, tactic
5. "suggested_actions" must contain objects with: step (number), action (string), priority (string)
6. If a field has no data, use empty array [] or empty string "", but the field must exist
7. Do NOT use alternative field names like "threat_analysis", "ioc_list", "remediation_steps", etc.
8. Do NOT nest the structure under other keys

IMPORTANT: Base your analysis ONLY on the provided evidence and retrieved knowledge. Do NOT hallucinate or invent details not present in the data. Be specific with IOCs - include exact values found in alerts.
"""


USER_PROMPT_TEMPLATE = """## SECURITY ALERT EVIDENCE

**Analysis Window**: {window_start} to {window_end}
**Total Alerts**: {alert_count}
**Affected Hosts**: {hosts}
**Affected Agents**: {agents}

### Alert Details:

{evidence_text}

---

## RETRIEVED THREAT INTELLIGENCE

The following knowledge items were retrieved from OpenCTI threat intelligence database based on observed MITRE techniques and semantic similarity:

{retrieved_text}

---

## YOUR TASK

Analyze the above evidence and retrieved knowledge to produce a comprehensive threat analysis report.

You MUST return ONLY a JSON object with EXACTLY these top-level fields:
- summary
- mitre_list
- predictions
- suggested_actions
- evidence_map
- iocs
- confidence_overall
- tldr

Focus on:
1. What attack is occurring or has occurred
2. Which MITRE ATT&CK techniques are involved (extract from alerts and knowledge)
3. What the attacker might do next (predictions)
4. How to respond and remediate (suggested_actions)
5. All IOCs that should be hunted across the network

CRITICAL: Return ONLY the JSON object. No markdown code blocks. No "```json". No explanatory text. Just the pure JSON object starting with {{ and ending with }}."""


def format_user_prompt(
    window_start: str,
    window_end: str,
    alert_count: int,
    hosts: list,
    agents: list,
    evidence_text: str,
    retrieved_text: str
) -> str:
    """
    Format the user prompt with actual data

    Args:
        window_start: Analysis window start timestamp
        window_end: Analysis window end timestamp
        alert_count: Number of alerts
        hosts: List of affected hosts
        agents: List of affected agent IDs
        evidence_text: Formatted alert evidence
        retrieved_text: Formatted retrieved knowledge

    Returns:
        Formatted user prompt
    """
    hosts_str = ', '.join(hosts) if hosts else 'N/A'
    agents_str = ', '.join(agents) if agents else 'N/A'

    return USER_PROMPT_TEMPLATE.format(
        window_start=window_start,
        window_end=window_end,
        alert_count=alert_count,
        hosts=hosts_str,
        agents=agents_str,
        evidence_text=evidence_text,
        retrieved_text=retrieved_text
    )


def format_alert_evidence(alerts: list, max_chars: int = 8000) -> str:
    """
    Format alerts into structured evidence text

    Args:
        alerts: List of alert dicts from database
        max_chars: Maximum characters to include (truncate if needed)

    Returns:
        Formatted evidence text
    """
    lines = []

    for i, alert in enumerate(alerts, 1):
        lines.append(f"### Alert #{i} (ID: {alert.get('alert_id', 'unknown')})")
        lines.append(f"- **Timestamp**: {alert.get('timestamp')}")
        lines.append(f"- **Rule**: {alert.get('rule_description')} (Level {alert.get('rule_level')})")
        lines.append(f"- **Agent**: {alert.get('agent_name')} ({alert.get('agent_id')})")
        lines.append(f"- **Host**: {alert.get('agent_ip')}")

        # MITRE techniques
        mitre = alert.get('mitre_techniques')
        if mitre and mitre != '[]':
            try:
                import json
                mitre_list = json.loads(mitre) if isinstance(mitre, str) else mitre
                if mitre_list:
                    lines.append(f"- **MITRE Techniques**: {', '.join(mitre_list)}")
            except:
                pass

        # Key fields
        if alert.get('source_ip'):
            lines.append(f"- **Source IP**: {alert.get('source_ip')}")
        if alert.get('dest_ip'):
            lines.append(f"- **Dest IP**: {alert.get('dest_ip')}")
        if alert.get('source_port'):
            lines.append(f"- **Source Port**: {alert.get('source_port')}")
        if alert.get('dest_port'):
            lines.append(f"- **Dest Port**: {alert.get('dest_port')}")
        if alert.get('process_name'):
            lines.append(f"- **Process**: {alert.get('process_name')}")
        if alert.get('file_path'):
            lines.append(f"- **File**: {alert.get('file_path')}")
        if alert.get('file_hash'):
            lines.append(f"- **Hash**: {alert.get('file_hash')}")
        if alert.get('command_line'):
            lines.append(f"- **Command**: {alert.get('command_line')}")

        # Log excerpt
        full_log = alert.get('full_log', '')
        if full_log:
            log_preview = full_log[:200] + '...' if len(full_log) > 200 else full_log
            lines.append(f"- **Log**: {log_preview}")

        lines.append("")  # Blank line between alerts

    text = '\n'.join(lines)

    # Truncate if too long
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n[... truncated {len(text) - max_chars} characters ...]"

    return text


def format_retrieved_knowledge(knowledge_items: list, max_chars: int = 6000) -> str:
    """
    Format retrieved knowledge items into text

    Args:
        knowledge_items: List of knowledge items from FAISS search
        max_chars: Maximum characters to include

    Returns:
        Formatted knowledge text
    """
    if not knowledge_items:
        return "No relevant threat intelligence found in knowledge base."

    lines = []

    for i, item in enumerate(knowledge_items, 1):
        lines.append(f"### Knowledge Item #{i}")
        lines.append(f"- **Type**: {item.get('entity_type', 'unknown')}")
        lines.append(f"- **Name**: {item.get('name', 'unknown')}")
        lines.append(f"- **Similarity Score**: {item.get('score', 0):.3f}")

        # Metadata
        metadata = item.get('metadata', {})
        if metadata.get('mitre_id'):
            lines.append(f"- **MITRE ID**: {metadata['mitre_id']}")
        if metadata.get('platforms'):
            lines.append(f"- **Platforms**: {', '.join(metadata['platforms'])}")
        if metadata.get('kill_chains'):
            lines.append(f"- **Kill Chain**: {', '.join(metadata['kill_chains'])}")

        # Content excerpt
        content = item.get('content', '')
        if content:
            content_preview = content[:500] + '...' if len(content) > 500 else content
            lines.append(f"\n{content_preview}")

        lines.append("")  # Blank line

    text = '\n'.join(lines)

    # Truncate if too long
    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n[... truncated {len(text) - max_chars} characters ...]"

    return text
