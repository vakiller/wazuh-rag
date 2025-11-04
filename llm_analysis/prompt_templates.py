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

## Output Format:

You MUST respond with valid JSON only (no markdown, no explanations outside JSON):

```json
{
  "summary": "One paragraph incident summary",
  "mitre_list": [
    {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
    ...
  ],
  "predictions": [
    {"action": "Attacker will attempt...", "confidence": "High", "reasoning": "Because..."},
    ...
  ],
  "suggested_actions": [
    {"step": 1, "action": "Isolate affected host...", "priority": "Critical"},
    ...
  ],
  "evidence_map": [
    {"finding": "Suspicious login", "alert_ids": ["123", "124"], "knowledge_refs": ["attack-pattern:T1078"]},
    ...
  ],
  "iocs": {
    "ips": ["192.168.1.100", ...],
    "hashes": ["abc123...", ...],
    "domains": ["malicious.com", ...],
    "file_paths": ["/tmp/suspicious", ...],
    "accounts": ["compromised_user", ...],
    "processes": ["malware.exe", ...]
  },
  "confidence_overall": 85,
  "tldr": "One-sentence summary of the threat"
}
```

## Important Guidelines:

- Base your analysis ONLY on provided evidence and retrieved knowledge
- Do NOT hallucinate or invent details not present in the data
- If confidence is low, state that clearly
- Prioritize actions by urgency
- Be specific with IOCs - include exact values found in alerts
- Cross-reference MITRE techniques with observed behaviors
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

Analyze the above evidence and retrieved knowledge to produce a comprehensive threat analysis report in the JSON format specified in your system instructions.

Focus on:
1. What attack is occurring or has occurred
2. Which MITRE ATT&CK techniques are involved
3. What the attacker might do next
4. How to respond and remediate
5. All IOCs that should be hunted across the network

Remember: Output ONLY valid JSON, no additional text."""


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
