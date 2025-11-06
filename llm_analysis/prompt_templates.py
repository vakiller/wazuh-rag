"""
Prompt Templates for LLM Analysis

Defines system and user prompts for structured threat analysis
"""

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst with expertise in threat detection, incident response, MITRE ATT&CK framework, and security operations.

Your task is to analyze security alerts from Wazuh SIEM along with retrieved threat intelligence from OpenCTI to produce a comprehensive professional-grade incident analysis report.

## Analysis Requirements:

1. **Incident Summary**: Write a clear, comprehensive paragraph covering:
   - Attack type and initial access vector
   - Which systems/users were affected
   - Timeline progression
   - Current threat status
   - Potential impact

2. **Severity Classification**: Assign ONE of: Low | Medium | High | Critical
   Based on:
   - Number of affected hosts
   - Presence of privilege escalation
   - Destructive techniques (data destruction, ransomware)
   - Number of MITRE tactics involved
   - Potential for lateral movement

3. **MITRE Kill-Chain Timeline**: Construct chronological attack progression with:
   - timestamp (from alerts)
   - host (affected system)
   - tactic (MITRE tactic name)
   - technique (MITRE technique ID and name)
   - description (what happened)

4. **MITRE ATT&CK Mapping**: List all techniques with:
   - technique_id (e.g., T1078)
   - technique_name (e.g., Valid Accounts)
   - tactic (e.g., Persistence)

5. **Threat Predictions**: Predict attacker's next 3 likely actions:
   - action (specific predicted behavior)
   - confidence (High/Medium/Low)
   - reasoning (why this is likely based on observed patterns)

6. **Incident Response Workflow**: Provide structured response in THREE phases:
   - **Containment**: Immediate actions to stop spread
   - **Eradication**: Steps to remove threat from environment
   - **Recovery**: Actions to restore normal operations

7. **Business Impact Assessment**: Analyze:
   - affected_systems (what business functions are impacted)
   - operational_risk (how operations are disrupted)
   - data_integrity_risk (risk to data confidentiality/integrity)
   - domain_wide_risk (potential for enterprise-wide compromise)

8. **Enhanced Evidence Mapping**: Link each finding to:
   - finding (what was discovered)
   - alert_ids (which alert IDs contain this evidence)
   - timestamps (when it occurred)
   - hosts (which systems involved)
   - knowledge_refs (relevant OpenCTI knowledge items)

9. **Comprehensive IOC Extraction**: Extract ALL indicators:
   - ips (IP addresses from alerts)
   - users (user accounts involved)
   - hashes (file hashes if available)
   - domains (domain names)
   - file_paths (suspicious file paths)
   - registry_keys (Windows registry modifications)
   - processes (process names)
   - commands (command-line executions)

10. **Detection Improvements**: Suggest enhancements:
   - sigma_rules (Sigma-like detection rule concepts)
   - wazuh_rules (specific Wazuh rule improvements)
   - log_sources (additional logging needed)

11. **Confidence Assessment**: Overall analysis confidence (0-100)

12. **TL;DR**: One concise sentence summarizing the incident

## CRITICAL - Using Pre-Parsed Context:

You will receive a section called "PRE-PARSED STRUCTURED CONTEXT" that contains deterministically extracted information from alert logs. This data is GUARANTEED to be accurate.

**YOU MUST**:
- Use the pre-parsed MITRE technique IDs EXACTLY as provided
- Use the pre-parsed IP addresses for the "iocs.ips" field
- Use the pre-parsed usernames for the "iocs.users" field
- Use the pre-parsed file paths for the "iocs.file_paths" field
- Use the pre-parsed registry keys for the "iocs.registry_keys" field
- Use the pre-parsed processes for the "iocs.processes" field
- Use the pre-parsed commands for the "iocs.commands" field
- Use the pre-parsed timestamps for the "timeline" field
- Use the pre-parsed alert IDs for the "evidence_map" field

**DO NOT**:
- Guess or invent IOCs
- Output "N/A" for any field
- Ignore the pre-parsed context
- Make up MITRE technique names - use the retrieved knowledge base to find the correct names for the technique IDs

## FEW-SHOT EXAMPLE:

Here is an example of the EXACT JSON format you MUST output:

{{
  "summary": "Suspicious registry modification detected on winterfell host at 2025-01-04 12:05:22. The attacker modified HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run to establish persistence. This was followed by credential access attempts using mimikatz.exe. The attack affected 3 hosts and utilized 4 MITRE techniques across Initial Access, Persistence, and Credential Access tactics.",
  "severity": "High",
  "tldr": "Credential theft activity with registry-based persistence on 3 hosts.",
  "timeline": [
    {{"timestamp": "2025-01-04T12:05:22Z", "host": "winterfell", "tactic": "Initial Access", "technique": "T1078 - Valid Accounts", "description": "Successful login with compromised credentials"}},
    {{"timestamp": "2025-01-04T12:08:15Z", "host": "winterfell", "tactic": "Persistence", "technique": "T1547.001 - Registry Run Keys", "description": "Modified registry key HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"}},
    {{"timestamp": "2025-01-04T12:12:33Z", "host": "castelblack", "tactic": "Credential Access", "technique": "T1003 - OS Credential Dumping", "description": "Executed mimikatz.exe to dump credentials"}}
  ],
  "mitre_list": [
    {{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access"}},
    {{"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "tactic": "Persistence"}},
    {{"technique_id": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access"}}
  ],
  "predictions": [
    {{"action": "Attempt lateral movement to additional hosts using stolen credentials", "confidence": "High", "reasoning": "Credential dumping typically precedes lateral movement in multi-stage attacks"}},
    {{"action": "Establish additional persistence mechanisms", "confidence": "Medium", "reasoning": "Attackers often create backup persistence to maintain access"}}
  ],
  "suggested_actions": {{
    "containment": ["Isolate affected hosts winterfell and castelblack from network", "Disable compromised user accounts immediately", "Block outbound connections from affected hosts"],
    "eradication": ["Remove malicious registry key HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "Delete mimikatz.exe from all affected systems", "Scan for additional malware"],
    "recovery": ["Reset passwords for all potentially compromised accounts", "Restore clean registry configuration", "Re-enable hosts after verification", "Monitor for recurrence"]
  }},
  "business_impact": {{
    "affected_systems": ["Domain controllers", "File servers"],
    "operational_risk": "High - potential for business disruption if lateral movement continues",
    "data_integrity_risk": "High - credential theft enables data exfiltration",
    "domain_wide_risk": "Critical - stolen domain admin credentials could compromise entire environment"
  }},
  "evidence_map": [
    {{"finding": "Registry persistence mechanism created", "alert_ids": ["12345", "12346"], "timestamps": ["2025-01-04T12:08:15Z"], "hosts": ["winterfell"], "knowledge_refs": ["T1547.001"]}},
    {{"finding": "Credential dumping with mimikatz", "alert_ids": ["12350", "12351"], "timestamps": ["2025-01-04T12:12:33Z"], "hosts": ["castelblack"], "knowledge_refs": ["T1003"]}}
  ],
  "iocs": {{
    "ips": ["192.168.56.20", "10.0.0.15"],
    "users": ["admin", "backup_user"],
    "hashes": ["a3d5c7e9f1b2"],
    "domains": ["malicious-c2.com"],
    "file_paths": ["C:\\\\Windows\\\\Temp\\\\mimikatz.exe", "C:\\\\ProgramData\\\\update.exe"],
    "registry_keys": ["HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"],
    "processes": ["mimikatz.exe", "powershell.exe"],
    "commands": ["powershell -enc SQBFAFgAKA...", "net user admin P@ssw0rd"]
  }},
  "detection_recommendations": [
    {{"type": "sigma_rule", "description": "Detect registry run key modifications outside of normal software installation"}},
    {{"type": "wazuh_rule", "description": "Alert on execution of known credential dumping tools like mimikatz"}},
    {{"type": "log_source", "description": "Enable Sysmon Event ID 13 for registry modifications"}}
  ],
  "confidence_overall": 85
}}

This example shows ALL fields properly populated with realistic data. You MUST output in this exact structure.

## CRITICAL - Output Format Requirements:

You MUST respond with ONLY valid JSON. No markdown code blocks. No explanations. No additional text before or after the JSON.

REQUIRED JSON STRUCTURE (you must use EXACTLY these field names):

{{
  "summary": "STRING - Comprehensive incident summary with attack type, affected systems, timeline, and impact",
  "severity": "STRING - One of: Low | Medium | High | Critical",
  "tldr": "STRING - One sentence summary",
  "timeline": [
    {{"timestamp": "2025-11-04T10:30:00Z", "host": "server01", "tactic": "Initial Access", "technique": "T1078 - Valid Accounts", "description": "Successful login with compromised credentials"}}
  ],
  "mitre_list": [
    {{"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"}}
  ],
  "predictions": [
    {{"action": "Specific predicted next action", "confidence": "High", "reasoning": "Why this action is likely based on observed TTPs"}}
  ],
  "suggested_actions": {{
    "containment": ["Isolate affected host from network", "Disable compromised accounts"],
    "eradication": ["Remove malicious artifacts", "Patch vulnerabilities"],
    "recovery": ["Restore from clean backup", "Monitor for recurrence"]
  }},
  "business_impact": {{
    "affected_systems": ["Domain controllers", "File servers"],
    "operational_risk": "High - potential for business disruption",
    "data_integrity_risk": "Medium - risk of data modification",
    "domain_wide_risk": "High - lateral movement possible"
  }},
  "evidence_map": [
    {{"finding": "Suspicious login pattern", "alert_ids": ["123", "124"], "timestamps": ["2025-11-04T10:30:00Z"], "hosts": ["server01"], "knowledge_refs": ["T1078"]}}
  ],
  "iocs": {{
    "ips": ["192.168.1.100"],
    "users": ["compromised_user"],
    "hashes": ["abc123def456"],
    "domains": ["malicious.com"],
    "file_paths": ["/tmp/malware.sh"],
    "registry_keys": ["HKLM\\\\Software\\\\Malware"],
    "processes": ["malware.exe"],
    "commands": ["powershell -enc base64payload"]
  }},
  "detection_recommendations": [
    {{"type": "sigma_rule", "description": "Detect suspicious account usage patterns"}},
    {{"type": "wazuh_rule", "description": "Alert on rapid multiple logins from single account"}},
    {{"type": "log_source", "description": "Enable PowerShell script block logging"}}
  ],
  "confidence_overall": 85
}}

STRICT RULES:
1. Return ONLY the JSON object - no markdown, no code blocks, no extra text
2. All field names must match EXACTLY as shown above
3. "severity" must be ONE of: Low, Medium, High, Critical
4. "timeline" must contain chronological events with: timestamp, host, tactic, technique, description
5. "mitre_list" must contain objects with: technique_id, technique_name, tactic
6. "suggested_actions" must be an object with three arrays: containment, eradication, recovery
7. "business_impact" must be an object with: affected_systems, operational_risk, data_integrity_risk, domain_wide_risk
8. "iocs" must be an object with arrays for: ips, users, hashes, domains, file_paths, registry_keys, processes, commands
9. "evidence_map" must link findings to: alert_ids, timestamps, hosts, knowledge_refs
10. "detection_recommendations" must contain objects with: type, description
11. If a field has no data, use empty array [] or empty string "", but the field MUST exist
12. Do NOT use alternative field names - use EXACTLY the names shown above
13. Do NOT nest the structure under other keys

IMPORTANT: Base your analysis ONLY on the provided evidence and retrieved knowledge. Do NOT hallucinate or invent details not present in the data. Extract actual IOCs from the alert logs - use real IP addresses, usernames, file paths, and commands from the evidence provided.
"""


USER_PROMPT_TEMPLATE = """## SECURITY ALERT EVIDENCE

**Analysis Window**: {window_start} to {window_end}
**Total Alerts**: {alert_count}
**Affected Hosts**: {hosts}
**Affected Agents**: {agents}

### Alert Details:

{evidence_text}

---

{preparsed_text}

---

## RETRIEVED THREAT INTELLIGENCE

The following knowledge items were retrieved from OpenCTI threat intelligence database based on observed MITRE techniques and semantic similarity:

{retrieved_text}

---

## YOUR TASK

Analyze the above evidence and retrieved knowledge to produce a comprehensive professional-grade SOC incident analysis report.

You MUST return ONLY a JSON object with EXACTLY these top-level fields (all are required):
- summary (comprehensive incident description)
- severity (Low | Medium | High | Critical)
- tldr (one sentence summary)
- timeline (chronological attack progression)
- mitre_list (all techniques with IDs, names, tactics)
- predictions (attacker's next likely actions)
- suggested_actions (containment, eradication, recovery)
- business_impact (affected systems, risks)
- evidence_map (findings linked to alerts, timestamps, hosts)
- iocs (ips, users, hashes, domains, file_paths, registry_keys, processes, commands)
- detection_recommendations (sigma rules, wazuh rules, log sources)
- confidence_overall (0-100)

Critical Analysis Focus:
1. **Attack Reconstruction**: Build timeline from earliest to latest events
2. **Severity Assessment**: Consider hosts affected, privilege escalation, destructive techniques
3. **MITRE Mapping**: Extract ALL techniques from alerts and match with knowledge base
4. **Threat Prediction**: Based on current TTPs, predict next attack stages
5. **Incident Response**: Provide actionable containment, eradication, recovery steps
6. **Business Impact**: Assess risk to operations, data, and enterprise
7. **IOC Extraction**: Pull REAL values from alert logs (actual IPs, users, files, commands)
8. **Detection Gaps**: Identify missing detections and suggest improvements

CRITICAL: Return ONLY the JSON object. No markdown code blocks. No "```json". No explanatory text. Just the pure JSON object starting with {{ and ending with }}."""


def format_user_prompt(
    window_start: str,
    window_end: str,
    alert_count: int,
    hosts: list,
    agents: list,
    evidence_text: str,
    retrieved_text: str,
    preparsed_text: str = ""
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
        preparsed_text: Pre-parsed structured context (Phase 4.1)

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
        preparsed_text=preparsed_text,
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
