"""
Field mapping definitions between Wazuh alert structure and normalized schema.
"""

from typing import List, Optional, Dict, Any

# Wazuh alert structure paths to normalized fields
ALERT_FIELD_MAPPINGS = {
    # Core fields
    'timestamp': '@timestamp',
    'index_name': '_index',
    'document_id': '_id',

    # Agent information
    'agent_id': 'agent.id',
    'agent_name': 'agent.name',
    'agent_ip': 'agent.ip',

    # Rule information
    'rule_id': 'rule.id',
    'rule_description': 'rule.description',
    'rule_level': 'rule.level',
    'rule_groups': 'rule.groups',  # Array
    'rule_mitre_id': 'rule.mitre.id',  # Array
    'rule_mitre_tactic': 'rule.mitre.tactic',  # Array
    'rule_mitre_technique': 'rule.mitre.technique',  # Array

    # Alert metadata
    'alert_id': 'id',
    'location': 'location',
    'decoder_name': 'decoder.name',

    # Network fields
    'source_ip': 'data.srcip',
    'dest_ip': 'data.dstip',
    'source_port': 'data.srcport',
    'dest_port': 'data.dstport',
    'protocol': 'data.protocol',

    # File/Process fields
    'file_path': 'syscheck.path',
    'file_hash_md5': 'syscheck.md5_after',
    'file_hash_sha1': 'syscheck.sha1_after',
    'file_hash_sha256': 'syscheck.sha256_after',
    'process_name': 'data.process_name',
    'process_id': 'data.process_id',
    'command_line': 'data.command',

    # User/Authentication
    'username': 'data.dstuser',
    'source_user': 'data.srcuser',

    # Windows-specific
    'win_eventid': 'data.win.eventdata.eventID',
    'win_system_name': 'data.win.system.computer',

    # Full log message
    'full_log': 'full_log',
}

# Fields that are arrays in Wazuh
ARRAY_FIELDS = {
    'rule_groups',
    'rule_mitre_id',
    'rule_mitre_tactic',
    'rule_mitre_technique'
}

# Fields that should be converted to integers
INTEGER_FIELDS = {
    'rule_level',
    'source_port',
    'dest_port',
    'process_id',
    'win_eventid'
}

# Normalized schema definition (for documentation and validation)
NORMALIZED_SCHEMA = {
    # Required fields (always present)
    'timestamp': str,  # ISO8601
    'index_name': str,
    'document_id': str,
    'agent_id': str,
    'rule_id': str,
    'rule_level': int,

    # Optional agent fields
    'agent_name': Optional[str],
    'agent_ip': Optional[str],

    # Optional rule fields
    'rule_description': Optional[str],
    'rule_groups': List[str],

    # MITRE ATT&CK fields (flattened from various sources)
    'mitre_techniques': List[str],
    'mitre_tactics': List[str],

    # Optional network fields
    'source_ip': Optional[str],
    'dest_ip': Optional[str],
    'source_port': Optional[int],
    'dest_port': Optional[int],
    'protocol': Optional[str],

    # Optional file fields
    'file_path': Optional[str],
    'file_hash': Optional[str],  # Prefer SHA256, fallback to SHA1, MD5

    # Optional process fields
    'process_name': Optional[str],
    'process_id': Optional[int],
    'command_line': Optional[str],

    # Optional user fields
    'username': Optional[str],

    # Optional Windows fields
    'win_eventid': Optional[int],

    # Full log message
    'full_log': Optional[str],
}

# MITRE ATT&CK technique to tactic mapping (for enrichment)
# This is a subset - you can expand based on your needs
MITRE_TECHNIQUE_TO_TACTIC = {
    'T1110': ['Credential Access'],
    'T1078': ['Defense Evasion', 'Persistence', 'Privilege Escalation', 'Initial Access'],
    'T1059': ['Execution'],
    'T1071': ['Command and Control'],
    'T1053': ['Execution', 'Persistence', 'Privilege Escalation'],
    'T1055': ['Defense Evasion', 'Privilege Escalation'],
    'T1082': ['Discovery'],
    'T1083': ['Discovery'],
    'T1087': ['Discovery'],
    'T1003': ['Credential Access'],
    'T1021': ['Lateral Movement'],
    'T1070': ['Defense Evasion'],
    'T1562': ['Defense Evasion'],
    'T1136': ['Persistence'],
    'T1098': ['Persistence'],
    'T1543': ['Persistence', 'Privilege Escalation'],
    'T1548': ['Privilege Escalation', 'Defense Evasion'],
}
