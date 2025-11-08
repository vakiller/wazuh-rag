// Type definitions for RAG Wazuh Dashboard

export interface ThreatReport {
  id: number;
  created_at: string;
  window_start: string;
  window_end: string;
  hosts: string[];
  agents: string[];
  alerts_count: number;
  mitre_list: MitreTechnique[];
  summary: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  risk_score: number;
  details: ReportDetails;
  iocs: IOCs;
  suggested_actions: SuggestedActions;
  faiss_context: KnowledgeItem[];
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface ReportDetails {
  tldr?: string;
  timeline?: TimelineEvent[];
  predictions?: Prediction[];
  business_impact?: BusinessImpact;
  evidence_map?: Evidence[];
  detection_recommendations?: DetectionRecommendation[] | {
    sigma_rules?: string[];
    wazuh_rules?: string[];
    log_sources?: string[];
  };
}

export interface TimelineEvent {
  timestamp: string;
  host: string;
  tactic: string;
  technique: string;
  description: string;
}

export interface Prediction {
  action: string;
  confidence: string;
  reasoning?: string;
}

export interface BusinessImpact {
  affected_systems?: string[] | string;
  operational_risk?: string;
  data_integrity_risk?: string;
  domain_wide_risk?: string;
}

export interface Evidence {
  finding: string;
  alert_ids: string[];
  timestamps: string[];
  hosts: string[];
  knowledge_refs: string[];
}

export interface DetectionRecommendation {
  type: string;
  description: string;
}

export interface IOCs {
  ips?: string[];
  users?: string[];
  hashes?: string[];
  domains?: string[];
  file_paths?: string[];
  registry_keys?: string[];
  processes?: string[];
  commands?: string[];
}

export interface SuggestedActions {
  containment?: Action[];
  eradication?: Action[];
  recovery?: Action[];
}

export interface Action {
  action: string;
  priority?: string;
  step?: number;
}

export interface KnowledgeItem {
  entity_type: string;
  name: string;
  score: number;
  mitre_id?: string;
}

export interface DashboardStats {
  total_reports: number;
  high_risk_count: number;
  avg_risk_score: number;
  recent_24h_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
}

export interface SystemConfig {
  wazuh: {
    host: string;
    port: number;
    user: string;
    password: string;
    index_pattern: string;
    ssl_verify: boolean;
  };
  opencti: {
    url: string;
    token: string;
    ssl_verify: boolean;
  };
  llm: {
    base_url: string;
    model: string;
  };
  database: {
    host: string;
    port: number;
    name: string;
    user: string;
    password: string;
  };
  cronjobs: {
    wazuh_retrieval: string;
    knowledge_ingest: string;
    llm_analysis_hourly: string;
    llm_analysis_daily: string;
  };
}
