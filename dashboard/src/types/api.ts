// Type definitions for ThreatStream API

export interface Source {
  name: string;
  first_seen: string;
  confidence?: number;
  tags?: string[];
  malware_family?: string;
}

export interface Enrichment {
  classification: string;
  threat_actor?: string;
  mitre_ttps: string[];
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  recommended_actions: string[];
  description?: string;
}

export interface Indicator {
  id: string;
  indicator_value: string;
  indicator_type: 'domain' | 'IPv4' | 'IPv6' | 'url' | 'hash' | 'email';
  confidence_score: number;
  source_count: number;
  sources: Source[];
  enrichment?: Enrichment;
  enriched_at?: string;
  created_at: string;
  updated_at: string;
}

export interface IndicatorListResponse {
  items: Indicator[];
  continuation_token?: string | null;
  count: number;
}

export interface Relationship {
  id: string;
  source_id: string;
  target_id: string;
  relationship_type: 'resolves_to' | 'downloads' | 'communicates_with' | 'contains';
  confidence: number;
  detected_at: string;
}

export interface RelationshipListResponse {
  items: Relationship[];
  count: number;
}

export interface Stats {
  total_indicators: number;
  by_type: {
    [key: string]: number;
  };
  last_updated: string | null;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
}

export interface ApiError {
  error: string;
  detail?: string;
  code?: string;
}

export interface QueryParams {
  indicator_type?: string;
  confidence_min?: number;
  page_size?: number;
  continuation_token?: string;
}

export interface SearchParams {
  q: string;
  page_size?: number;
}

export interface SSEEvent {
  type: 'heartbeat' | 'indicator' | 'error' | 'close';
  data: any;
}
