import type {
  Indicator,
  IndicatorListResponse,
  RelationshipListResponse,
  Stats,
  HealthResponse,
  QueryParams,
  SearchParams,
  ApiError,
} from '../types/api';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const API_KEY = import.meta.env.VITE_API_KEY || '';

class ApiClient {
  private baseUrl: string;
  private apiKey: string;

  constructor(baseUrl: string = API_BASE_URL, apiKey: string = API_KEY) {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }

  private async fetch<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    // Add API key for authenticated endpoints
    if (this.apiKey && endpoint !== '/health') {
      headers['X-API-Key'] = this.apiKey;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const error: ApiError = await response.json().catch(() => ({
          error: response.statusText,
        }));
        throw new Error(error.error || `HTTP ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      if (error instanceof Error) {
        throw error;
      }
      throw new Error('An unexpected error occurred');
    }
  }

  // Health check (no auth required)
  async getHealth(): Promise<HealthResponse> {
    return this.fetch<HealthResponse>('/health');
  }

  // Query indicators with filters
  async getIndicators(params: QueryParams = {}): Promise<IndicatorListResponse> {
    const queryString = new URLSearchParams(
      Object.entries(params)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [key, String(value)])
    ).toString();

    return this.fetch<IndicatorListResponse>(`/indicators${queryString ? `?${queryString}` : ''}`);
  }

  // Get indicator by ID
  async getIndicatorById(id: string): Promise<Indicator> {
    return this.fetch<Indicator>(`/indicators/${encodeURIComponent(id)}`);
  }

  // Search indicators
  async searchIndicators(params: SearchParams): Promise<IndicatorListResponse> {
    const queryString = new URLSearchParams(
      Object.entries(params)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [key, String(value)])
    ).toString();

    return this.fetch<IndicatorListResponse>(`/indicators/search?${queryString}`);
  }

  // Get relationships
  async getRelationships(indicatorId?: string, relationshipType?: string): Promise<RelationshipListResponse> {
    const params: Record<string, string> = {};
    if (indicatorId) params.indicator_id = indicatorId;
    if (relationshipType) params.relationship_type = relationshipType;

    const queryString = new URLSearchParams(params).toString();

    return this.fetch<RelationshipListResponse>(`/relationships${queryString ? `?${queryString}` : ''}`);
  }

  // Get platform statistics
  async getStats(): Promise<Stats> {
    return this.fetch<Stats>('/stats');
  }

  // Create EventSource for SSE streaming
  createIndicatorStream(
    onIndicator: (indicator: Indicator) => void,
    onError: (error: Error) => void,
    options: { confidence_min?: number; indicator_type?: string; heartbeat_interval?: number } = {}
  ): EventSource {
    const params = new URLSearchParams(
      Object.entries(options)
        .filter(([, value]) => value !== undefined)
        .map(([key, value]) => [key, String(value)])
    );

    // EventSource doesn't support custom headers, so we append API key as query param
    if (this.apiKey) {
      params.set('api_key', this.apiKey);
    }

    const url = `${this.baseUrl}/stream/indicators?${params.toString()}`;
    const eventSource = new EventSource(url);

    eventSource.addEventListener('indicator', (event) => {
      try {
        const indicator: Indicator = JSON.parse(event.data);
        onIndicator(indicator);
      } catch (error) {
        console.error('Failed to parse indicator:', error);
      }
    });

    eventSource.addEventListener('error', (event) => {
      try {
        const errorData = JSON.parse((event as MessageEvent).data);
        onError(new Error(errorData.error || 'Stream error'));
      } catch {
        onError(new Error('Connection error'));
      }
    });

    eventSource.onerror = () => {
      onError(new Error('EventSource connection failed'));
    };

    return eventSource;
  }
}

export const apiClient = new ApiClient();
export default ApiClient;
