import { useEffect, useState } from 'react';
import { Database, AlertTriangle, TrendingUp, Activity } from 'lucide-react';
import Header from '../components/Header';
import StatCard from '../components/StatCard';
import SearchFilters from '../components/SearchFilters';
import IndicatorCard from '../components/IndicatorCard';
import IndicatorTypeChart from '../components/IndicatorTypeChart';
import RealTimeFeed from '../components/RealTimeFeed';
import IndicatorModal from '../components/IndicatorModal';
import { apiClient } from '../services/api';
import type { Indicator, Stats, HealthResponse } from '../types/api';

export default function Dashboard() {
  // State
  const [health, setHealth] = useState<HealthResponse['status']>('healthy');
  const [stats, setStats] = useState<Stats | null>(null);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [selectedIndicator, setSelectedIndicator] = useState<Indicator | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Search filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('all');
  const [minConfidence, setMinConfidence] = useState(75);

  // Load initial data
  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);

        // Load health status
        const healthData = await apiClient.getHealth();
        setHealth(healthData.status);

        // Load stats
        const statsData = await apiClient.getStats();
        setStats(statsData);

        // Load initial indicators
        const indicatorsData = await apiClient.getIndicators({
          confidence_min: minConfidence,
          page_size: 20,
        });
        setIndicators(indicatorsData.items);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load data');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  // Handle search
  const handleSearch = async () => {
    try {
      setLoading(true);
      setError(null);

      if (searchQuery.trim()) {
        // Search by query
        const data = await apiClient.searchIndicators({
          q: searchQuery,
          page_size: 50,
        });
        setIndicators(data.items);
      } else {
        // Filter by type and confidence
        const data = await apiClient.getIndicators({
          indicator_type: selectedType !== 'all' ? selectedType : undefined,
          confidence_min: minConfidence,
          page_size: 50,
        });
        setIndicators(data.items);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
    } finally {
      setLoading(false);
    }
  };

  // Calculate high severity count
  const highSeverityCount = indicators.filter(
    (ind) => ind.enrichment?.severity === 'High' || ind.enrichment?.severity === 'Critical'
  ).length;

  // Calculate average confidence
  const avgConfidence = indicators.length > 0
    ? Math.round(indicators.reduce((sum, ind) => sum + ind.confidence_score, 0) / indicators.length)
    : 0;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <Header health={health} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Banner */}
        {error && (
          <div className="mb-6 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400" />
              <span className="text-sm text-red-700 dark:text-red-300">{error}</span>
            </div>
          </div>
        )}

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Total Indicators"
            value={stats?.total_indicators || 0}
            icon={Database}
            loading={loading && !stats}
          />
          <StatCard
            title="High Severity"
            value={highSeverityCount}
            icon={AlertTriangle}
            loading={loading}
          />
          <StatCard
            title="Avg Confidence"
            value={`${avgConfidence}%`}
            icon={TrendingUp}
            loading={loading}
          />
          <StatCard
            title="Sources Active"
            value={3}
            icon={Activity}
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Search and Results */}
          <div className="lg:col-span-2 space-y-6">
            {/* Search Filters */}
            <SearchFilters
              searchQuery={searchQuery}
              onSearchChange={setSearchQuery}
              selectedType={selectedType}
              onTypeChange={setSelectedType}
              minConfidence={minConfidence}
              onConfidenceChange={setMinConfidence}
              onSearch={handleSearch}
            />

            {/* Indicator Type Chart */}
            {stats?.by_type && <IndicatorTypeChart data={stats.by_type} />}

            {/* Indicators List */}
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                Indicators ({indicators.length})
              </h3>

              {loading ? (
                <div className="space-y-3">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="animate-pulse bg-gray-200 dark:bg-gray-700 rounded-lg h-24" />
                  ))}
                </div>
              ) : indicators.length === 0 ? (
                <div className="text-center py-12 text-gray-500 dark:text-gray-400">
                  <Database className="w-12 h-12 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">No indicators found</p>
                </div>
              ) : (
                <div className="space-y-3 max-h-[800px] overflow-y-auto">
                  {indicators.map((indicator) => (
                    <IndicatorCard
                      key={indicator.id}
                      indicator={indicator}
                      onClick={() => setSelectedIndicator(indicator)}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Right Column - Live Feed */}
          <div className="lg:col-span-1">
            <RealTimeFeed
              confidenceMin={minConfidence}
              onIndicatorClick={setSelectedIndicator}
            />
          </div>
        </div>
      </main>

      {/* Indicator Details Modal */}
      <IndicatorModal
        indicator={selectedIndicator}
        isOpen={selectedIndicator !== null}
        onClose={() => setSelectedIndicator(null)}
      />
    </div>
  );
}
