import { useEffect, useState } from 'react';
import { Radio, AlertCircle } from 'lucide-react';
import type { Indicator } from '../types/api';
import { apiClient } from '../services/api';
import IndicatorCard from './IndicatorCard';

interface RealTimeFeedProps {
  confidenceMin?: number;
  onIndicatorClick?: (indicator: Indicator) => void;
}

export default function RealTimeFeed({ confidenceMin = 75, onIndicatorClick }: RealTimeFeedProps) {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const source = apiClient.createIndicatorStream(
      (indicator) => {
        setIndicators((prev) => [indicator, ...prev].slice(0, 10)); // Keep last 10
        setIsConnected(true);
        setError(null);
      },
      (err) => {
        setError(err.message);
        setIsConnected(false);
      },
      { confidence_min: confidenceMin }
    );

    return () => {
      source.close();
    };
  }, [confidenceMin]);

  return (
    <div className="card">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          <Radio className="w-5 h-5 text-primary-600 dark:text-primary-400" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Live Feed
          </h3>
        </div>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
          <span className="text-xs text-gray-600 dark:text-gray-400">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Error State */}
      {error && (
        <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 text-red-600 dark:text-red-400" />
            <span className="text-sm text-red-700 dark:text-red-300">{error}</span>
          </div>
        </div>
      )}

      {/* Indicators */}
      <div className="space-y-3 max-h-[600px] overflow-y-auto">
        {indicators.length === 0 ? (
          <div className="text-center py-8 text-gray-500 dark:text-gray-400">
            <Radio className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p className="text-sm">Waiting for new indicators...</p>
          </div>
        ) : (
          indicators.map((indicator) => (
            <IndicatorCard
              key={indicator.id}
              indicator={indicator}
              onClick={() => onIndicatorClick?.(indicator)}
            />
          ))
        )}
      </div>
    </div>
  );
}
