import { Globe, Hash, Mail, Server } from 'lucide-react';
import type { Indicator } from '../types/api';
import { formatDistanceToNow } from 'date-fns';

interface IndicatorCardProps {
  indicator: Indicator;
  onClick?: () => void;
}

export default function IndicatorCard({ indicator, onClick }: IndicatorCardProps) {
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'domain':
      case 'url':
        return Globe;
      case 'IPv4':
      case 'IPv6':
        return Server;
      case 'email':
        return Mail;
      case 'hash':
        return Hash;
      default:
        return Globe;
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'badge-danger';
      case 'high':
        return 'badge-danger';
      case 'medium':
        return 'badge-warning';
      case 'low':
        return 'badge-success';
      default:
        return 'badge-info';
    }
  };

  const getConfidenceColor = (score: number) => {
    if (score >= 90) return 'text-green-600 dark:text-green-400';
    if (score >= 75) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const Icon = getTypeIcon(indicator.indicator_type);

  return (
    <div
      className="card hover:shadow-lg transition-shadow cursor-pointer"
      onClick={onClick}
    >
      <div className="flex items-start space-x-4">
        {/* Icon */}
        <div className="flex-shrink-0">
          <div className="flex items-center justify-center w-10 h-10 bg-gray-100 dark:bg-gray-700 rounded-lg">
            <Icon className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Indicator Value */}
          <p className="text-sm font-mono font-medium text-gray-900 dark:text-white truncate">
            {indicator.indicator_value}
          </p>

          {/* Type and Confidence */}
          <div className="mt-1 flex items-center space-x-2">
            <span className="badge badge-info">
              {indicator.indicator_type}
            </span>
            <span className={`text-xs font-semibold ${getConfidenceColor(indicator.confidence_score)}`}>
              {indicator.confidence_score}% confidence
            </span>
          </div>

          {/* Enrichment */}
          {indicator.enrichment && (
            <div className="mt-2">
              <div className="flex items-center space-x-2">
                <span className={`badge ${getSeverityColor(indicator.enrichment.severity)}`}>
                  {indicator.enrichment.severity}
                </span>
                <span className="text-xs text-gray-600 dark:text-gray-400">
                  {indicator.enrichment.classification}
                </span>
              </div>

              {/* MITRE TTPs */}
              {indicator.enrichment.mitre_ttps.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {indicator.enrichment.mitre_ttps.slice(0, 3).map((ttp) => (
                    <span
                      key={ttp}
                      className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
                    >
                      {ttp}
                    </span>
                  ))}
                  {indicator.enrichment.mitre_ttps.length > 3 && (
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      +{indicator.enrichment.mitre_ttps.length - 3} more
                    </span>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Metadata */}
          <div className="mt-2 flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
            <span>{indicator.source_count} source{indicator.source_count !== 1 ? 's' : ''}</span>
            <span>•</span>
            <span>{formatDistanceToNow(new Date(indicator.created_at), { addSuffix: true })}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
