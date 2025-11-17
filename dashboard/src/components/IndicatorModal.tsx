import { X, Globe, Calendar, Shield, Users } from 'lucide-react';
import type { Indicator } from '../types/api';
import { format } from 'date-fns';

interface IndicatorModalProps {
  indicator: Indicator | null;
  isOpen: boolean;
  onClose: () => void;
}

export default function IndicatorModal({ indicator, isOpen, onClose }: IndicatorModalProps) {
  if (!isOpen || !indicator) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
        {/* Backdrop */}
        <div
          className="fixed inset-0 transition-opacity bg-gray-500 bg-opacity-75 dark:bg-gray-900 dark:bg-opacity-75"
          onClick={onClose}
        />

        {/* Modal */}
        <div className="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-3xl sm:w-full">
          {/* Header */}
          <div className="bg-gray-50 dark:bg-gray-700 px-6 py-4 border-b border-gray-200 dark:border-gray-600">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Globe className="w-6 h-6 text-primary-600 dark:text-primary-400" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Indicator Details
                </h3>
              </div>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300 focus:outline-none"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
          </div>

          {/* Content */}
          <div className="px-6 py-4 space-y-6">
            {/* Indicator Value */}
            <div>
              <h4 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-1">
                Indicator Value
              </h4>
              <p className="text-lg font-mono font-semibold text-gray-900 dark:text-white">
                {indicator.indicator_value}
              </p>
              <div className="mt-2 flex items-center space-x-2">
                <span className="badge badge-info">{indicator.indicator_type}</span>
                <span className="badge badge-success">
                  {indicator.confidence_score}% confidence
                </span>
              </div>
            </div>

            {/* Enrichment */}
            {indicator.enrichment && (
              <div>
                <div className="flex items-center space-x-2 mb-3">
                  <Shield className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                  <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                    Threat Analysis
                  </h4>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 space-y-3">
                  <div>
                    <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                      Classification:
                    </span>
                    <p className="mt-1 text-sm text-gray-900 dark:text-white">
                      {indicator.enrichment.classification}
                    </p>
                  </div>

                  {indicator.enrichment.threat_actor && (
                    <div>
                      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                        Threat Actor:
                      </span>
                      <p className="mt-1 text-sm text-gray-900 dark:text-white">
                        {indicator.enrichment.threat_actor}
                      </p>
                    </div>
                  )}

                  <div>
                    <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                      Severity:
                    </span>
                    <div className="mt-1">
                      <span className={`badge ${
                        indicator.enrichment.severity === 'Critical' || indicator.enrichment.severity === 'High'
                          ? 'badge-danger'
                          : indicator.enrichment.severity === 'Medium'
                          ? 'badge-warning'
                          : 'badge-success'
                      }`}>
                        {indicator.enrichment.severity}
                      </span>
                    </div>
                  </div>

                  {/* MITRE ATT&CK */}
                  {indicator.enrichment.mitre_ttps.length > 0 && (
                    <div>
                      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                        MITRE ATT&CK TTPs:
                      </span>
                      <div className="mt-2 flex flex-wrap gap-2">
                        {indicator.enrichment.mitre_ttps.map((ttp) => (
                          <span
                            key={ttp}
                            className="inline-flex items-center px-2 py-1 rounded text-xs font-mono bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
                          >
                            {ttp}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommended Actions */}
                  {indicator.enrichment.recommended_actions.length > 0 && (
                    <div>
                      <span className="text-sm font-medium text-gray-500 dark:text-gray-400">
                        Recommended Actions:
                      </span>
                      <ul className="mt-2 space-y-1">
                        {indicator.enrichment.recommended_actions.map((action, idx) => (
                          <li key={idx} className="text-sm text-gray-700 dark:text-gray-300 flex items-start">
                            <span className="mr-2">•</span>
                            <span>{action}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Sources */}
            <div>
              <div className="flex items-center space-x-2 mb-3">
                <Users className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                  Sources ({indicator.source_count})
                </h4>
              </div>
              <div className="space-y-2">
                {indicator.sources.map((source, idx) => (
                  <div
                    key={idx}
                    className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-sm text-gray-900 dark:text-white">
                        {source.name}
                      </span>
                      {source.confidence && (
                        <span className="text-xs text-gray-600 dark:text-gray-400">
                          {source.confidence}% confidence
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      First seen: {format(new Date(source.first_seen), 'PPpp')}
                    </p>
                    {source.tags && source.tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {source.tags.map((tag) => (
                          <span
                            key={tag}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-200 text-gray-700 dark:bg-gray-600 dark:text-gray-300"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Metadata */}
            <div>
              <div className="flex items-center space-x-2 mb-3">
                <Calendar className="w-5 h-5 text-gray-500 dark:text-gray-400" />
                <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                  Timeline
                </h4>
              </div>
              <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Created:</span>
                  <span className="text-gray-900 dark:text-white">
                    {format(new Date(indicator.created_at), 'PPpp')}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600 dark:text-gray-400">Updated:</span>
                  <span className="text-gray-900 dark:text-white">
                    {format(new Date(indicator.updated_at), 'PPpp')}
                  </span>
                </div>
                {indicator.enriched_at && (
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Enriched:</span>
                    <span className="text-gray-900 dark:text-white">
                      {format(new Date(indicator.enriched_at), 'PPpp')}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="bg-gray-50 dark:bg-gray-700 px-6 py-4 border-t border-gray-200 dark:border-gray-600">
            <button
              onClick={onClose}
              className="w-full sm:w-auto px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
