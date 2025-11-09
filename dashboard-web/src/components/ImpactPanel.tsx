import { AlertTriangle, TrendingDown } from 'lucide-react';
import type { BusinessImpact } from '@/types';

interface ImpactPanelProps {
  impact: BusinessImpact;
}

const getRiskColor = (risk: string) => {
  const lowerRisk = risk?.toLowerCase() || '';
  if (lowerRisk.includes('critical') || lowerRisk.includes('severe')) return 'text-critical';
  if (lowerRisk.includes('high')) return 'text-high';
  if (lowerRisk.includes('medium') || lowerRisk.includes('moderate')) return 'text-medium';
  return 'text-low';
};

export default function ImpactPanel({ impact }: ImpactPanelProps) {
  const hasImpactData = impact?.operational_risk || impact?.data_integrity_risk || impact?.domain_wide_risk;

  if (!hasImpactData) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-lg p-8 text-center">
        <TrendingDown className="w-12 h-12 text-gray-600 mx-auto mb-4" />
        <p className="text-gray-400">No business impact assessment available</p>
      </div>
    );
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-dark-surface border-b border-dark-border p-6">
        <div className="flex items-center space-x-3">
          <AlertTriangle className="w-6 h-6 text-high" />
          <div>
            <h3 className="text-lg font-bold text-white">Business Impact Assessment</h3>
            <p className="text-sm text-gray-400 mt-1">AI-analyzed operational and security risks</p>
          </div>
        </div>
      </div>

      {/* Impact Areas */}
      <div className="p-6 space-y-4">
        {impact.operational_risk && (
          <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
            <div className="flex items-start justify-between mb-2">
              <h4 className="text-sm font-semibold text-gray-300">Operational Risk</h4>
              <span className={`text-sm font-bold ${getRiskColor(impact.operational_risk)}`}>
                {impact.operational_risk.split('-')[0]?.trim() || 'Unknown'}
              </span>
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">{impact.operational_risk}</p>
          </div>
        )}

        {impact.data_integrity_risk && (
          <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
            <div className="flex items-start justify-between mb-2">
              <h4 className="text-sm font-semibold text-gray-300">Data Integrity Risk</h4>
              <span className={`text-sm font-bold ${getRiskColor(impact.data_integrity_risk)}`}>
                {impact.data_integrity_risk.split('-')[0]?.trim() || 'Unknown'}
              </span>
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">{impact.data_integrity_risk}</p>
          </div>
        )}

        {impact.domain_wide_risk && (
          <div className="bg-dark-surface border border-dark-border rounded-lg p-4">
            <div className="flex items-start justify-between mb-2">
              <h4 className="text-sm font-semibold text-gray-300">Domain-Wide Risk</h4>
              <span className={`text-sm font-bold ${getRiskColor(impact.domain_wide_risk)}`}>
                {impact.domain_wide_risk.split('-')[0]?.trim() || 'Unknown'}
              </span>
            </div>
            <p className="text-sm text-gray-400 leading-relaxed">{impact.domain_wide_risk}</p>
          </div>
        )}
      </div>
    </div>
  );
}
