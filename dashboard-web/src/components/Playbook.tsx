import { useState } from 'react';
import { Lightbulb, ChevronDown, ChevronUp, Shield, XCircle, CheckCircle } from 'lucide-react';
import type { SuggestedActions } from '@/types';

interface PlaybookProps {
  playbook: SuggestedActions;
}

type PhaseKey = 'containment' | 'eradication' | 'recovery';

const phaseConfig: Record<PhaseKey, { label: string; icon: typeof Shield; color: string; description: string }> = {
  containment: {
    label: 'Containment',
    icon: XCircle,
    color: 'from-critical to-high',
    description: 'Immediate actions to prevent further damage'
  },
  eradication: {
    label: 'Eradication',
    icon: Shield,
    color: 'from-high to-medium',
    description: 'Remove threat actor presence and artifacts'
  },
  recovery: {
    label: 'Recovery',
    icon: CheckCircle,
    color: 'from-medium to-low',
    description: 'Restore systems to normal operation'
  },
};

export default function Playbook({ playbook }: PlaybookProps) {
  const [expandedPhases, setExpandedPhases] = useState<Set<PhaseKey>>(
    new Set(['containment', 'eradication', 'recovery'])
  );

  const togglePhase = (phase: PhaseKey) => {
    const newExpanded = new Set(expandedPhases);
    if (newExpanded.has(phase)) {
      newExpanded.delete(phase);
    } else {
      newExpanded.add(phase);
    }
    setExpandedPhases(newExpanded);
  };

  const hasAnyActions = playbook.containment?.length || playbook.eradication?.length || playbook.recovery?.length;

  if (!hasAnyActions) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-lg p-12 text-center">
        <Lightbulb className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <p className="text-gray-400">No response playbook available</p>
      </div>
    );
  }

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-dark-surface border-b border-dark-border p-6">
        <div className="flex items-center space-x-3">
          <Lightbulb className="w-6 h-6 text-medium" />
          <div>
            <h3 className="text-xl font-bold text-white">AI-Generated Response Playbook</h3>
            <p className="text-sm text-gray-400 mt-1">Recommended incident response workflow</p>
          </div>
        </div>
      </div>

      {/* Phases */}
      <div className="divide-y divide-dark-border">
        {(Object.keys(phaseConfig) as PhaseKey[]).map((phase) => {
          const config = phaseConfig[phase];
          const Icon = config.icon;
          const actions = playbook[phase] || [];
          const isExpanded = expandedPhases.has(phase);

          if (actions.length === 0) return null;

          return (
            <div key={phase}>
              {/* Phase Header */}
              <button
                onClick={() => togglePhase(phase)}
                className="w-full p-6 flex items-center justify-between hover:bg-dark-hover transition-colors"
              >
                <div className="flex items-center space-x-4">
                  <div className={`p-3 rounded-lg bg-gradient-to-br ${config.color}`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="flex items-center space-x-3">
                      <h4 className="text-lg font-bold text-white">{config.label}</h4>
                      <span className="px-3 py-1 bg-dark-border rounded-full text-xs font-semibold text-gray-400">
                        {actions.length} {actions.length === 1 ? 'Action' : 'Actions'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 mt-1">{config.description}</p>
                  </div>
                </div>
                {isExpanded ? (
                  <ChevronUp className="w-5 h-5 text-gray-400" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-gray-400" />
                )}
              </button>

              {/* Actions List */}
              {isExpanded && (
                <div className="px-6 pb-6 bg-dark-surface/30">
                  <div className="space-y-3">
                    {actions.map((actionItem, index) => {
                      const actionText = typeof actionItem === 'string' ? actionItem : actionItem.action;
                      const priority = typeof actionItem === 'object' ? actionItem.priority : undefined;

                      return (
                        <div
                          key={index}
                          className="flex items-start space-x-4 bg-dark-card border border-dark-border rounded-lg p-4 hover:border-info/30 transition-all"
                        >
                          <div className="flex-shrink-0 w-8 h-8 rounded-full bg-dark-border flex items-center justify-center">
                            <span className="text-sm font-bold text-gray-300">{index + 1}</span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-start justify-between">
                              <p className="text-sm text-gray-200 leading-relaxed flex-1">{actionText}</p>
                              {priority && (
                                <span className={`ml-4 flex-shrink-0 px-2 py-1 rounded text-xs font-semibold ${
                                  priority.toLowerCase() === 'high' ? 'bg-critical/20 text-critical' :
                                  priority.toLowerCase() === 'medium' ? 'bg-medium/20 text-medium' :
                                  'bg-low/20 text-low'
                                }`}>
                                  {priority}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
