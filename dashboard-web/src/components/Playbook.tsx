import { useState } from 'react';
import { Lightbulb, ChevronDown, ChevronUp, Shield, XCircle, CheckCircle, Terminal, Copy, Check } from 'lucide-react';
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
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const togglePhase = (phase: PhaseKey) => {
    const newExpanded = new Set(expandedPhases);
    if (newExpanded.has(phase)) {
      newExpanded.delete(phase);
    } else {
      newExpanded.add(phase);
    }
    setExpandedPhases(newExpanded);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCommand(text);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const hasAnyActions = playbook.containment?.length || playbook.eradication?.length || playbook.recovery?.length;

  if (!hasAnyActions) {
    return (
      <div className="bg-white border border-neutral-300 p-12 text-center">
        <Lightbulb className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
        <p className="text-neutral-700 font-medium">No response playbook available</p>
      </div>
    );
  }

  return (
    <div className="bg-white border border-neutral-300 overflow-hidden">
      {/* Header */}
      <div className="bg-neutral-50 border-b border-neutral-300 p-6">
        <div className="flex items-center space-x-3">
          <Lightbulb className="w-6 h-6 text-medium" />
          <div>
            <h3 className="text-xl font-medium text-neutral-900">AI-Generated Response Playbook</h3>
            <p className="text-sm text-neutral-700 font-medium mt-1">Recommended incident response workflow</p>
          </div>
        </div>
      </div>

      {/* Phases */}
      <div className="divide-y divide-neutral-300">
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
                className="w-full p-6 flex items-center justify-between hover:bg-neutral-50 transition-colors"
              >
                <div className="flex items-center space-x-4">
                  <div className={`p-3 bg-gradient-to-br ${config.color}`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <div className="text-left">
                    <div className="flex items-center space-x-3">
                      <h4 className="text-lg font-medium text-neutral-900">{config.label}</h4>
                      <span className="px-3 py-1 bg-neutral-200 text-xs font-semibold text-neutral-900">
                        {actions.length} {actions.length === 1 ? 'Action' : 'Actions'}
                      </span>
                    </div>
                    <p className="text-sm text-neutral-700 font-medium mt-1">{config.description}</p>
                  </div>
                </div>
                {isExpanded ? (
                  <ChevronUp className="w-5 h-5 text-neutral-700" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-neutral-700" />
                )}
              </button>

              {/* Actions List */}
              {isExpanded && (
                <div className="px-6 pb-6 bg-neutral-50">
                  <div className="space-y-3">
                    {actions.map((actionItem, index) => {
                      const actionText = typeof actionItem === 'string' ? actionItem : actionItem.action;
                      const priority = typeof actionItem === 'object' ? actionItem.priority : undefined;
                      const command = typeof actionItem === 'object' ? actionItem.command : undefined;
                      const tools = typeof actionItem === 'object' ? actionItem.tools : undefined;

                      return (
                        <div
                          key={index}
                          className="flex items-start space-x-4 bg-white border border-neutral-300 p-4 hover:shadow-md transition-all"
                        >
                          <div className="flex-shrink-0 w-8 h-8 rounded-full bg-neutral-200 flex items-center justify-center">
                            <span className="text-sm font-semibold text-neutral-900">{index + 1}</span>
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-start justify-between">
                              <p className="text-sm text-neutral-900 leading-relaxed flex-1 font-medium">{actionText}</p>
                              {priority && (
                                <span className={`ml-4 flex-shrink-0 px-2 py-1 text-xs font-semibold border ${priority.toLowerCase() === 'critical' ? 'bg-critical-light text-critical border-critical' :
                                  priority.toLowerCase() === 'high' ? 'bg-high-light text-high border-high' :
                                    priority.toLowerCase() === 'medium' ? 'bg-medium-light text-medium border-medium' :
                                      'bg-low-light text-low border-low'
                                  }`}>
                                  {priority}
                                </span>
                              )}
                            </div>

                            {/* Tools Tags */}
                            {tools && tools.length > 0 && (
                              <div className="mt-3 flex flex-wrap gap-2">
                                {tools.map((tool, i) => (
                                  <span key={i} className="px-2 py-1 bg-neutral-50 text-xs text-neutral-700 font-medium border border-neutral-300">
                                    {tool}
                                  </span>
                                ))}
                              </div>
                            )}

                            {/* Command Block */}
                            {command && (
                              <div className="mt-3 relative group">
                                <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                  <button
                                    onClick={() => copyToClipboard(command)}
                                    className="p-1.5 bg-neutral-100 hover:bg-neutral-200 text-neutral-700 hover:text-neutral-900 transition-colors"
                                    title="Copy command"
                                  >
                                    {copiedCommand === command ? <Check className="w-4 h-4 text-green-600" /> : <Copy className="w-4 h-4" />}
                                  </button>
                                </div>
                                <div className="bg-neutral-900 border border-neutral-300 p-3 font-mono text-sm text-neutral-100 overflow-x-auto flex items-start gap-3">
                                  <Terminal className="w-4 h-4 text-neutral-400 flex-shrink-0 mt-0.5" />
                                  <span>{command}</span>
                                </div>
                              </div>
                            )}
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
