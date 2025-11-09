import { useState } from 'react';
import { Clock, ChevronDown, ChevronUp, Target, Server } from 'lucide-react';
import type { TimelineEvent } from '@/types';

interface AttackTimelineProps {
  timeline: TimelineEvent[];
}

const tacticColors: Record<string, string> = {
  'Initial Access': 'from-critical to-high',
  'Execution': 'from-high to-medium',
  'Persistence': 'from-high to-medium',
  'Privilege Escalation': 'from-high to-critical',
  'Defense Evasion': 'from-medium to-high',
  'Credential Access': 'from-critical to-high',
  'Discovery': 'from-medium to-low',
  'Lateral Movement': 'from-high to-critical',
  'Collection': 'from-medium to-high',
  'Command and Control': 'from-high to-critical',
  'Exfiltration': 'from-critical to-critical',
  'Impact': 'from-critical to-critical',
};

export default function AttackTimeline({ timeline }: AttackTimelineProps) {
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set([0, 1, 2]));
  const [groupByHost, setGroupByHost] = useState(false);

  if (!timeline || timeline.length === 0) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-lg p-12 text-center">
        <Clock className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <p className="text-gray-400">No timeline data available</p>
      </div>
    );
  }

  const toggleEvent = (index: number) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedEvents(newExpanded);
  };

  const getTacticGradient = (tactic: string) => {
    for (const [key, gradient] of Object.entries(tacticColors)) {
      if (tactic.includes(key)) return gradient;
    }
    return 'from-info to-info';
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-dark-surface border-b border-dark-border p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Target className="w-6 h-6 text-critical" />
            <div>
              <h3 className="text-xl font-bold text-white">AI-Reconstructed Attack Timeline</h3>
              <p className="text-sm text-gray-400 mt-1">
                Chronological sequence of adversary actions based on {timeline.length} correlated events
              </p>
            </div>
          </div>
          <button
            onClick={() => setGroupByHost(!groupByHost)}
            className="px-4 py-2 bg-dark-card hover:bg-dark-hover border border-dark-border rounded-lg text-sm transition-colors"
          >
            {groupByHost ? 'Show All' : 'Group by Host'}
          </button>
        </div>
      </div>

      {/* Timeline */}
      <div className="p-6">
        <div className="relative">
          {/* Vertical Line */}
          <div className="absolute left-6 top-0 bottom-0 w-0.5 bg-gradient-to-b from-critical via-high to-medium" />

          {/* Events */}
          <div className="space-y-6">
            {timeline.map((event, index) => {
              const isExpanded = expandedEvents.has(index);
              const gradient = getTacticGradient(event.tactic || '');

              return (
                <div key={index} className="relative flex space-x-6">
                  {/* Timeline Dot */}
                  <div className="relative z-10 flex-shrink-0">
                    <div className={`w-12 h-12 rounded-full bg-gradient-to-br ${gradient} flex items-center justify-center border-4 border-dark-card shadow-lg`}>
                      <span className="text-white font-bold text-sm">{index + 1}</span>
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 pb-6">
                    <div className="bg-dark-surface border border-dark-border rounded-lg overflow-hidden hover:border-info/30 transition-all">
                      {/* Header - Always Visible */}
                      <div
                        className="p-4 cursor-pointer select-none"
                        onClick={() => toggleEvent(index)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <Clock className="w-4 h-4 text-gray-400" />
                            <span className="text-sm font-mono text-gray-400">
                              {new Date(event.timestamp).toLocaleString()}
                            </span>
                            <Server className="w-4 h-4 text-info ml-4" />
                            <span className="text-sm font-semibold text-info">{event.host}</span>
                          </div>
                          {isExpanded ? (
                            <ChevronUp className="w-5 h-5 text-gray-400" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-gray-400" />
                          )}
                        </div>

                        <div className="flex items-center space-x-3">
                          {event.tactic && (
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold bg-gradient-to-r ${gradient} text-white`}>
                              {event.tactic}
                            </span>
                          )}
                          <span className="text-sm font-mono text-medium font-semibold">
                            {event.technique}
                          </span>
                        </div>
                      </div>

                      {/* Expanded Content */}
                      {isExpanded && (
                        <div className="px-4 pb-4 border-t border-dark-border bg-dark-card/50">
                          <div className="mt-4">
                            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
                              Event Description
                            </h4>
                            <p className="text-sm text-gray-200 leading-relaxed">
                              {event.description}
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Summary Footer */}
        <div className="mt-8 pt-6 border-t border-dark-border">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-400">
              Total Events: <span className="text-white font-semibold">{timeline.length}</span>
            </span>
            <span className="text-gray-400">
              Unique Hosts: <span className="text-white font-semibold">
                {new Set(timeline.map(e => e.host)).size}
              </span>
            </span>
            <span className="text-gray-400">
              Duration: <span className="text-white font-semibold">
                {timeline.length > 1 ?
                  `${Math.round((new Date(timeline[timeline.length - 1].timestamp).getTime() -
                    new Date(timeline[0].timestamp).getTime()) / (1000 * 60))} minutes`
                  : 'N/A'}
              </span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
