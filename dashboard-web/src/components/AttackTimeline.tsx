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
      <div className="bg-white border border-neutral-300 p-12 text-center">
        <Clock className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
        <p className="text-neutral-700 font-medium">No timeline data available</p>
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
    <div className="bg-white border border-neutral-300 overflow-hidden">
      {/* Header */}
      <div className="bg-neutral-50 border-b border-neutral-300 p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Target className="w-6 h-6 text-critical" />
            <div>
              <h3 className="text-xl font-medium text-neutral-900">AI-Reconstructed Attack Timeline</h3>
              <p className="text-sm text-neutral-700 font-medium mt-1">
                Chronological sequence of adversary actions based on {timeline.length} correlated events
              </p>
            </div>
          </div>
          <button
            onClick={() => setGroupByHost(!groupByHost)}
            className="btn-minimal text-sm"
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
                    <div className={`w-12 h-12 rounded-full bg-gradient-to-br ${gradient} flex items-center justify-center border-4 border-white shadow-md`}>
                      <span className="text-white font-semibold text-sm">{index + 1}</span>
                    </div>
                  </div>

                  {/* Content */}
                  <div className="flex-1 pb-6">
                    <div className="bg-neutral-50 border border-neutral-300 overflow-hidden hover:shadow-md transition-all">
                      {/* Header - Always Visible */}
                      <div
                        className="p-4 cursor-pointer select-none"
                        onClick={() => toggleEvent(index)}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-3">
                            <Clock className="w-4 h-4 text-neutral-700" />
                            <span className="text-sm font-mono text-neutral-900 font-medium">
                              {new Date(event.timestamp).toLocaleString()}
                            </span>
                            <Server className="w-4 h-4 text-info ml-4" />
                            <span className="text-sm font-semibold text-info">{event.host}</span>
                          </div>
                          {isExpanded ? (
                            <ChevronUp className="w-5 h-5 text-neutral-700" />
                          ) : (
                            <ChevronDown className="w-5 h-5 text-neutral-700" />
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
                        <div className="px-4 pb-4 border-t border-neutral-300 bg-white">
                          <div className="mt-4">
                            <h4 className="text-xs font-medium uppercase tracking-wider text-neutral-700 mb-2">
                              Event Description
                            </h4>
                            <p className="text-sm text-neutral-900 leading-relaxed font-medium">
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
        <div className="mt-8 pt-6 border-t border-neutral-300">
          <div className="flex items-center justify-between text-sm">
            <span className="text-neutral-700 font-medium">
              Total Events: <span className="text-neutral-900 font-semibold">{timeline.length}</span>
            </span>
            <span className="text-neutral-700 font-medium">
              Unique Hosts: <span className="text-neutral-900 font-semibold">
                {new Set(timeline.map(e => e.host)).size}
              </span>
            </span>
            <span className="text-neutral-700 font-medium">
              Duration: <span className="text-neutral-900 font-semibold">
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
