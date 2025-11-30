import { Shield, ExternalLink } from 'lucide-react';
import type { MitreTechnique } from '@/types';

interface MitrePanelProps {
  techniques: MitreTechnique[];
}

const tacticColors: Record<string, string> = {
  'Initial Access': 'bg-critical-light border-critical text-critical',
  'Execution': 'bg-high-light border-high text-high',
  'Persistence': 'bg-high-light border-high text-high',
  'Privilege Escalation': 'bg-critical-light border-critical text-critical',
  'Defense Evasion': 'bg-medium-light border-medium text-medium',
  'Credential Access': 'bg-critical-light border-critical text-critical',
  'Discovery': 'bg-low-light border-low text-low',
  'Lateral Movement': 'bg-critical-light border-critical text-critical',
  'Collection': 'bg-medium-light border-medium text-medium',
  'Command and Control': 'bg-high-light border-high text-high',
  'Exfiltration': 'bg-critical-light border-critical text-critical',
  'Impact': 'bg-critical-light border-critical text-critical',
};

export default function MitrePanel({ techniques }: MitrePanelProps) {
  if (!techniques || techniques.length === 0) {
    return (
      <div className="bg-white border border-neutral-300 p-6">
        <h3 className="text-lg font-medium text-neutral-900 mb-4">MITRE ATT&CK</h3>
        <p className="text-sm text-neutral-700 font-medium">No techniques identified</p>
      </div>
    );
  }

  // Group techniques by tactic
  const groupedByTactic: Record<string, MitreTechnique[]> = {};
  techniques.forEach(technique => {
    const tactics = technique.tactic.split(',').map(t => t.trim());
    tactics.forEach(tactic => {
      if (!groupedByTactic[tactic]) {
        groupedByTactic[tactic] = [];
      }
      if (!groupedByTactic[tactic].find(t => t.technique_id === technique.technique_id)) {
        groupedByTactic[tactic].push(technique);
      }
    });
  });

  const getTacticColor = (tactic: string) => {
    for (const [key, color] of Object.entries(tacticColors)) {
      if (tactic.includes(key)) return color;
    }
    return 'bg-info-light border-info text-info';
  };

  return (
    <div className="sticky top-6">
      <div className="bg-white border border-neutral-300 overflow-hidden">
        {/* Header */}
        <div className="bg-neutral-50 border-b border-neutral-300 p-4">
          <div className="flex items-center space-x-3">
            <Shield className="w-5 h-5 text-medium" />
            <div className="flex-1">
              <h3 className="text-lg font-medium text-neutral-900">MITRE ATT&CK</h3>
              <p className="text-xs text-neutral-700 font-medium mt-0.5">Mapped Techniques</p>
            </div>
            <a
              href="https://attack.mitre.org"
              target="_blank"
              rel="noopener noreferrer"
              className="text-info hover:text-info-dark transition-colors"
            >
              <ExternalLink className="w-4 h-4" />
            </a>
          </div>
        </div>

        {/* Tactics & Techniques */}
        <div className="p-4 space-y-6 max-h-[calc(100vh-200px)] overflow-y-auto scrollbar-hide">
          {Object.entries(groupedByTactic).map(([tactic, tacticTechniques]) => (
            <div key={tactic}>
              {/* Tactic Header */}
              <div className={`px-3 py-2 border ${getTacticColor(tactic)} mb-3`}>
                <h4 className="text-sm font-semibold">{tactic}</h4>
              </div>

              {/* Techniques */}
              <div className="space-y-2 ml-2">
                {tacticTechniques.map((technique) => (
                  <a
                    key={technique.technique_id}
                    href={`https://attack.mitre.org/techniques/${technique.technique_id.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block group"
                  >
                    <div className="bg-neutral-50 border border-neutral-300 p-3 hover:shadow-md transition-all">
                      <div className="flex items-start justify-between mb-1">
                        <span className="font-mono text-xs font-semibold text-medium group-hover:text-info transition-colors">
                          {technique.technique_id}
                        </span>
                        <ExternalLink className="w-3 h-3 text-neutral-500 group-hover:text-info transition-colors" />
                      </div>
                      <p className="text-sm text-neutral-900 group-hover:text-neutral-900 font-medium transition-colors leading-snug">
                        {technique.technique_name}
                      </p>
                    </div>
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer Stats */}
        <div className="bg-neutral-50 border-t border-neutral-300 p-4">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div>
              <div className="text-2xl font-light text-neutral-900">{techniques.length}</div>
              <div className="text-xs text-neutral-700 font-medium">Techniques</div>
            </div>
            <div>
              <div className="text-2xl font-light text-critical">{Object.keys(groupedByTactic).length}</div>
              <div className="text-xs text-neutral-700 font-medium">Tactics</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
