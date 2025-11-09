import { Shield, ExternalLink } from 'lucide-react';
import type { MitreTechnique } from '@/types';

interface MitrePanelProps {
  techniques: MitreTechnique[];
}

const tacticColors: Record<string, string> = {
  'Initial Access': 'bg-critical/10 border-critical/30 text-critical',
  'Execution': 'bg-high/10 border-high/30 text-high',
  'Persistence': 'bg-high/10 border-high/30 text-high',
  'Privilege Escalation': 'bg-critical/10 border-critical/30 text-critical',
  'Defense Evasion': 'bg-medium/10 border-medium/30 text-medium',
  'Credential Access': 'bg-critical/10 border-critical/30 text-critical',
  'Discovery': 'bg-low/10 border-low/30 text-low',
  'Lateral Movement': 'bg-critical/10 border-critical/30 text-critical',
  'Collection': 'bg-medium/10 border-medium/30 text-medium',
  'Command and Control': 'bg-high/10 border-high/30 text-high',
  'Exfiltration': 'bg-critical/10 border-critical/30 text-critical',
  'Impact': 'bg-critical/10 border-critical/30 text-critical',
};

export default function MitrePanel({ techniques }: MitrePanelProps) {
  if (!techniques || techniques.length === 0) {
    return (
      <div className="bg-dark-card border border-dark-border rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">MITRE ATT&CK</h3>
        <p className="text-sm text-gray-400">No techniques identified</p>
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
    return 'bg-info/10 border-info/30 text-info';
  };

  return (
    <div className="sticky top-6">
      <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
        {/* Header */}
        <div className="bg-dark-surface border-b border-dark-border p-4">
          <div className="flex items-center space-x-3">
            <Shield className="w-5 h-5 text-medium" />
            <div className="flex-1">
              <h3 className="text-lg font-bold text-white">MITRE ATT&CK</h3>
              <p className="text-xs text-gray-400 mt-0.5">Mapped Techniques</p>
            </div>
            <a
              href="https://attack.mitre.org"
              target="_blank"
              rel="noopener noreferrer"
              className="text-info hover:text-info-light transition-colors"
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
              <div className={`px-3 py-2 rounded-lg border ${getTacticColor(tactic)} mb-3`}>
                <h4 className="text-sm font-bold">{tactic}</h4>
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
                    <div className="bg-dark-surface border border-dark-border rounded-lg p-3 hover:border-info/40 hover:bg-dark-hover transition-all">
                      <div className="flex items-start justify-between mb-1">
                        <span className="font-mono text-xs font-semibold text-medium group-hover:text-info transition-colors">
                          {technique.technique_id}
                        </span>
                        <ExternalLink className="w-3 h-3 text-gray-500 group-hover:text-info transition-colors" />
                      </div>
                      <p className="text-sm text-gray-300 group-hover:text-white transition-colors leading-snug">
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
        <div className="bg-dark-surface border-t border-dark-border p-4">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div>
              <div className="text-2xl font-bold text-white">{techniques.length}</div>
              <div className="text-xs text-gray-400">Techniques</div>
            </div>
            <div>
              <div className="text-2xl font-bold text-critical">{Object.keys(groupedByTactic).length}</div>
              <div className="text-xs text-gray-400">Tactics</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
