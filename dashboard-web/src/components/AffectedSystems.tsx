import { Server, Shield } from 'lucide-react';

interface AffectedSystemsProps {
  hosts: string[];
  agents: string[];
}

export default function AffectedSystems({ hosts, agents }: AffectedSystemsProps) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-dark-surface border-b border-dark-border p-6">
        <div className="flex items-center space-x-3">
          <Server className="w-6 h-6 text-info" />
          <div>
            <h3 className="text-lg font-bold text-white">Affected Systems</h3>
            <p className="text-sm text-gray-400 mt-1">Compromised or impacted hosts and agents</p>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Hosts */}
        {hosts && hosts.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
              Hosts ({hosts.length})
            </h4>
            <div className="grid grid-cols-2 gap-3">
              {hosts.map((host, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-3 bg-dark-surface border border-dark-border rounded-lg p-3 hover:border-info/30 transition-all"
                >
                  <Server className="w-4 h-4 text-info flex-shrink-0" />
                  <span className="text-sm font-mono text-gray-200 truncate">{host}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Agents */}
        {agents && agents.length > 0 && (
          <div>
            <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wide mb-3">
              Agent IDs ({agents.length})
            </h4>
            <div className="flex flex-wrap gap-2">
              {agents.map((agent, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-2 bg-dark-surface border border-dark-border rounded-lg px-3 py-2 hover:border-info/30 transition-all"
                >
                  <Shield className="w-3 h-3 text-medium flex-shrink-0" />
                  <span className="text-sm font-mono text-gray-200">{agent}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Summary */}
        <div className="pt-4 border-t border-dark-border">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div className="bg-dark-surface rounded-lg p-4">
              <div className="text-3xl font-bold text-info">{hosts?.length || 0}</div>
              <div className="text-xs text-gray-400 mt-1">Total Hosts</div>
            </div>
            <div className="bg-dark-surface rounded-lg p-4">
              <div className="text-3xl font-bold text-medium">{agents?.length || 0}</div>
              <div className="text-xs text-gray-400 mt-1">Total Agents</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
