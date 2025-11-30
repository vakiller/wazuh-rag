import { Server, Shield } from 'lucide-react';

interface AffectedSystemsProps {
  hosts: string[];
  agents: string[];
}

export default function AffectedSystems({ hosts, agents }: AffectedSystemsProps) {
  return (
    <div className="bg-white border border-neutral-300 overflow-hidden">
      {/* Header */}
      <div className="bg-neutral-50 border-b border-neutral-300 p-6">
        <div className="flex items-center space-x-3">
          <Server className="w-6 h-6 text-info" />
          <div>
            <h3 className="text-lg font-medium text-neutral-900">Affected Systems</h3>
            <p className="text-sm text-neutral-700 font-medium mt-1">Compromised or impacted hosts and agents</p>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Hosts */}
        {hosts && hosts.length > 0 && (
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider text-neutral-700 mb-3">
              Hosts ({hosts.length})
            </h4>
            <div className="grid grid-cols-2 gap-3">
              {hosts.map((host, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-3 bg-neutral-50 border border-neutral-300 p-3 hover:shadow-md transition-all"
                >
                  <Server className="w-4 h-4 text-info flex-shrink-0" />
                  <span className="text-sm font-mono text-neutral-900 truncate font-medium">{host}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Agents */}
        {agents && agents.length > 0 && (
          <div>
            <h4 className="text-xs font-medium uppercase tracking-wider text-neutral-700 mb-3">
              Agent IDs ({agents.length})
            </h4>
            <div className="flex flex-wrap gap-2">
              {agents.map((agent, index) => (
                <div
                  key={index}
                  className="flex items-center space-x-2 bg-neutral-50 border border-neutral-300 px-3 py-2 hover:shadow-md transition-all"
                >
                  <Shield className="w-3 h-3 text-medium flex-shrink-0" />
                  <span className="text-sm font-mono text-neutral-900 font-medium">{agent}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Summary */}
        <div className="pt-4 border-t border-neutral-300">
          <div className="grid grid-cols-2 gap-4 text-center">
            <div className="bg-neutral-50 border border-neutral-300 p-4">
              <div className="text-3xl font-light text-info">{hosts?.length || 0}</div>
              <div className="text-xs text-neutral-700 font-medium mt-1">Total Hosts</div>
            </div>
            <div className="bg-neutral-50 border border-neutral-300 p-4">
              <div className="text-3xl font-light text-medium">{agents?.length || 0}</div>
              <div className="text-xs text-neutral-700 font-medium mt-1">Total Agents</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
