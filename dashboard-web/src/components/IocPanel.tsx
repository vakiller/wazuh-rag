import { useState } from 'react';
import { Eye, Globe, User, Cpu, FileText, Copy, Check } from 'lucide-react';
import type { IOCs } from '@/types';

interface IocPanelProps {
  iocs: IOCs;
}

type IocTab = 'ips' | 'domains' | 'users' | 'processes' | 'files';

const tabConfig: Record<IocTab, { label: string; icon: typeof Globe; color: string }> = {
  ips: { label: 'IP Addresses', icon: Globe, color: 'text-critical' },
  domains: { label: 'Domains', icon: Globe, color: 'text-high' },
  users: { label: 'Users', icon: User, color: 'text-medium' },
  processes: { label: 'Processes', icon: Cpu, color: 'text-info' },
  files: { label: 'File Paths', icon: FileText, color: 'text-low' },
};

export default function IocPanel({ iocs }: IocPanelProps) {
  const [activeTab, setActiveTab] = useState<IocTab>('ips');
  const [copiedItem, setCopiedItem] = useState<string | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedItem(text);
    setTimeout(() => setCopiedItem(null), 2000);
  };

  const getIocData = (tab: IocTab): string[] => {
    const data = iocs[tab === 'files' ? 'file_paths' : tab] || [];
    return data.filter(item => item && item.trim().length > 0);
  };

  const activeData = getIocData(activeTab);
  const ActiveIcon = tabConfig[activeTab].icon;

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
      {/* Header */}
      <div className="bg-dark-surface border-b border-dark-border p-6">
        <div className="flex items-center space-x-3">
          <Eye className="w-6 h-6 text-info" />
          <div>
            <h3 className="text-xl font-bold text-white">Indicators of Compromise</h3>
            <p className="text-sm text-gray-400 mt-1">Extracted IOCs from analyzed alerts</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-dark-surface border-b border-dark-border px-6 pt-4">
        <div className="flex space-x-2 overflow-x-auto scrollbar-hide">
          {(Object.keys(tabConfig) as IocTab[]).map((tab) => {
            const config = tabConfig[tab];
            const Icon = config.icon;
            const count = getIocData(tab).length;
            const isActive = activeTab === tab;

            return (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`flex items-center space-x-2 px-4 py-3 rounded-t-lg border-b-2 transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-dark-card border-info text-info'
                    : 'bg-transparent border-transparent text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="text-sm font-medium">{config.label}</span>
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                  isActive ? 'bg-info/20 text-info' : 'bg-dark-border text-gray-500'
                }`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {activeData.length > 0 ? (
          <div className="space-y-2">
            {activeData.map((item, index) => (
              <div
                key={index}
                className="group flex items-center justify-between bg-dark-surface border border-dark-border rounded-lg p-4 hover:border-info/30 transition-all"
              >
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <ActiveIcon className={`w-4 h-4 flex-shrink-0 ${tabConfig[activeTab].color}`} />
                  <span className="text-sm font-mono text-gray-200 truncate">{item}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(item)}
                  className="flex-shrink-0 ml-4 p-2 rounded-lg hover:bg-dark-hover transition-colors opacity-0 group-hover:opacity-100"
                  title="Copy to clipboard"
                >
                  {copiedItem === item ? (
                    <Check className="w-4 h-4 text-low" />
                  ) : (
                    <Copy className="w-4 h-4 text-gray-400" />
                  )}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <ActiveIcon className="w-16 h-16 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-400">No {tabConfig[activeTab].label.toLowerCase()} identified</p>
          </div>
        )}
      </div>

      {/* Footer */}
      {activeData.length > 0 && (
        <div className="bg-dark-surface border-t border-dark-border px-6 py-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-400">
              Total {tabConfig[activeTab].label}: <span className="text-white font-semibold">{activeData.length}</span>
            </span>
            <button
              onClick={() => {
                const allItems = activeData.join('\n');
                copyToClipboard(allItems);
              }}
              className="text-info hover:text-info-light transition-colors text-sm font-medium"
            >
              Copy All
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
