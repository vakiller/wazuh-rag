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
    <div className="bg-white border border-neutral-300 overflow-hidden">
      {/* Header */}
      <div className="bg-neutral-50 border-b border-neutral-300 p-6">
        <div className="flex items-center space-x-3">
          <Eye className="w-6 h-6 text-info" />
          <div>
            <h3 className="text-xl font-medium text-neutral-900">Indicators of Compromise</h3>
            <p className="text-sm text-neutral-700 font-medium mt-1">Extracted IOCs from analyzed alerts</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-neutral-50 border-b border-neutral-300 px-6 pt-4">
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
                className={`flex items-center space-x-2 px-4 py-3 border-b-2 transition-all whitespace-nowrap ${
                  isActive
                    ? 'bg-white border-info text-info'
                    : 'bg-transparent border-transparent text-neutral-700 hover:text-neutral-900 hover:bg-neutral-100'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="text-sm font-medium">{config.label}</span>
                <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                  isActive ? 'bg-info-light text-info border border-info' : 'bg-neutral-200 text-neutral-700'
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
                className="group flex items-center justify-between bg-neutral-50 border border-neutral-300 p-4 hover:shadow-md transition-all"
              >
                <div className="flex items-center space-x-3 flex-1 min-w-0">
                  <ActiveIcon className={`w-4 h-4 flex-shrink-0 ${tabConfig[activeTab].color}`} />
                  <span className="text-sm font-mono text-neutral-900 font-medium truncate">{item}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(item)}
                  className="flex-shrink-0 ml-4 p-2 hover:bg-neutral-100 transition-colors opacity-0 group-hover:opacity-100"
                  title="Copy to clipboard"
                >
                  {copiedItem === item ? (
                    <Check className="w-4 h-4 text-low" />
                  ) : (
                    <Copy className="w-4 h-4 text-neutral-700" />
                  )}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <ActiveIcon className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
            <p className="text-neutral-700 font-medium">No {tabConfig[activeTab].label.toLowerCase()} identified</p>
          </div>
        )}
      </div>

      {/* Footer */}
      {activeData.length > 0 && (
        <div className="bg-neutral-50 border-t border-neutral-300 px-6 py-4">
          <div className="flex items-center justify-between text-sm">
            <span className="text-neutral-700 font-medium">
              Total {tabConfig[activeTab].label}: <span className="text-neutral-900 font-semibold">{activeData.length}</span>
            </span>
            <button
              onClick={() => {
                const allItems = activeData.join('\n');
                copyToClipboard(allItems);
              }}
              className="text-info hover:text-info-dark transition-colors text-sm font-medium"
            >
              Copy All
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
