import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, Settings, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

interface LayoutProps {
  children: React.ReactNode;
}

export default function Layout({ children }: LayoutProps) {
  const location = useLocation();

  const navItems = [
    { path: '/', icon: Home, label: 'Dashboard' },
    { path: '/settings', icon: Settings, label: 'Settings' },
  ];

  return (
    <div className="min-h-screen bg-dark-bg flex">
      {/* Sidebar */}
      <aside className="w-64 bg-dark-surface border-r border-dark-border flex flex-col">
        {/* Logo */}
        <div className="p-6 border-b border-dark-border">
          <Link to="/" className="flex items-center space-x-3 group">
            <div className="relative">
              <Shield className="w-8 h-8 text-info transition-transform group-hover:scale-110" />
              <Activity className="w-4 h-4 text-critical absolute -bottom-1 -right-1 animate-pulse" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">RAG Wazuh</h1>
              <p className="text-xs text-gray-400">AI Threat Analysis</p>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'flex items-center space-x-3 px-4 py-3 rounded-lg transition-all',
                  isActive
                    ? 'bg-info/10 text-info border border-info/20'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-dark-hover'
                )}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-dark-border">
          <div className="text-xs text-gray-500 space-y-1">
            <div className="flex justify-between">
              <span>Version</span>
              <span className="text-gray-400">1.0.0</span>
            </div>
            <div className="flex justify-between">
              <span>Status</span>
              <span className="flex items-center text-low">
                <span className="w-2 h-2 bg-low rounded-full mr-2 animate-pulse"></span>
                Online
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}
