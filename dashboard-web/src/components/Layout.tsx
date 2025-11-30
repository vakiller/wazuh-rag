import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, Settings } from 'lucide-react';
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
    <div className="min-h-screen bg-neutral-50 flex">
      {/* Minimal Sidebar */}
      <aside className="w-64 bg-white border-r border-neutral-300 flex flex-col">
        {/* Logo Section */}
        <div className="p-8 border-b border-neutral-300">
          <Link to="/" className="flex items-center space-x-3 group">
            <div className="w-10 h-10 bg-neutral-900 flex items-center justify-center transition-all duration-200 group-hover:bg-neutral-800">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-medium text-neutral-900 tracking-tight">
                Wazuh
              </h1>
              <p className="text-xs text-neutral-700 tracking-wide font-medium">
                Threat Analysis
              </p>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-6 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'flex items-center space-x-3 px-4 py-3 transition-colors duration-150',
                  isActive
                    ? 'bg-neutral-900 text-white'
                    : 'text-neutral-700 hover:bg-neutral-100'
                )}
              >
                <Icon className="w-5 h-5" />
                <span className="text-sm font-medium">{item.label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Footer - System Status */}
        <div className="p-6 border-t border-neutral-300 bg-neutral-50">
          <div className="space-y-2 text-xs text-neutral-900 font-medium">
            <div className="flex items-center justify-between">
              <span>Status</span>
              <span className="flex items-center space-x-1">
                <span className="w-1.5 h-1.5 bg-low rounded-full"></span>
                <span>Online</span>
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span>Version</span>
              <span className="font-mono">1.0.0</span>
            </div>
            <div className="flex items-center justify-between">
              <span>Model</span>
              <span className="font-mono">Qwen3-8b</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-neutral-50">
        {children}
      </main>
    </div>
  );
}
