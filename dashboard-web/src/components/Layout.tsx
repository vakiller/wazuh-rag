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
    <div className="min-h-screen bg-command-void flex">
      {/* Sidebar with hexagon pattern background */}
      <aside className="w-72 bg-command-deep border-r-2 border-info/20 flex flex-col relative overflow-hidden">
        {/* Hexagon pattern background */}
        <div className="absolute inset-0 bg-hex-pattern opacity-10 pointer-events-none"></div>

        {/* Logo Section */}
        <div className="p-6 border-b border-command-border relative z-10">
          <Link to="/" className="flex items-center space-x-4 group">
            {/* Hexagonal logo with neon glow */}
            <div className="relative w-14 h-14">
              <div className="absolute inset-0 hexagon bg-gradient-to-br from-info/20 to-neon-magenta/20 animate-glow-pulse"></div>
              <div className="absolute inset-1 hexagon bg-command-surface flex items-center justify-center">
                <Shield className="w-7 h-7 text-info" />
              </div>
              <Activity className="w-4 h-4 text-critical absolute bottom-0 right-0 animate-pulse" />
            </div>
            <div>
              <h1 className="text-2xl font-bold terminal-text text-white tracking-wider">
                RAG<span className="text-info">_</span>WAZUH
              </h1>
              <p className="text-xs text-gray-400 font-mono uppercase tracking-widest">
                Threat Analysis
              </p>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2 relative z-10">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                className={cn(
                  'flex items-center space-x-3 px-4 py-3.5 rounded transition-all relative overflow-hidden group',
                  isActive
                    ? 'bg-info/10 text-info border border-info/30 neon-glow-cyan'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-command-hover border border-transparent'
                )}
              >
                {isActive && (
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-info animate-glow-pulse"></div>
                )}
                <Icon className="w-5 h-5 relative z-10" />
                <span className="font-medium font-mono uppercase text-sm tracking-wide relative z-10">
                  {item.label}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Footer - System Status */}
        <div className="p-4 border-t border-command-border bg-command-surface/50 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-gray-500 uppercase">System</span>
              <span className="text-low flex items-center space-x-2">
                <span className="w-2 h-2 bg-low rounded-full animate-pulse neon-glow-low"></span>
                <span>ONLINE</span>
              </span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-gray-500 uppercase">Ver</span>
              <span className="text-info">1.0.0</span>
            </div>
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-gray-500 uppercase">Model</span>
              <span className="text-neon-magenta">DeepSeek-R1</span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto command-grid">
        {children}
      </main>
    </div>
  );
}
