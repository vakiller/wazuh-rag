import { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatsCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  color?: 'info' | 'critical' | 'high' | 'medium' | 'low';
}

export default function StatsCard({ title, value, icon: Icon, trend, color = 'info' }: StatsCardProps) {
  const colorClasses = {
    info: 'text-info border-info/30 neon-glow-cyan',
    critical: 'text-critical border-critical/30 neon-glow-critical',
    high: 'text-high border-high/30 neon-glow-high',
    medium: 'text-medium border-medium/30 neon-glow-medium',
    low: 'text-low border-low/30 neon-glow-low',
  };

  const bgClasses = {
    info: 'bg-info',
    critical: 'bg-critical',
    high: 'bg-high',
    medium: 'bg-medium',
    low: 'bg-low',
  };

  return (
    <div className="stat-card p-6 rounded-lg animate-fade-in-up hover:scale-105 transition-all duration-300">
      <div className="flex items-start justify-between relative z-10">
        <div className="flex-1">
          <p className="text-gray-400 text-xs font-mono uppercase tracking-wider mb-2">
            {title}
          </p>
          <p className={cn(
            'text-4xl font-bold terminal-text mb-2',
            colorClasses[color]
          )}>
            {value}
          </p>
          {trend && (
            <p className="text-gray-500 text-xs font-mono">
              {trend}
            </p>
          )}
        </div>
        <div className={cn(
          'p-4 rounded-lg border-2 backdrop-blur-sm',
          colorClasses[color],
          `bg-${color}-bg`
        )}>
          <Icon className="w-8 h-8" />
        </div>
      </div>
      {/* Animated scan line effect */}
      <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-info/50 to-transparent animate-scan-line opacity-50"></div>
    </div>
  );
}
