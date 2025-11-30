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
    info: 'text-info',
    critical: 'text-critical',
    high: 'text-high',
    medium: 'text-medium',
    low: 'text-low',
  };

  const bgClasses = {
    info: 'bg-info-light',
    critical: 'bg-critical-light',
    high: 'bg-high-light',
    medium: 'bg-medium-light',
    low: 'bg-low-light',
  };

  return (
    <div className="bg-white border border-neutral-300 p-6 transition-shadow duration-200 hover:shadow-md animate-fade-in">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs font-medium uppercase tracking-wider text-neutral-700 mb-2">
            {title}
          </p>
          <p className={cn(
            'text-4xl font-light tracking-tight mb-1',
            colorClasses[color]
          )}>
            {value}
          </p>
          {trend && (
            <p className="text-sm text-neutral-700 font-medium">
              {trend}
            </p>
          )}
        </div>
        <div className={cn(
          'p-3 transition-colors duration-200',
          bgClasses[color]
        )}>
          <Icon className={cn("w-6 h-6", colorClasses[color])} />
        </div>
      </div>
    </div>
  );
}
