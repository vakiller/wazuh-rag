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
    info: 'text-info bg-info/10 border-info/20',
    critical: 'text-critical bg-critical/10 border-critical/20',
    high: 'text-high bg-high/10 border-high/20',
    medium: 'text-medium bg-medium/10 border-medium/20',
    low: 'text-low bg-low/10 border-low/20',
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg p-6 hover:border-dark-hover transition-all animate-slide-in">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-gray-400">{title}</h3>
        <div className={cn('p-2 rounded-lg border', colorClasses[color])}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="space-y-1">
        <p className="text-3xl font-bold text-white">{value}</p>
        {trend && <p className="text-xs text-gray-500">{trend}</p>}
      </div>
    </div>
  );
}
