import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import type { DashboardStats } from '@/types';

interface SeverityDistributionProps {
  stats: DashboardStats | null;
}

export default function SeverityDistribution({ stats }: SeverityDistributionProps) {
  if (!stats) return null;

  const data = [
    { name: 'Critical', value: stats.critical_count, color: '#dc2626' },
    { name: 'High', value: stats.high_count, color: '#ea580c' },
    { name: 'Medium', value: stats.medium_count, color: '#ca8a04' },
    { name: 'Low', value: stats.low_count, color: '#16a34a' },
  ].filter((item) => item.value > 0);

  const total = data.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg p-6">
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-1">Severity Distribution</h3>
        <p className="text-sm text-gray-400">Threat categorization breakdown</p>
      </div>

      {data.length > 0 ? (
        <>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1a1f2e',
                  border: '1px solid #2a3142',
                  borderRadius: '8px',
                  color: '#fff',
                }}
              />
            </PieChart>
          </ResponsiveContainer>

          <div className="mt-6 space-y-3">
            {data.map((item) => (
              <div key={item.name} className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-sm text-gray-300">{item.name}</span>
                </div>
                <div className="flex items-center space-x-3">
                  <span className="text-sm font-semibold text-white">{item.value}</span>
                  <span className="text-xs text-gray-500">
                    {((item.value / total) * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <div className="h-64 flex items-center justify-center text-gray-500">
          No severity data available
        </div>
      )}
    </div>
  );
}
