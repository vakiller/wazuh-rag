import { useEffect, useState } from 'react';
import { Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';
import { reportsApi } from '@/lib/api';
import { TrendingUp } from 'lucide-react';

export default function RiskTrendChart() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const timeseriesData = await reportsApi.getTimeSeriesData(7);
      setData(timeseriesData);
    } catch (error) {
      console.error('Failed to load chart data:', error);
      // Mock data for demo
      setData([
        { date: '2024-01-01', avgRisk: 45, reports: 12 },
        { date: '2024-01-02', avgRisk: 62, reports: 18 },
        { date: '2024-01-03', avgRisk: 55, reports: 15 },
        { date: '2024-01-04', avgRisk: 78, reports: 22 },
        { date: '2024-01-05', avgRisk: 85, reports: 25 },
        { date: '2024-01-06', avgRisk: 70, reports: 20 },
        { date: '2024-01-07', avgRisk: 90, reports: 28 },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-dark-card border border-dark-border rounded-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-white mb-1">Risk Score Trends</h3>
          <p className="text-sm text-gray-400">7-day threat landscape overview</p>
        </div>
        <div className="flex items-center space-x-2 text-high">
          <TrendingUp className="w-5 h-5" />
          <span className="text-sm font-medium">Trending Up</span>
        </div>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-gray-500">
          Loading chart data...
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a3142" />
            <XAxis
              dataKey="date"
              stroke="#6b7280"
              tick={{ fill: '#9ca3af' }}
              tickFormatter={(value) => {
                const date = new Date(value);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
              }}
            />
            <YAxis
              stroke="#6b7280"
              tick={{ fill: '#9ca3af' }}
              domain={[0, 100]}
              label={{ value: 'Risk Score', angle: -90, position: 'insideLeft', fill: '#9ca3af' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1a1f2e',
                border: '1px solid #2a3142',
                borderRadius: '8px',
                color: '#fff',
              }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Area
              type="monotone"
              dataKey="avgRisk"
              stroke="#dc2626"
              strokeWidth={2}
              fill="url(#colorRisk)"
              name="Avg Risk Score"
            />
            <Line
              type="monotone"
              dataKey="reports"
              stroke="#0891b2"
              strokeWidth={2}
              dot={{ fill: '#0891b2', r: 4 }}
              name="Reports Count"
              yAxisId="right"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}

      <div className="mt-4 grid grid-cols-2 gap-4 pt-4 border-t border-dark-border">
        <div>
          <p className="text-sm text-gray-400 mb-1">Highest Risk Score</p>
          <p className="text-2xl font-bold text-critical">
            {Math.max(...data.map((d) => d.avgRisk || 0))}
          </p>
        </div>
        <div>
          <p className="text-sm text-gray-400 mb-1">Total Reports (7d)</p>
          <p className="text-2xl font-bold text-info">
            {data.reduce((sum, d) => sum + (d.reports || 0), 0)}
          </p>
        </div>
      </div>
    </div>
  );
}
