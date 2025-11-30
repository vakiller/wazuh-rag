import { useEffect, useState } from 'react';
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart, Legend } from 'recharts';
import { reportsApi } from '@/lib/api';
import { Activity } from 'lucide-react';
import type { ThreatReport } from '@/types';

export default function RiskTrendChart() {
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const reports: ThreatReport[] = await reportsApi.getAll({ limit: 10000, offset: 0 });

      if (!reports || reports.length === 0) {
        setData([]);
        setLoading(false);
        return;
      }

      // Get all unique dates from reports and sort them
      const allDates = reports.map(r => new Date(r.created_at).toISOString().split('T')[0]);
      const uniqueDates = Array.from(new Set(allDates)).sort();

      // If we have reports, use their date range, otherwise use last 7 days
      let dateRange: string[];
      if (uniqueDates.length > 0) {
        // Get the oldest and newest dates
        const oldestDate = new Date(uniqueDates[0]);
        const newestDate = new Date(uniqueDates[uniqueDates.length - 1]);

        // Create date range (limit to last 30 days max to avoid too many data points)
        const daysDiff = Math.min(30, Math.ceil((newestDate.getTime() - oldestDate.getTime()) / (1000 * 60 * 60 * 24)) + 1);

        dateRange = Array.from({ length: daysDiff }, (_, i) => {
          const date = new Date(oldestDate);
          date.setDate(date.getDate() + i);
          return date.toISOString().split('T')[0];
        });
      } else {
        // Fallback to last 7 days
        dateRange = Array.from({ length: 7 }, (_, i) => {
          const date = new Date();
          date.setDate(date.getDate() - (6 - i));
          return date.toISOString().split('T')[0];
        });
      }

      const groupedData = dateRange.map(dateStr => {
        const reportsOnDate = reports.filter(r => {
          const reportDate = new Date(r.created_at).toISOString().split('T')[0];
          return reportDate === dateStr;
        });

        const severityCounts = {
          critical: reportsOnDate.filter(r => r.severity?.toLowerCase() === 'critical').length,
          high: reportsOnDate.filter(r => r.severity?.toLowerCase() === 'high').length,
          medium: reportsOnDate.filter(r => r.severity?.toLowerCase() === 'medium').length,
          low: reportsOnDate.filter(r => r.severity?.toLowerCase() === 'low').length,
        };

        return {
          date: dateStr,
          critical: severityCounts.critical,
          high: severityCounts.high,
          medium: severityCounts.medium,
          low: severityCounts.low,
          total: reportsOnDate.length,
        };
      });

      // Only keep dates with at least one report to avoid empty chart
      const filteredData = groupedData.filter(d => d.total > 0);

      // If no data after filtering, keep all dates to show the timeline
      setData(filteredData.length > 0 ? filteredData : groupedData);
    } catch (error) {
      console.error('Failed to load reports for chart:', error);
      setData([]);
    } finally {
      setLoading(false);
    }
  };

  const getTotalBySeverity = (severity: string) => {
    return data.reduce((sum, d) => sum + (d[severity] || 0), 0);
  };

  const grandTotal = data.reduce((sum, d) => sum + (d.total || 0), 0);

  return (
    <div className="bg-white border border-neutral-300 p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-medium text-neutral-900 mb-1">Threat Activity Trends</h3>
          <p className="text-sm text-neutral-700 font-medium">
            {data.length > 0 ? `${data.length} day${data.length > 1 ? 's' : ''} of data` : 'No data available'}
          </p>
        </div>
        <div className="flex items-center space-x-2 text-info">
          <Activity className="w-5 h-5" />
          <span className="text-sm font-medium">{grandTotal} Total Reports</span>
        </div>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-neutral-700 font-medium">
          Loading chart data...
        </div>
      ) : data.length === 0 || grandTotal === 0 ? (
        <div className="h-64 flex items-center justify-center">
          <div className="text-center">
            <Activity className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
            <p className="text-neutral-700 font-medium">No threat reports available</p>
            <p className="text-sm text-neutral-600 mt-2">Reports will appear here once generated</p>
          </div>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#dc2626" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ea580c" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ea580c" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ca8a04" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#ca8a04" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#16a34a" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#16a34a" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e5e5" />
            <XAxis
              dataKey="date"
              stroke="#737373"
              tick={{ fill: '#404040', fontSize: 12 }}
              tickFormatter={(value) => {
                const date = new Date(value);
                return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
              }}
            />
            <YAxis
              stroke="#737373"
              tick={{ fill: '#404040', fontSize: 12 }}
              label={{ value: 'Reports Count', angle: -90, position: 'insideLeft', fill: '#404040', fontSize: 12 }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#ffffff',
                border: '1px solid #d4d4d4',
                borderRadius: '4px',
                color: '#171717',
                fontSize: '12px',
              }}
              labelStyle={{ color: '#404040', fontWeight: 500 }}
            />
            <Legend
              wrapperStyle={{ fontSize: '12px', paddingTop: '10px' }}
              iconType="square"
            />
            <Area
              type="monotone"
              dataKey="critical"
              stackId="1"
              stroke="#dc2626"
              strokeWidth={2}
              fill="url(#colorCritical)"
              name="Critical"
            />
            <Area
              type="monotone"
              dataKey="high"
              stackId="1"
              stroke="#ea580c"
              strokeWidth={2}
              fill="url(#colorHigh)"
              name="High"
            />
            <Area
              type="monotone"
              dataKey="medium"
              stackId="1"
              stroke="#ca8a04"
              strokeWidth={2}
              fill="url(#colorMedium)"
              name="Medium"
            />
            <Area
              type="monotone"
              dataKey="low"
              stackId="1"
              stroke="#16a34a"
              strokeWidth={2}
              fill="url(#colorLow)"
              name="Low"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}

      <div className="mt-4 grid grid-cols-4 gap-4 pt-4 border-t border-neutral-300">
        <div>
          <p className="text-xs text-neutral-700 font-medium mb-1">Critical</p>
          <p className="text-xl font-light text-critical">
            {getTotalBySeverity('critical')}
          </p>
        </div>
        <div>
          <p className="text-xs text-neutral-700 font-medium mb-1">High</p>
          <p className="text-xl font-light text-high">
            {getTotalBySeverity('high')}
          </p>
        </div>
        <div>
          <p className="text-xs text-neutral-700 font-medium mb-1">Medium</p>
          <p className="text-xl font-light text-medium">
            {getTotalBySeverity('medium')}
          </p>
        </div>
        <div>
          <p className="text-xs text-neutral-700 font-medium mb-1">Low</p>
          <p className="text-xl font-light text-low">
            {getTotalBySeverity('low')}
          </p>
        </div>
      </div>
    </div>
  );
}
