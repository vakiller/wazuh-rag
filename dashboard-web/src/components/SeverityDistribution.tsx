import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { Shield } from 'lucide-react';
import { reportsApi } from '@/lib/api';
import type { ThreatReport } from '@/types';

export default function TacticDistribution() {
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

      // Extract all tactics from MITRE techniques across all reports
      const tacticCounts: Record<string, number> = {};

      reports.forEach(report => {
        if (report.mitre_list && Array.isArray(report.mitre_list)) {
          report.mitre_list.forEach(technique => {
            if (technique.tactic) {
              // Split comma-separated tactics
              const tactics = technique.tactic.split(',').map(t => t.trim());
              tactics.forEach(tactic => {
                if (tactic) {
                  tacticCounts[tactic] = (tacticCounts[tactic] || 0) + 1;
                }
              });
            }
          });
        }
      });

      // Convert to array and sort by count
      const tacticData = Object.entries(tacticCounts)
        .map(([name, count]) => ({
          name,
          count,
          color: getTacticColor(name),
        }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10); // Top 10 tactics

      setData(tacticData);
    } catch (error) {
      console.error('Failed to load tactics data:', error);
      setData([]);
    } finally {
      setLoading(false);
    }
  };

  const getTacticColor = (tactic: string): string => {
    const colorMap: Record<string, string> = {
      'Initial Access': '#dc2626',
      'Execution': '#ea580c',
      'Persistence': '#f59e0b',
      'Privilege Escalation': '#dc2626',
      'Defense Evasion': '#ca8a04',
      'Credential Access': '#dc2626',
      'Discovery': '#16a34a',
      'Lateral Movement': '#ea580c',
      'Collection': '#ca8a04',
      'Command and Control': '#ea580c',
      'Exfiltration': '#dc2626',
      'Impact': '#dc2626',
    };

    // Check if tactic contains any of the known tactics
    for (const [key, color] of Object.entries(colorMap)) {
      if (tactic.includes(key)) {
        return color;
      }
    }

    return '#0891b2'; // Default info color
  };

  const totalTactics = data.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="bg-white border border-neutral-300 p-6">
      <div className="mb-6">
        <div className="flex items-center space-x-3 mb-1">
          <Shield className="w-5 h-5 text-medium" />
          <h3 className="text-lg font-medium text-neutral-900">MITRE ATT&CK Tactics</h3>
        </div>
        <p className="text-sm text-neutral-700 font-medium">Top attack tactics observed</p>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-neutral-700 font-medium">
          Loading tactics data...
        </div>
      ) : data.length === 0 ? (
        <div className="h-64 flex items-center justify-center">
          <div className="text-center">
            <Shield className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
            <p className="text-neutral-700 font-medium">No MITRE tactics data available</p>
            <p className="text-sm text-neutral-600 mt-2">Tactics will appear once reports are analyzed</p>
          </div>
        </div>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={data.slice(0, 8)} layout="horizontal">
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e5e5" />
              <XAxis
                type="number"
                stroke="#737373"
                tick={{ fill: '#404040', fontSize: 11 }}
              />
              <YAxis
                type="category"
                dataKey="name"
                width={120}
                stroke="#737373"
                tick={{ fill: '#404040', fontSize: 11 }}
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
                cursor={{ fill: '#f5f5f5' }}
              />
              <Bar dataKey="count" name="Occurrences" radius={[0, 4, 4, 0]}>
                {data.slice(0, 8).map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>

          <div className="mt-6 max-h-32 overflow-y-auto scrollbar-thin scrollbar-thumb-neutral-300 scrollbar-track-neutral-100">
            <div className="space-y-2 pr-2">
              {data.map((item) => (
                <div key={item.name} className="flex items-center justify-between py-2 border-b border-neutral-200 last:border-0">
                  <div className="flex items-center space-x-3">
                    <div className="w-3 h-3 flex-shrink-0" style={{ backgroundColor: item.color }} />
                    <span className="text-sm text-neutral-900 font-medium">{item.name}</span>
                  </div>
                  <div className="flex items-center space-x-3 flex-shrink-0">
                    <span className="text-sm font-semibold text-neutral-900">{item.count}</span>
                    <span className="text-xs text-neutral-700 font-medium w-12 text-right">
                      {totalTactics > 0 ? ((item.count / totalTactics) * 100).toFixed(0) : 0}%
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {data.length > 0 && (
            <div className="mt-4 pt-4 border-t border-neutral-300 text-center">
              <p className="text-xs text-neutral-600">
                {data.length} tactics • {totalTactics} total occurrences
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
