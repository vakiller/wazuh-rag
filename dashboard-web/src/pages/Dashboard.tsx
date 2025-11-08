import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  TrendingUp,
  Shield,
  Clock,
  ArrowRight,
  RefreshCw,
  Filter,
} from 'lucide-react';
import { reportsApi } from '@/lib/api';
import type { ThreatReport, DashboardStats } from '@/types';
import { formatRelativeTime, getSeverityColor, getSeverityIcon, getRiskScoreColor } from '@/lib/utils';
import StatsCard from '@/components/StatsCard';
import RiskTrendChart from '@/components/RiskTrendChart';
import SeverityDistribution from '@/components/SeverityDistribution';

export default function Dashboard() {
  const [reports, setReports] = useState<ThreatReport[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [reportsData, statsData] = await Promise.all([
        reportsApi.getRecent(20),
        reportsApi.getStats(),
      ]);
      setReports(reportsData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredReports = reports.filter((report) => {
    if (filterSeverity === 'all') return true;
    return report.severity?.toLowerCase() === filterSeverity;
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-info animate-spin mx-auto mb-4" />
          <p className="text-gray-400">Loading threat intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 space-y-8 max-w-[1800px] mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Threat Analysis Dashboard</h1>
          <p className="text-gray-400">
            AI-powered security insights and predictive threat intelligence
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center space-x-2 px-4 py-2 bg-dark-card hover:bg-dark-hover border border-dark-border rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Refresh</span>
        </button>
      </div>

      {/* Stats Grid */}
      {stats && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatsCard
            title="Total Reports"
            value={stats.total_reports}
            icon={Shield}
            trend="+12% from last week"
            color="info"
          />
          <StatsCard
            title="High Risk Alerts"
            value={stats.high_risk_count}
            icon={AlertTriangle}
            trend={`${stats.critical_count} critical`}
            color="critical"
          />
          <StatsCard
            title="Avg Risk Score"
            value={`${stats.avg_risk_score}/100`}
            icon={TrendingUp}
            trend="AI-calculated"
            color="medium"
          />
          <StatsCard
            title="Last 24h"
            value={stats.recent_24h_count}
            icon={Clock}
            trend="Active monitoring"
            color="low"
          />
        </div>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RiskTrendChart />
        </div>
        <div>
          <SeverityDistribution stats={stats} />
        </div>
      </div>

      {/* Reports Table */}
      <div className="bg-dark-card border border-dark-border rounded-lg overflow-hidden">
        <div className="p-6 border-b border-dark-border">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-white">Recent Threat Reports</h2>
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-dark-surface border border-dark-border rounded-lg px-3 py-1 text-sm focus:outline-none focus:border-info"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-dark-surface">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Report ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Alerts
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Affected Hosts
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  AI Summary
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {filteredReports.map((report) => (
                <tr
                  key={report.id}
                  className="hover:bg-dark-hover transition-colors"
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link
                      to={`/reports/${report.id}`}
                      className="text-info hover:text-info-light font-mono font-medium"
                    >
                      #{report.id.toString().padStart(4, '0')}
                    </Link>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border ${getSeverityColor(
                        report.severity
                      )}`}
                    >
                      {getSeverityIcon(report.severity)} {report.severity || 'Unknown'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <div className="flex-1 h-2 bg-dark-surface rounded-full overflow-hidden">
                        <div
                          className={`h-full ${getRiskScoreColor(report.risk_score)} bg-current`}
                          style={{ width: `${report.risk_score}%` }}
                        />
                      </div>
                      <span className={`text-sm font-semibold ${getRiskScoreColor(report.risk_score)}`}>
                        {report.risk_score}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                    {report.alerts_count}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex -space-x-1">
                      {report.hosts?.slice(0, 3).map((host, idx) => (
                        <div
                          key={idx}
                          className="w-8 h-8 rounded-full bg-dark-surface border-2 border-dark-card flex items-center justify-center text-xs font-medium"
                          title={host}
                        >
                          {host.charAt(0).toUpperCase()}
                        </div>
                      ))}
                      {report.hosts && report.hosts.length > 3 && (
                        <div className="w-8 h-8 rounded-full bg-dark-surface border-2 border-dark-card flex items-center justify-center text-xs font-medium">
                          +{report.hosts.length - 3}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 max-w-md">
                    <p className="text-sm text-gray-300 truncate" title={report.details?.tldr || report.summary}>
                      {report.details?.tldr || report.summary || 'No summary available'}
                    </p>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {formatRelativeTime(report.created_at)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link
                      to={`/reports/${report.id}`}
                      className="inline-flex items-center space-x-1 text-info hover:text-info-light transition-colors"
                    >
                      <span className="text-sm">View</span>
                      <ArrowRight className="w-4 h-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredReports.length === 0 && (
            <div className="text-center py-12">
              <Shield className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400">No threat reports found</p>
              <p className="text-sm text-gray-500 mt-2">
                System is monitoring for security threats...
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
