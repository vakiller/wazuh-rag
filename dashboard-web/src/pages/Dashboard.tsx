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
  Search,
  ChevronLeft,
  ChevronRight,
  Calendar,
} from 'lucide-react';
import { reportsApi } from '@/lib/api';
import type { ThreatReport, DashboardStats } from '@/types';
import { formatRelativeTime, getSeverityColor, getSeverityIcon, getRiskScoreColor } from '@/lib/utils';
import StatsCard from '@/components/StatsCard';
import RiskTrendChart from '@/components/RiskTrendChart';
import SeverityDistribution from '@/components/SeverityDistribution';

export default function Dashboard() {
  const [allReports, setAllReports] = useState<ThreatReport[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [dateFilter, setDateFilter] = useState<string>('all');
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 10;

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [reportsData, statsData] = await Promise.all([
        reportsApi.getAll({ limit: 10000, offset: 0 }),
        reportsApi.getStats(),
      ]);
      setAllReports(reportsData);
      setStats(statsData);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredReports = allReports.filter((report) => {
    // Severity filter
    if (filterSeverity !== 'all' && report.severity?.toLowerCase() !== filterSeverity) {
      return false;
    }

    // Search filter (by ID, summary, or hosts)
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      const matchesId = report.id.toString().includes(query);
      const matchesSummary = (report.summary || '').toLowerCase().includes(query);
      const matchesTldr = (report.details?.tldr || '').toLowerCase().includes(query);
      const matchesHosts = report.hosts?.some(host => host.toLowerCase().includes(query));

      if (!matchesId && !matchesSummary && !matchesTldr && !matchesHosts) {
        return false;
      }
    }

    // Date filter
    if (dateFilter !== 'all') {
      const reportDate = new Date(report.created_at);
      const now = new Date();
      const diffHours = (now.getTime() - reportDate.getTime()) / (1000 * 60 * 60);

      switch (dateFilter) {
        case '24h':
          if (diffHours > 24) return false;
          break;
        case '7d':
          if (diffHours > 24 * 7) return false;
          break;
        case '30d':
          if (diffHours > 24 * 30) return false;
          break;
      }
    }

    return true;
  });

  // Pagination
  const totalPages = Math.ceil(filteredReports.length / pageSize);
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedReports = filteredReports.slice(startIndex, endIndex);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [filterSeverity, searchQuery, dateFilter]);

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
        <div className="p-6 border-b border-dark-border space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold text-white">All Threat Reports</h2>
            <div className="text-sm text-gray-400">
              Showing {startIndex + 1}-{Math.min(endIndex, filteredReports.length)} of {filteredReports.length} reports
            </div>
          </div>

          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Search Bar */}
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search by ID, summary, or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-dark-surface border border-dark-border rounded-lg pl-10 pr-4 py-2 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-info transition-colors"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-info transition-colors"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Date Filter */}
            <div className="flex items-center space-x-2">
              <Calendar className="w-4 h-4 text-gray-400" />
              <select
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="bg-dark-surface border border-dark-border rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-info transition-colors"
              >
                <option value="all">All Time</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
                <option value="30d">Last 30 Days</option>
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
              {paginatedReports.map((report) => (
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
                {searchQuery || filterSeverity !== 'all' || dateFilter !== 'all'
                  ? 'Try adjusting your filters'
                  : 'System is monitoring for security threats...'}
              </p>
            </div>
          )}
        </div>

        {/* Pagination */}
        {filteredReports.length > 0 && totalPages > 1 && (
          <div className="bg-dark-surface border-t border-dark-border px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Page info */}
              <div className="text-sm text-gray-400">
                Page <span className="font-semibold text-white">{currentPage}</span> of{' '}
                <span className="font-semibold text-white">{totalPages}</span>
              </div>

              {/* Pagination controls */}
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-2 bg-dark-card border border-dark-border rounded-lg text-gray-400 hover:text-white hover:border-info/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  <ChevronLeft className="w-5 h-5" />
                </button>

                {/* Page numbers */}
                <div className="flex items-center space-x-1">
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let pageNum;
                    if (totalPages <= 5) {
                      pageNum = i + 1;
                    } else if (currentPage <= 3) {
                      pageNum = i + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + i;
                    } else {
                      pageNum = currentPage - 2 + i;
                    }

                    return (
                      <button
                        key={pageNum}
                        onClick={() => setCurrentPage(pageNum)}
                        className={`px-4 py-2 rounded-lg text-sm font-semibold transition-all ${
                          currentPage === pageNum
                            ? 'bg-info text-white'
                            : 'bg-dark-card border border-dark-border text-gray-400 hover:text-white hover:border-info/30'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                </div>

                <button
                  onClick={() => setCurrentPage((prev) => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-2 bg-dark-card border border-dark-border rounded-lg text-gray-400 hover:text-white hover:border-info/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
                >
                  <ChevronRight className="w-5 h-5" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
