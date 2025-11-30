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
import TacticDistribution from '@/components/SeverityDistribution';

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
      <div className="flex items-center justify-center h-screen bg-neutral-50">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-neutral-900 animate-spin mx-auto mb-4" />
          <p className="text-neutral-700 text-sm font-medium">Loading threat intelligence...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-12 space-y-12 max-w-7xl mx-auto">
      {/* Minimal Header */}
      <div className="flex items-center justify-between border-b border-neutral-300 pb-6">
        <div>
          <h1 className="text-4xl font-light tracking-tight text-neutral-900 mb-2">
            Threat Analysis Dashboard
          </h1>
          <p className="text-sm text-neutral-700 font-medium">
            AI-powered security insights and predictive threat intelligence
          </p>
        </div>

        <button
          onClick={loadData}
          className="btn-minimal flex items-center space-x-2"
        >
          <RefreshCw className="w-4 h-4" />
          <span className="text-sm font-medium">Refresh</span>
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
          <TacticDistribution />
        </div>
      </div>

      {/* Minimal Reports Table */}
      <div className="bg-white border border-neutral-300">
        <div className="p-6 border-b border-neutral-300 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-2xl font-medium tracking-tight text-neutral-900">
              All Threat Reports
            </h2>
            <div className="text-sm text-neutral-700 font-medium">
              {startIndex + 1}–{Math.min(endIndex, filteredReports.length)} of {filteredReports.length}
            </div>
          </div>

          {/* Search and Filters */}
          <div className="flex flex-col sm:flex-row gap-3">
            {/* Search Bar */}
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
              <input
                type="text"
                placeholder="Search by ID, summary, or hostname..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="input-minimal w-full pl-10 text-sm"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-neutral-500" />
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="input-minimal text-sm pr-8"
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
              <Calendar className="w-4 h-4 text-neutral-500" />
              <select
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
                className="input-minimal text-sm pr-8"
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
          <table>
            <thead>
              <tr>
                <th>Report ID</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Alerts</th>
                <th>Affected Hosts</th>
                <th>AI Summary</th>
                <th>Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedReports.map((report) => (
                <tr key={report.id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link
                      to={`/reports/${report.id}`}
                      className="text-info hover:underline font-mono font-medium transition-colors"
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
                      <div className="flex-1 h-2 bg-neutral-200 rounded-full overflow-hidden">
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
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-900 font-medium">
                    {report.alerts_count}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex -space-x-1">
                      {report.hosts?.slice(0, 3).map((host, idx) => (
                        <div
                          key={idx}
                          className="w-8 h-8 rounded-full bg-neutral-200 border-2 border-white flex items-center justify-center text-xs font-medium text-neutral-900"
                          title={host}
                        >
                          {host.charAt(0).toUpperCase()}
                        </div>
                      ))}
                      {report.hosts && report.hosts.length > 3 && (
                        <div className="w-8 h-8 rounded-full bg-neutral-200 border-2 border-white flex items-center justify-center text-xs font-medium text-neutral-900">
                          +{report.hosts.length - 3}
                        </div>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 max-w-md">
                    <p className="text-sm text-neutral-900 truncate" title={report.details?.tldr || report.summary}>
                      {report.details?.tldr || report.summary || 'No summary available'}
                    </p>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-700">
                    {formatRelativeTime(report.created_at)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <Link
                      to={`/reports/${report.id}`}
                      className="inline-flex items-center space-x-1 text-info hover:underline transition-colors font-medium"
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
              <Shield className="w-16 h-16 text-neutral-400 mx-auto mb-4" />
              <p className="text-neutral-900 font-medium">No threat reports found</p>
              <p className="text-sm text-neutral-700 mt-2">
                {searchQuery || filterSeverity !== 'all' || dateFilter !== 'all'
                  ? 'Try adjusting your filters'
                  : 'System is monitoring for security threats...'}
              </p>
            </div>
          )}
        </div>

        {/* Minimal Pagination */}
        {filteredReports.length > 0 && totalPages > 1 && (
          <div className="bg-neutral-50 border-t border-neutral-300 px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Page info */}
              <div className="text-sm text-neutral-900 font-medium">
                Page <span className="font-semibold">{currentPage}</span> of{' '}
                <span className="font-semibold">{totalPages}</span>
              </div>

              {/* Pagination controls */}
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => setCurrentPage((prev) => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="btn-minimal disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-4 h-4" />
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
                        className={`px-4 py-2 text-sm font-medium transition-all ${
                          currentPage === pageNum
                            ? 'bg-neutral-900 text-white'
                            : 'btn-minimal'
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
                  className="btn-minimal disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
