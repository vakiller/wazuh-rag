import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, Brain, FileWarning, Target, AlertTriangle, Server, Shield } from 'lucide-react';
import { reportsApi } from '@/lib/api';
import type { ThreatReport } from '@/types';

// Import new components
import ExecutiveSummary from '@/components/ExecutiveSummary';
import AttackTimeline from '@/components/AttackTimeline';
import MitrePanel from '@/components/MitrePanel';
import IocPanel from '@/components/IocPanel';
import Playbook from '@/components/Playbook';
import ImpactPanel from '@/components/ImpactPanel';
import AffectedSystems from '@/components/AffectedSystems';
import StatsCard from '@/components/StatsCard';

export default function ReportDetail() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<ThreatReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadReport();
  }, [id]);

  const loadReport = async () => {
    if (!id) return;
    try {
      const data = await reportsApi.getById(parseInt(id));
      setReport(data);
    } catch (error) {
      console.error('Failed to load report:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen bg-neutral-50">
        <div className="text-center">
          <Brain className="w-16 h-16 text-info animate-pulse mx-auto mb-6" />
          <div className="space-y-2">
            <p className="text-xl font-semibold text-neutral-900">Analyzing Threat Intelligence</p>
            <p className="text-sm text-neutral-700 font-medium">Reconstructing attack timeline with llm...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="flex items-center justify-center h-screen bg-neutral-50">
        <div className="text-center">
          <FileWarning className="w-20 h-20 text-neutral-400 mx-auto mb-6" />
          <p className="text-xl text-neutral-900 font-medium mb-6">Report not found</p>
          <Link
            to="/"
            className="btn-primary inline-flex items-center space-x-2"
          >
            <ArrowLeft className="w-5 h-5" />
            <span>Return to Dashboard</span>
          </Link>
        </div>
      </div>
    );
  }

  // Extract tactics from MITRE techniques
  const uniqueTactics = new Set<string>();
  report.mitre_list?.forEach(technique => {
    technique.tactic.split(',').forEach(t => uniqueTactics.add(t.trim()));
  });

  return (
    <div className="min-h-screen bg-neutral-50">
      <div className="p-12 space-y-12 max-w-7xl mx-auto">
        {/* Back Button */}
        <Link
          to="/"
          className="inline-flex items-center space-x-2 text-neutral-700 hover:text-neutral-900 transition-colors group font-medium"
        >
          <ArrowLeft className="w-5 h-5 group-hover:-translate-x-1 transition-transform" />
          <span>Back to Dashboard</span>
        </Link>

        {/* Executive Summary Banner */}
        <ExecutiveSummary report={report} />

        {/* Overview Cards - 4 Column Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatsCard
            title="Risk Score"
            value={`${report.risk_score}/100`}
            icon={Target}
            color={report.risk_score >= 80 ? 'critical' : report.risk_score >= 60 ? 'high' : 'medium'}
          />
          <StatsCard
            title="Alerts Analyzed"
            value={report.alerts_count}
            icon={AlertTriangle}
            trend={`${report.hosts?.length || 0} hosts affected`}
            color="high"
          />
          <StatsCard
            title="Affected Hosts"
            value={report.hosts?.length || 0}
            icon={Server}
            trend={`${report.agents?.length || 0} agents`}
            color="medium"
          />
          <StatsCard
            title="MITRE Tactics"
            value={uniqueTactics.size}
            icon={Shield}
            trend={`${report.mitre_list?.length || 0} techniques`}
            color="info"
          />
        </div>

        {/* Main Content Grid: 8 cols left + 4 cols right */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          {/* Left Column - Main Content (8 cols) */}
          <div className="lg:col-span-8 space-y-8">
            {/* Attack Timeline */}
            {report.details?.timeline && report.details.timeline.length > 0 && (
              <AttackTimeline timeline={report.details.timeline} />
            )}

            {/* IOC Intelligence */}
            {report.iocs && (
              <IocPanel iocs={report.iocs} />
            )}

            {/* Response Playbook */}
            {report.suggested_actions && (
              <Playbook playbook={report.suggested_actions} />
            )}

            {/* Bottom Row: Impact + Systems */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              {/* Business Impact */}
              {report.details?.business_impact && (
                <ImpactPanel impact={report.details.business_impact} />
              )}

              {/* Affected Systems */}
              <AffectedSystems hosts={report.hosts || []} agents={report.agents || []} />
            </div>
          </div>

          {/* Right Column - Sidebar (4 cols) */}
          <div className="lg:col-span-4">
            {report.mitre_list && report.mitre_list.length > 0 && (
              <MitrePanel techniques={report.mitre_list} />
            )}
          </div>
        </div>

        {/* AI Predictions Section (if available) */}
        {report.details?.predictions && report.details.predictions.length > 0 && (
          <div className="bg-high-light border-2 border-high p-8">
            <div className="flex items-center space-x-3 mb-6">
              <Brain className="w-6 h-6 text-high" />
              <h3 className="text-2xl font-medium text-neutral-900">AI-Predicted Next Actions</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {report.details.predictions.map((pred, idx) => (
                <div
                  key={idx}
                  className="bg-white border border-neutral-300 p-6 hover:shadow-md transition-all"
                >
                  <div className="flex items-start justify-between mb-3">
                    <span className="px-3 py-1 bg-high-light text-high-dark border border-high text-xs font-bold">
                      {pred.confidence}
                    </span>
                  </div>
                  <p className="text-neutral-900 font-semibold mb-2">{pred.action}</p>
                  {pred.reasoning && (
                    <p className="text-sm text-neutral-700">{pred.reasoning}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
