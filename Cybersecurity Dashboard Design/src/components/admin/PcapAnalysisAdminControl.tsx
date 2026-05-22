import React, { useEffect, useMemo, useRef, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  AlertTriangle,
  Archive,
  BarChart3,
  CheckCircle,
  Clock,
  Database,
  Download,
  Eye,
  FileJson,
  FileSearch,
  Gauge,
  Layers,
  ListChecks,
  Loader2,
  PlayCircle,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Timer,
  UploadCloud,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner@2.0.3";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import {
  AdminPcapJob,
  AdminPcapOverview,
  buildPcapArtifactFetchInit,
  emptyAdminPcapOverview,
  formatAdminPcapTime,
  formatProcessingTime,
  getDownloadFilename,
  getPcapJobExportUrl,
  getQueueHealthState,
  getRiskBadgeClass,
  loadAdminPcapOverview,
} from "../../services/adminPcapOverview";
import "./PcapAnalysisAdminControl.css";

type ExportType = "report" | "evidence";

interface ReportPreviewState {
  filename: string;
  jobId: string;
  jsonText: string;
}

interface MetricCardConfig {
  title: string;
  value: string;
  helper: string;
  icon: LucideIcon;
  tone: "blue" | "cyan" | "emerald" | "amber" | "red" | "slate";
}

function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return "0";
  }
  return Number(value).toLocaleString();
}

function formatScore(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) {
    return "N/A";
  }
  return `${Math.round(Number(value))}`;
}

function titleCase(value: string): string {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

function isSuspiciousPcapJob(job: AdminPcapJob): boolean {
  const family = String(job.detected_family || "").trim().toLowerCase();
  return (
    job.threat_detected === true ||
    ["medium", "high", "critical"].includes(String(job.risk_level || "").toLowerCase()) ||
    (Number(job.score || 0) > 0) ||
    Boolean(family && !["benign", "normal", "unknown", "unknown / not classified", "not classified"].includes(family))
  );
}

async function getArtifactErrorMessage(response: Response, fallback: string): Promise<string> {
  try {
    const payload = await response.clone().json();
    return String(payload?.message || payload?.error || fallback);
  } catch {
    return fallback;
  }
}

function queueTone(status: string): string {
  if (status === "healthy") return "pcap-admin-health pcap-admin-health-healthy";
  if (status === "warning") return "pcap-admin-health pcap-admin-health-warning";
  if (status === "critical") return "pcap-admin-health pcap-admin-health-critical";
  return "pcap-admin-health pcap-admin-health-unknown";
}

function statusBadgeClass(status: string): string {
  const normalized = status.toLowerCase();
  if (["done", "completed", "success", "resolved"].includes(normalized)) {
    return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
  if (["running", "processing", "in_progress"].includes(normalized)) {
    return "border-sky-200 bg-sky-50 text-sky-700";
  }
  if (["queued", "pending", "waiting"].includes(normalized)) {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  if (["error", "failed", "failure"].includes(normalized)) {
    return "border-red-200 bg-red-50 text-red-700";
  }
  return "border-slate-200 bg-slate-50 text-slate-500";
}

function zeekLabel(value: string): string {
  if (value === "yes") return "Yes";
  if (value === "no") return "No";
  return "Unknown";
}

function SkeletonBlock({ className = "" }: { className?: string }) {
  return <div className={`pcap-admin-skeleton ${className}`} />;
}

function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="pcap-admin-empty">
      <FileSearch className="h-8 w-8 text-sky-400" />
      <div>
        <div className="font-semibold text-slate-700">{title}</div>
        <div className="mt-1 text-sm text-slate-500">{description}</div>
      </div>
    </div>
  );
}

function MetricCard({
  config,
  loading,
}: {
  config: MetricCardConfig;
  loading: boolean;
}) {
  const Icon = config.icon;
  return (
    <div className={`pcap-admin-metric pcap-admin-tone-${config.tone}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="pcap-admin-metric-title">{config.title}</p>
          {loading ? (
            <SkeletonBlock className="mt-3 h-8 w-24" />
          ) : (
            <p className="pcap-admin-metric-value">{config.value}</p>
          )}
        </div>
        <div className="pcap-admin-icon-wrap">
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {loading ? (
        <SkeletonBlock className="mt-4 h-4 w-32" />
      ) : (
        <p className="pcap-admin-metric-helper">{config.helper}</p>
      )}
    </div>
  );
}

function ActionButton({
  children,
  disabled,
  title,
  onClick,
}: {
  children: React.ReactNode;
  disabled?: boolean;
  title: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      className="pcap-admin-row-action"
      disabled={disabled}
      title={title}
      onClick={onClick}
    >
      {children}
    </button>
  );
}

export default function PcapAnalysisAdminControl() {
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const [overview, setOverview] = useState<AdminPcapOverview>(() => emptyAdminPcapOverview());
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<ExportType | "summary" | null>(null);
  const [selectedTimelineJobId, setSelectedTimelineJobId] = useState<string | null>(null);
  const [reportPreview, setReportPreview] = useState<ReportPreviewState | null>(null);

  const loadOverview = async (showToast = false) => {
    setError(null);
    setRefreshing(showToast);
    if (!showToast) setLoading(true);

    try {
      const result = await loadAdminPcapOverview();
      setOverview(result);
      if (showToast) toast.success("PCAP admin overview refreshed.");
    } catch (caught: any) {
      const message = caught?.message || "Failed to load PCAP admin overview.";
      setOverview(emptyAdminPcapOverview());
      setError(message);
      if (showToast) toast.error(message);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    void loadOverview();
  }, []);

  const queueHealth = useMemo(() => getQueueHealthState(overview), [overview]);

  const metricCards: MetricCardConfig[] = useMemo(
    () => [
      {
        title: "Total Uploaded Files",
        value: formatNumber(overview.summary.total_uploaded_files),
        helper: "Unique PCAP files observed by the registry.",
        icon: UploadCloud,
        tone: "blue",
      },
      {
        title: "Total Jobs",
        value: formatNumber(overview.summary.total_jobs),
        helper: "All queued, running, completed, and failed jobs.",
        icon: Database,
        tone: "cyan",
      },
      {
        title: "Running Jobs",
        value: formatNumber(overview.summary.running_jobs),
        helper: "Currently processing captures.",
        icon: PlayCircle,
        tone: "blue",
      },
      {
        title: "Completed Jobs",
        value: formatNumber(overview.summary.completed_jobs),
        helper: "Finished analyses with persisted state.",
        icon: CheckCircle,
        tone: "emerald",
      },
      {
        title: "Failed Jobs",
        value: formatNumber(overview.summary.failed_jobs),
        helper: overview.summary.failed_jobs > 0 ? "Needs review." : "No failures recorded.",
        icon: AlertTriangle,
        tone: overview.summary.failed_jobs > 0 ? "red" : "slate",
      },
      {
        title: "Queued Jobs",
        value: formatNumber(overview.summary.queued_jobs),
        helper: "Waiting for a worker slot.",
        icon: ListChecks,
        tone: overview.summary.queued_jobs > 0 ? "amber" : "slate",
      },
      {
        title: "Average Processing Time",
        value: formatProcessingTime(overview.summary.average_processing_time_seconds),
        helper: "Calculated from job timestamps when exact timing is absent.",
        icon: Timer,
        tone: "cyan",
      },
      {
        title: "Last Analysis Time",
        value: formatAdminPcapTime(overview.summary.last_analysis_time),
        helper: "Most recent successful PCAP completion.",
        icon: Clock,
        tone: "blue",
      },
    ],
    [overview],
  );

  const timelineEvents = useMemo(() => {
    if (!selectedTimelineJobId) return overview.timeline;
    return overview.timeline.filter((event) => event.job_id === selectedTimelineJobId);
  }, [overview.timeline, selectedTimelineJobId]);

  const latestExportableReport = useMemo(
    () => overview.latest_files.find((job) => job.report_available && job.job_id),
    [overview.latest_files],
  );

  const latestExportableEvidence = useMemo(
    () => overview.latest_files.find((job) => job.evidence_available && job.job_id && isSuspiciousPcapJob(job)),
    [overview.latest_files],
  );

  const suspiciousPcapFiles = useMemo(
    () => overview.top_suspicious_files.filter(isSuspiciousPcapJob),
    [overview.top_suspicious_files],
  );

  const rankedPcapFiles = suspiciousPcapFiles.length > 0 ? suspiciousPcapFiles : overview.latest_files;
  const hasSuspiciousPcapFiles = suspiciousPcapFiles.length > 0;

  const exportSummary = () => {
    setExporting("summary");
    try {
      const blob = new Blob([JSON.stringify(overview, null, 2)], {
        type: "application/json;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `pcap-admin-summary-${new Date().toISOString().slice(0, 10)}.json`;
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
        anchor.remove();
      }, 1000);
      toast.success("PCAP admin summary exported.");
    } finally {
      setExporting(null);
    }
  };

  const downloadArtifact = async (job: AdminPcapJob | undefined, type: ExportType) => {
    if (!job?.job_id) {
      toast.error("No PCAP job is available for export.");
      return;
    }

    setExporting(type);
    try {
      const response = await fetch(
        getPcapJobExportUrl(job.job_id, type),
        buildPcapArtifactFetchInit({ cache: "no-store" }),
      );

      if (!response.ok) {
        const fallback =
          type === "evidence"
            ? "Evidence export is not available for this job."
            : "Report export is not available for this job.";
        const message = await getArtifactErrorMessage(response, fallback);
        throw new Error(message);
      }

      const blob = await response.blob();
      if (!blob || blob.size === 0) {
        throw new Error(
          type === "evidence"
            ? "Evidence export returned an empty file."
            : "Report export returned an empty file.",
        );
      }

      const fallbackName =
        type === "evidence"
          ? `pcap_evidence_${job.job_id}.zip`
          : `pcap_report_${job.job_id}.json`;
      const filename = getDownloadFilename(
        response.headers.get("content-disposition"),
        fallbackName,
      );
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      anchor.style.display = "none";
      document.body.appendChild(anchor);
      anchor.click();
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
        anchor.remove();
      }, 1000);
      toast.success(type === "evidence" ? "Evidence bundle exported." : "Latest report exported.");
    } catch (caught: any) {
      toast.error(caught?.message || "PCAP export failed.");
    } finally {
      setExporting(null);
    }
  };

  const openReport = async (job: AdminPcapJob) => {
    if (!job.job_id || !job.report_available) {
      toast.info("Report is not available for this PCAP job yet.");
      return;
    }

    setExporting("report");
    try {
      const response = await fetch(
        getPcapJobExportUrl(job.job_id, "report"),
        buildPcapArtifactFetchInit({ cache: "no-store" }),
      );

      if (!response.ok) {
        const message = await getArtifactErrorMessage(
          response,
          "Report export is not available for this job.",
        );
        throw new Error(message);
      }

      const reportText = await response.text();
      if (!reportText.trim()) {
        throw new Error("Report export returned an empty file.");
      }

      let jsonText = reportText;
      try {
        jsonText = JSON.stringify(JSON.parse(reportText), null, 2);
      } catch {}

      const filename = getDownloadFilename(
        response.headers.get("content-disposition"),
        `pcap_report_${job.job_id}.json`,
      );
      setReportPreview({ filename, jobId: job.job_id, jsonText });
    } catch (caught: any) {
      toast.error(caught?.message || "PCAP report failed to open.");
    } finally {
      setExporting(null);
    }
  };

  const downloadPreviewReport = () => {
    if (!reportPreview) return;

    const blob = new Blob([reportPreview.jsonText], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = reportPreview.filename;
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    window.setTimeout(() => {
      URL.revokeObjectURL(url);
      anchor.remove();
    }, 1000);
  };

  const viewTimeline = (job: AdminPcapJob) => {
    const hasTimeline = overview.timeline.some((event) => event.job_id === job.job_id);
    if (!job.job_id || !hasTimeline) {
      toast.info("Detailed timeline data is not available for this job.");
      return;
    }
    setSelectedTimelineJobId(job.job_id);
    timelineRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <section className="pcap-admin-control">
      <div className="pcap-admin-hero">
        <div className="min-w-0">
          <div className="pcap-admin-eyebrow">
            <ShieldCheck className="h-4 w-4" />
            PCAP Operations
          </div>
          <h1>PCAP Analysis Admin Control</h1>
          <p>
            Monitor uploaded PCAP files, analysis jobs, queue health, detection quality,
            processing performance, and recent file scores.
          </p>
        </div>

        <div className="pcap-admin-hero-actions">
          <Button
            type="button"
            variant="outline"
            className="pcap-admin-button"
            onClick={() => void loadOverview(true)}
            disabled={refreshing}
          >
            {refreshing ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="h-4 w-4" />
            )}
            Refresh
          </Button>
          <Button
            type="button"
            className="pcap-admin-button-primary"
            onClick={exportSummary}
            disabled={exporting === "summary"}
          >
            <Download className="h-4 w-4" />
            Export Summary
          </Button>
        </div>
      </div>

      {error ? (
        <div className="pcap-admin-error">
          <AlertTriangle className="h-5 w-5" />
          <span>{error}</span>
        </div>
      ) : null}

      <div className="pcap-admin-metrics-grid">
        {metricCards.map((card) => (
          <MetricCard key={card.title} config={card} loading={loading} />
        ))}
      </div>

      <div className="pcap-admin-two-grid pcap-admin-status-grid">
        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">Jobs Queue Health</p>
              <h2>Queue Health</h2>
            </div>
            <div className="pcap-admin-icon-wrap">
              <Activity className="h-5 w-5" />
            </div>
          </div>
          {loading ? (
            <div className="space-y-3">
              <SkeletonBlock className="h-8 w-36" />
              <SkeletonBlock className="h-4 w-full" />
              <SkeletonBlock className="h-4 w-4/5" />
            </div>
          ) : (
            <>
              <div className={queueTone(queueHealth.status)}>
                <span className="pcap-admin-health-dot" />
                {titleCase(queueHealth.status)}
              </div>
              <p className="pcap-admin-card-copy">{queueHealth.message}</p>
              <div className="pcap-admin-mini-grid">
                <span>Queued: {overview.summary.queued_jobs}</span>
                <span>Running: {overview.summary.running_jobs}</span>
                <span>Failed: {overview.summary.failed_jobs}</span>
                <span>Completed: {overview.summary.completed_jobs}</span>
              </div>
              <p className="pcap-admin-footnote">
                Latest job status: {titleCase(queueHealth.latest_job_status)}
              </p>
            </>
          )}
        </div>

        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">Processing Performance</p>
              <h2>Performance</h2>
            </div>
            <div className="pcap-admin-icon-wrap">
              <Gauge className="h-5 w-5" />
            </div>
          </div>
          {loading ? (
            <div className="space-y-3">
              <SkeletonBlock className="h-5 w-full" />
              <SkeletonBlock className="h-5 w-5/6" />
              <SkeletonBlock className="h-5 w-3/4" />
            </div>
          ) : (
            <div className="pcap-admin-definition-list">
              <div>
                <span>Average time</span>
                <strong>
                  {formatProcessingTime(overview.performance.average_processing_time_seconds)}
                </strong>
              </div>
              <div>
                <span>Fastest analysis</span>
                <strong>
                  {formatProcessingTime(overview.performance.fastest_processing_time_seconds)}
                </strong>
              </div>
              <div>
                <span>Slowest analysis</span>
                <strong>
                  {formatProcessingTime(overview.performance.slowest_processing_time_seconds)}
                </strong>
              </div>
              <div>
                <span>Total processed files</span>
                <strong>{formatNumber(overview.performance.processed_files)}</strong>
              </div>
              <div>
                <span>Failed processing rate</span>
                <strong>
                  {overview.performance.failed_processing_rate === null
                    ? "Not available"
                    : `${overview.performance.failed_processing_rate}%`}
                </strong>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="pcap-admin-card">
        <div className="pcap-admin-card-head">
          <div>
            <p className="pcap-admin-card-kicker">Latest 5 PCAP Analysis Results</p>
            <h2>Latest Analysis Results</h2>
          </div>
          <div className="pcap-admin-icon-wrap">
            <BarChart3 className="h-5 w-5" />
          </div>
        </div>
        {loading ? (
          <div className="space-y-3">
            <SkeletonBlock className="h-10 w-full" />
            <SkeletonBlock className="h-10 w-full" />
            <SkeletonBlock className="h-10 w-full" />
          </div>
        ) : overview.latest_files.length === 0 ? (
          <EmptyState
            title="No analyzed files yet"
            description="Completed PCAP analysis jobs will appear here once reports are available."
          />
        ) : (
          <div className="pcap-admin-table-wrap">
            <table className="pcap-admin-table">
              <thead>
                <tr>
                  <th>Stored Filename</th>
                  <th>Status</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Analysis Mode</th>
                  <th>Zeek Used</th>
                  <th>Processing Time</th>
                  <th>Finished At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {overview.latest_files.map((job) => (
                  <tr key={job.job_id || job.filename}>
                    <td>
                      <div className="pcap-admin-file-cell">
                        <FileSearch className="h-4 w-4 text-sky-500" />
                        <span>{job.filename}</span>
                      </div>
                    </td>
                    <td>
                      <Badge className={statusBadgeClass(job.status)}>
                        {titleCase(job.status)}
                      </Badge>
                    </td>
                    <td>{formatScore(job.score)}</td>
                    <td>
                      <Badge className={getRiskBadgeClass(job.risk_level)}>
                        {titleCase(job.risk_level)}
                      </Badge>
                    </td>
                    <td>{job.analysis_mode}</td>
                    <td>{zeekLabel(job.zeek_used)}</td>
                    <td>{formatProcessingTime(job.processing_time_seconds)}</td>
                    <td>{formatAdminPcapTime(job.finished_at)}</td>
                    <td>
                      <div className="pcap-admin-actions-inline">
                        <ActionButton
                          title={
                            job.report_available
                              ? "Preview this report inside the admin console."
                              : "Report is not available for this job."
                          }
                          disabled={!job.report_available || exporting !== null}
                          onClick={() => void openReport(job)}
                        >
                          <Eye className="h-4 w-4" />
                        </ActionButton>
                        <ActionButton
                          title={
                            job.evidence_available && isSuspiciousPcapJob(job)
                              ? "Export the evidence bundle."
                              : "Evidence bundle is available only when suspicious activity is detected."
                          }
                          disabled={!job.evidence_available || !isSuspiciousPcapJob(job) || exporting !== null}
                          onClick={() => void downloadArtifact(job, "evidence")}
                        >
                          <Archive className="h-4 w-4" />
                        </ActionButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="pcap-admin-two-grid">
        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">{hasSuspiciousPcapFiles ? "Top Suspicious Files" : "Recent PCAP Files"}</p>
              <h2>Ranked Recent PCAP Files</h2>
            </div>
            <div className="pcap-admin-icon-wrap">
              <ShieldAlert className="h-5 w-5" />
            </div>
          </div>
          {loading ? (
            <div className="space-y-3">
              <SkeletonBlock className="h-16 w-full" />
              <SkeletonBlock className="h-16 w-full" />
            </div>
          ) : rankedPcapFiles.length === 0 ? (
            <EmptyState
              title="No suspicious PCAP files detected yet."
              description="Recent benign or low-risk PCAP files will appear after completed analysis jobs."
            />
          ) : (
            <div className="space-y-3">
              {!hasSuspiciousPcapFiles ? (
                <div className="rounded-2xl border border-emerald-200/70 bg-emerald-50/80 px-4 py-3 text-sm text-emerald-800">
                  Showing the latest analyzed PCAP files. No suspicious activity was detected in these results.
                </div>
              ) : null}
              {rankedPcapFiles.map((job, index) => (
                <div className="pcap-admin-ranked-row" key={job.job_id || job.filename}>
                  <div className="pcap-admin-rank">{index + 1}</div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <p className="truncate font-semibold text-slate-800">{job.filename}</p>
                      <Badge className={getRiskBadgeClass(job.risk_level)}>
                        {titleCase(job.risk_level)}
                      </Badge>
                    </div>
                    <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
                      <span>Risk Score: {formatScore(job.score)}</span>
                      <span>Family: {job.detected_family}</span>
                      <span>Status: {titleCase(job.status)}</span>
                      <span>Finished: {formatAdminPcapTime(job.finished_at)}</span>
                      <span>Report: {job.report_available ? "Available" : "Not available"}</span>
                    </div>
                  </div>
                  <div className="pcap-admin-ranked-actions">
                    <ActionButton
                      title={
                        job.report_available
                          ? isSuspiciousPcapJob(job)
                            ? "View the threat evidence report summary."
                            : "View the normal PCAP analysis report."
                          : "Report endpoint/artifact is not available."
                      }
                      disabled={!job.report_available || exporting !== null}
                      onClick={() => void openReport(job)}
                    >
                      <Eye className="h-4 w-4" />
                      {isSuspiciousPcapJob(job) ? "View Evidence" : "View Report"}
                    </ActionButton>
                    {!isSuspiciousPcapJob(job) && (
                    <ActionButton
                      title={
                        job.report_available
                          ? "Export the normal PCAP analysis report."
                          : "Report endpoint/artifact is not available."
                      }
                      disabled={!job.report_available || exporting !== null}
                      onClick={() => void downloadArtifact(job, "report")}
                    >
                      <Download className="h-4 w-4" />
                      Export Report
                    </ActionButton>
                    )}
                    {isSuspiciousPcapJob(job) && (
                    <ActionButton
                      title={
                        job.evidence_available
                          ? "Download the existing evidence bundle endpoint."
                          : "Evidence bundle is available only when suspicious activity is detected."
                      }
                      disabled={!job.evidence_available || exporting !== null}
                      onClick={() => void downloadArtifact(job, "evidence")}
                    >
                      <Archive className="h-4 w-4" />
                      Export Evidence
                    </ActionButton>
                    )}
                    <ActionButton
                      title={
                        overview.timeline.some((event) => event.job_id === job.job_id)
                          ? "Filter the admin timeline to this job."
                          : "Detailed timeline data is not available."
                      }
                      disabled={!overview.timeline.some((event) => event.job_id === job.job_id)}
                      onClick={() => viewTimeline(job)}
                    >
                      <Layers className="h-4 w-4" />
                      View Timeline
                    </ActionButton>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">Observed Classification Labels</p>
              <h2>Classification Labels</h2>
              <p className="mt-1 text-xs text-slate-500">
                These labels represent model or heuristic observations. Final risk is determined after validation and scoring.
              </p>
            </div>
            <div className="pcap-admin-icon-wrap">
              <Zap className="h-5 w-5" />
            </div>
          </div>
          {loading ? (
            <div className="space-y-3">
              <SkeletonBlock className="h-12 w-full" />
              <SkeletonBlock className="h-12 w-full" />
              <SkeletonBlock className="h-12 w-full" />
            </div>
          ) : overview.latest_attack_families.length === 0 ? (
            <EmptyState
              title="No classification labels available yet"
              description="Labels will be derived from recent PCAP alerts, clusters, or timeline metadata."
            />
          ) : (
            <div className="pcap-admin-family-list">
              {overview.latest_attack_families.map((family) => (
                <div className="pcap-admin-family-row" key={family.family}>
                  <div>
                    <p className="font-semibold text-slate-800">{family.family}</p>
                    <p className="text-xs text-slate-500">
                      Source: {family.source || "Unknown"}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getRiskBadgeClass(family.severity as any)}>
                      {family.severity ? titleCase(family.severity) : "Unknown"}
                    </Badge>
                    <span className="pcap-admin-family-count">{family.count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="pcap-admin-two-grid" ref={timelineRef}>
        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">Analysis Timeline</p>
              <h2>Recent Workflow Events</h2>
              <p className="mt-1 text-xs text-slate-500">
                Timeline is generated from available job metadata.
              </p>
            </div>
            <div className="pcap-admin-icon-wrap">
              <Clock className="h-5 w-5" />
            </div>
          </div>
          {selectedTimelineJobId ? (
            <button
              type="button"
              className="pcap-admin-clear-filter"
              onClick={() => setSelectedTimelineJobId(null)}
            >
              Showing one job. Clear timeline filter
            </button>
          ) : null}
          {loading ? (
            <div className="space-y-3">
              <SkeletonBlock className="h-24 w-full" />
              <SkeletonBlock className="h-24 w-full" />
            </div>
          ) : timelineEvents.length === 0 ? (
            <EmptyState
              title="No timeline data available"
              description="When detailed workflow data is missing, this panel uses job timestamps."
            />
          ) : (
            <div className="pcap-admin-timeline-strip">
              {timelineEvents.slice(0, 10).map((event, index) => (
                <article
                  className="pcap-admin-timeline-event"
                  key={`${event.job_id}-${event.label}-${event.timestamp}-${index}`}
                >
                  <div className="pcap-admin-timeline-dot">
                    <span />
                  </div>
                  <div>
                    <p className="font-semibold text-slate-800">{event.label}</p>
                    <p className="mt-1 text-xs text-slate-500">{event.filename}</p>
                    <p className="mt-2 text-sm text-slate-600">{event.detail}</p>
                    <p className="mt-3 text-xs font-medium text-sky-700">
                      {formatAdminPcapTime(event.timestamp)}
                    </p>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        <div className="pcap-admin-card">
          <div className="pcap-admin-card-head">
            <div>
              <p className="pcap-admin-card-kicker">Evidence & Export Center</p>
              <h2>Export Controls</h2>
            </div>
            <div className="pcap-admin-icon-wrap">
              <Download className="h-5 w-5" />
            </div>
          </div>
          <div className="pcap-admin-export-grid">
            <button
              type="button"
              className="pcap-admin-export-card"
              onClick={exportSummary}
              disabled={exporting !== null}
            >
              <Download className="h-5 w-5" />
              <span>Export PCAP Admin Summary</span>
              <small>Downloads the current normalized admin overview as JSON.</small>
            </button>
            <button
              type="button"
              className="pcap-admin-export-card"
              disabled={!latestExportableReport || exporting !== null}
              title={
                latestExportableReport
                  ? "Use the existing PCAP report export endpoint."
                  : "No latest report artifact is available."
              }
              onClick={() => void downloadArtifact(latestExportableReport, "report")}
            >
              <FileJson className="h-5 w-5" />
              <span>Export Latest Report</span>
              <small>
                {latestExportableReport
                  ? latestExportableReport.filename
                  : "Not available"}
              </small>
            </button>
            <button
              type="button"
              className="pcap-admin-export-card"
              disabled={!latestExportableEvidence || exporting !== null}
              title={
                latestExportableEvidence
                  ? "Use the existing PCAP evidence export endpoint."
                  : "Evidence bundle is available only when suspicious activity is detected."
              }
              onClick={() => void downloadArtifact(latestExportableEvidence, "evidence")}
            >
              <Archive className="h-5 w-5" />
              <span>Export Evidence Bundle</span>
              <small>
                {latestExportableEvidence
                  ? latestExportableEvidence.filename
                  : "Suspicious activity required"}
              </small>
            </button>
          </div>
          <p className="pcap-admin-footnote mt-4">
            Report and evidence exports call existing PCAP artifact endpoints. Disabled
            evidence controls mean no suspicious activity was detected or no artifact is available.
          </p>
        </div>
      </div>

      {reportPreview ? (
        <div
          className="pcap-admin-report-preview-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="pcap-admin-report-preview-title"
        >
          <div className="pcap-admin-report-preview">
            <div className="pcap-admin-report-preview-head">
              <div className="min-w-0">
                <p className="pcap-admin-card-kicker">Admin Report Preview</p>
                <h2 id="pcap-admin-report-preview-title">{reportPreview.filename}</h2>
                <p>Job ID: {reportPreview.jobId}</p>
              </div>
              <div className="pcap-admin-report-preview-actions">
                <button
                  type="button"
                  className="pcap-admin-row-action"
                  onClick={downloadPreviewReport}
                  title="Download this report JSON."
                >
                  <Download className="h-4 w-4" />
                  Download
                </button>
                <button
                  type="button"
                  className="pcap-admin-row-action"
                  onClick={() => setReportPreview(null)}
                  title="Close report preview."
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            <pre className="pcap-admin-report-preview-body">{reportPreview.jsonText}</pre>
          </div>
        </div>
      ) : null}
    </section>
  );
}
