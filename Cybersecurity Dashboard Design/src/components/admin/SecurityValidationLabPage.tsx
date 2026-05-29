import React, { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Bug,
  CheckCircle,
  Eye,
  FileWarning,
  Globe,
  Lock,
  Radar,
  RefreshCcw,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  X,
  XCircle,
  Zap,
} from 'lucide-react';
import { motion } from 'motion/react';
import { toast } from 'sonner@2.0.3';
import './SecurityValidationLabPage.css';

const API_BASE_URL =
  import.meta.env.DEV ? '' : (import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000');

type ValidationTest = {
  test_id: string;
  attack_name: string;
  method: string;
  target: string;
  expected_status: number;
  control: string;
  result: string;
  purpose: string;
  expected_behavior: string;
  description: string;
};

type ValidationResult = ValidationTest & {
  actual_status: number | null;
  passed: boolean;
  timestamp: string;
  explanation?: string;
  attempts?: number;
};

type ToastState = {
  type: 'success' | 'warning' | 'error';
  message: string;
} | null;

type OverallStatus = 'Ready' | 'Protected' | 'Partial' | 'Failed';

const ICONS: Record<string, React.ElementType> = {
  sqli_login: Terminal,
  xss_contact: Bug,
  path_traversal: FileWarning,
  cors_bad_origin: Globe,
  cors_allowed_origin: ShieldCheck,
  idor_profile: Lock,
  brute_force_login: Zap,
};

const DESCRIPTIONS: Record<string, string> = {
  sqli_login: 'Confirms login injection patterns stop at WAF Rule 1001.',
  xss_contact: 'Checks script payload blocking before application handling.',
  path_traversal: 'Validates download traversal containment at the edge.',
  cors_bad_origin: 'Verifies sensitive account APIs reject untrusted origins.',
  cors_allowed_origin: 'Confirms trusted frontend origin passes the WAF.',
  idor_profile: 'Exercises obvious profile object id manipulation blocking.',
  brute_force_login: 'Runs repeated local login attempts until throttled.',
};

const STORAGE_KEY = 'sentinel_admin_security_validation_lab_results_v1';
const MAX_TIMELINE_ITEMS = 12;

function loadStoredValidationState(): {
  results: Record<string, ValidationResult>;
  timeline: ValidationResult[];
} {
  if (typeof window === 'undefined') {
    return { results: {}, timeline: [] };
  }

  try {
    const parsed = JSON.parse(window.localStorage.getItem(STORAGE_KEY) || '{}');
    const rawResults = parsed?.results && typeof parsed.results === 'object' ? parsed.results : {};
    const rawTimeline = Array.isArray(parsed?.timeline) ? parsed.timeline : [];
    const results = Object.fromEntries(
      Object.entries(rawResults).filter(([, value]) => Boolean(value && typeof value === 'object')),
    ) as Record<string, ValidationResult>;
    const timeline = rawTimeline
      .filter((item: unknown) => Boolean(item && typeof item === 'object'))
      .slice(0, MAX_TIMELINE_ITEMS) as ValidationResult[];
    return { results, timeline };
  } catch {
    return { results: {}, timeline: [] };
  }
}

function saveStoredValidationState(
  results: Record<string, ValidationResult>,
  timeline: ValidationResult[],
) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({
      results,
      timeline: timeline.slice(0, MAX_TIMELINE_ITEMS),
    }),
  );
}

function clearStoredValidationState() {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(STORAGE_KEY);
}

function authHeaders(): Headers {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  const token = window.localStorage.getItem('sentinel_admin_token');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  return headers;
}

function formatTime(value?: string | null) {
  if (!value) return 'Not run yet';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return 'Unknown';
  return parsed.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function safeSummary(value?: string) {
  return value?.trim() || 'Sanitized validation result is available after the simulation runs.';
}

function statusTone(status: OverallStatus) {
  return status.toLowerCase();
}

function resultTone(result?: ValidationResult) {
  if (!result) return 'ready';
  return result.passed ? 'passed' : 'failed';
}

export default function SecurityValidationLabPage() {
  const storedState = useMemo(loadStoredValidationState, []);
  const [tests, setTests] = useState<ValidationTest[]>([]);
  const [results, setResults] = useState<Record<string, ValidationResult>>(storedState.results);
  const [timeline, setTimeline] = useState<ValidationResult[]>(storedState.timeline);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [selected, setSelected] = useState<ValidationResult | ValidationTest | null>(null);
  const [safeError, setSafeError] = useState('');
  const [toastState, setToastState] = useState<ToastState>(null);

  useEffect(() => {
    let active = true;
    async function loadTests() {
      setLoading(true);
      setSafeError('');
      try {
        const response = await fetch(`${API_BASE_URL || ''}/api/admin/security-simulation/tests`, {
          headers: authHeaders(),
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload.success) {
          throw new Error(payload.message || 'Unable to load validation tests.');
        }
        if (active) setTests(Array.isArray(payload.tests) ? payload.tests : []);
      } catch {
        if (active) {
          setSafeError('Security validation service is unavailable. Please make sure the WAF is running.');
        }
      } finally {
        if (active) setLoading(false);
      }
    }
    loadTests();
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!toastState) return;
    if (toastState.type === 'success') toast.success(toastState.message);
    if (toastState.type === 'warning') toast.warning(toastState.message);
    if (toastState.type === 'error') toast.error(toastState.message);
  }, [toastState]);

  useEffect(() => {
    saveStoredValidationState(results, timeline);
  }, [results, timeline]);

  const summary = useMemo(() => {
    const resultList = Object.values(results);
    const passed = resultList.filter((item) => item.passed).length;
    const blocked = resultList.filter((item) => item.passed && item.actual_status === 403).length;
    const backendAuth = resultList.filter((item) => item.passed && item.actual_status === 401).length;
    const rateLimited = resultList.filter((item) => {
      const searchable = [
        item.test_id,
        item.attack_name,
        item.control,
        item.result,
        item.purpose,
        item.description,
      ].join(' ').toLowerCase();
      return (
        item.passed &&
        (item.actual_status === 429 ||
          item.expected_status === 429 ||
          searchable.includes('rate limit') ||
          searchable.includes('brute force') ||
          searchable.includes('brute-force'))
      );
    }).length;
    const total = tests.length;
    let status: OverallStatus = 'Protected';
    if (resultList.length === 0) status = 'Ready';
    else if (passed === 0) status = 'Failed';
    else if (passed < total) status = 'Partial';
    return { total, passed, blocked, backendAuth, rateLimited, status };
  }, [results, tests.length]);

  async function runSimulation(testId: string) {
    setRunning(testId);
    setSafeError('');
    try {
      const response = await fetch(`${API_BASE_URL || ''}/api/admin/security-simulation/run`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ test_id: testId }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.success) {
        throw new Error(payload.message || 'Security validation service is unavailable. Please make sure the WAF is running.');
      }
      const result = payload as ValidationResult;
      setResults((current) => ({ ...current, [result.test_id]: result }));
      setTimeline((current) => [result, ...current].slice(0, MAX_TIMELINE_ITEMS));
      setToastState({
        type: result.passed ? 'success' : 'warning',
        message: result.passed ? 'Simulation completed successfully.' : 'Some protections did not return the expected result.',
      });
    } catch {
      setSafeError('Security validation service is unavailable. Please make sure the WAF is running.');
      setToastState({ type: 'error', message: 'Security validation service is unavailable. Please make sure the WAF is running.' });
    } finally {
      setRunning(null);
    }
  }

  async function runAll() {
    setRunning('all');
    setSafeError('');
    try {
      const response = await fetch(`${API_BASE_URL || ''}/api/admin/security-simulation/run`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ run_all: true }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload.success || !Array.isArray(payload.results)) {
        throw new Error(payload.message || 'Security validation service is unavailable. Please make sure the WAF is running.');
      }
      const nextResults: Record<string, ValidationResult> = {};
      payload.results.forEach((result: ValidationResult) => {
        nextResults[result.test_id] = result;
      });
      setResults(nextResults);
      setTimeline((current) => [...[...payload.results].reverse(), ...current].slice(0, MAX_TIMELINE_ITEMS));
      setToastState({
        type: payload.passed ? 'success' : 'warning',
        message: payload.passed ? 'Simulation completed successfully.' : 'Some protections did not return the expected result.',
      });
    } catch {
      setSafeError('Security validation service is unavailable. Please make sure the WAF is running.');
      setToastState({ type: 'error', message: 'Security validation service is unavailable. Please make sure the WAF is running.' });
    } finally {
      setRunning(null);
    }
  }

  function resetResults() {
    setResults({});
    setTimeline([]);
    setSafeError('');
    clearStoredValidationState();
  }

  const selectedResult = selected && 'passed' in selected ? selected : null;
  const lastRun = timeline[0]?.timestamp;

  return (
    <div className="svl-page">
      <div className="svl-shell">
        <section className="svl-hero">
          <div className="svl-hero-copy">
            <div className="svl-eyebrow">
              <ShieldCheck size={16} />
              Admin-only validation workspace
            </div>
            <h1>Security Validation Lab</h1>
            <p>
              Run safe predefined local simulations to verify that WAF and backend security controls are working.
            </p>
            <div className="svl-hero-badges">
              {['HTTPS Enabled', 'WAF Protected', 'Admin Only', 'Local Simulation'].map((label) => (
                <span key={label}>{label}</span>
              ))}
            </div>
          </div>
          <div className="svl-hero-visual" aria-hidden="true">
            <div className="svl-radar-ring svl-radar-ring-lg" />
            <div className="svl-radar-ring svl-radar-ring-sm" />
            <Radar className="svl-radar" size={156} />
            <div className="svl-shield-core">
              <Shield size={70} />
            </div>
            <span className="svl-orbit svl-orbit-top">WAF online</span>
            <span className="svl-orbit svl-orbit-bottom">Local only</span>
          </div>
        </section>

        {safeError && (
          <section className="svl-warning">
            <AlertTriangle size={26} />
            <div>
              <h2>Validation Service Warning</h2>
              <p>Security validation service is unavailable. Please make sure the WAF is running.</p>
            </div>
          </section>
        )}

        <section className="svl-command-bar">
          <div className="svl-command-meta">
            <span className={`svl-status svl-status-${statusTone(summary.status)}`}>{summary.status}</span>
            <span className="svl-last-run">
              <Activity size={16} />
              Last run: {formatTime(lastRun)}
            </span>
          </div>
          <div className="svl-command-actions">
            <button className="svl-button svl-button-primary" onClick={runAll} disabled={Boolean(running)}>
              {running === 'all' ? <RefreshCcw size={17} className="svl-spin" /> : <Zap size={17} />}
              Run All Tests
            </button>
            <button className="svl-button svl-button-secondary" onClick={resetResults}>
              <RefreshCcw size={17} />
              Reset Results
            </button>
          </div>
        </section>

        <section className="svl-metrics">
          {[
            { label: 'Total Tests', value: summary.total, detail: 'Predefined local checks', icon: Activity, tone: 'cyan' },
            { label: 'Passed Tests', value: summary.passed, detail: 'Controls matched expectations', icon: CheckCircle, tone: 'green' },
            { label: 'Blocked by WAF', value: summary.blocked, detail: 'Edge protections returned 403', icon: ShieldCheck, tone: 'blue' },
            { label: 'Backend Auth Verified', value: summary.backendAuth, detail: 'Trusted origin passed WAF and backend returned 401', icon: Lock, tone: 'violet' },
            { label: 'Rate Limited', value: summary.rateLimited, detail: 'Brute-force protection returned 429', icon: Zap, tone: 'orange' },
          ].map((item) => (
            <motion.div key={item.label} whileHover={{ y: -4 }} className={`svl-metric svl-metric-${item.tone}`}>
              <div>
                <p>{item.label}</p>
                <strong>{item.value}</strong>
                <span>{item.detail}</span>
              </div>
              <div className="svl-metric-icon">
                <item.icon size={25} />
              </div>
            </motion.div>
          ))}
        </section>

        <section className="svl-workspace">
          <div className="svl-main">
            <div className="svl-section-heading">
              <div>
                <h2>Simulation Control Deck</h2>
                <p>Run individual validation cards without exposing raw payload details.</p>
              </div>
              <span>{loading ? 'Loading checks' : `${tests.length} checks loaded`}</span>
            </div>

            {loading ? (
              <div className="svl-simulation-grid">
                {Array.from({ length: 6 }).map((_, index) => (
                  <div key={index} className="svl-card-skeleton" />
                ))}
              </div>
            ) : (
              <div className="svl-simulation-grid">
                {tests.map((test) => {
                  const Icon = ICONS[test.test_id] || ShieldCheck;
                  const result = results[test.test_id];
                  const isRunning = running === test.test_id || running === 'all';
                  const tone = isRunning ? 'running' : resultTone(result);
                  return (
                    <motion.article key={test.test_id} whileHover={{ y: -5 }} className={`svl-sim-card svl-sim-${tone}`}>
                      <div className="svl-sim-header">
                        <div className="svl-attack-icon">
                          <Icon size={24} />
                        </div>
                        <div>
                          <h3>{test.attack_name}</h3>
                          <p>{DESCRIPTIONS[test.test_id] || test.description}</p>
                        </div>
                        <span className={`svl-result-pill svl-result-${tone}`}>
                          {isRunning ? 'Running' : result ? (result.passed ? 'Protected' : 'Failed') : 'Not Run'}
                        </span>
                      </div>

                      <div className="svl-endpoint">
                        <span>Target endpoint</span>
                        <code title={test.target}>{test.method} {test.target}</code>
                      </div>

                      <div className="svl-sim-stats">
                        <div>
                          <span>Expected</span>
                          <strong>HTTP {test.expected_status}</strong>
                        </div>
                        <div>
                          <span>Actual</span>
                          <strong className={result?.passed ? 'svl-good' : result ? 'svl-bad' : ''}>
                            {result ? `HTTP ${result.actual_status ?? 'N/A'}` : 'Pending'}
                          </strong>
                        </div>
                      </div>

                      <div className="svl-control-row">
                        <span>{test.control}</span>
                        <span>{result ? (result.passed ? 'Expected behavior verified' : 'Needs review') : 'Awaiting run'}</span>
                      </div>

                      <div className="svl-card-actions">
                        <button className="svl-button svl-card-run" onClick={() => runSimulation(test.test_id)} disabled={Boolean(running)}>
                          {isRunning ? <RefreshCcw size={16} className="svl-spin" /> : <Zap size={16} />}
                          Run Test
                        </button>
                        <button className="svl-button svl-card-details" onClick={() => setSelected(result || test)}>
                          <Eye size={16} />
                          View Details
                        </button>
                      </div>
                    </motion.article>
                  );
                })}
              </div>
            )}
          </div>

          <aside className="svl-side">
            <section className="svl-timeline">
              <div className="svl-panel-heading">
                <div>
                  <h2>Latest Validation Timeline</h2>
                  <p>Session results with sanitized status metadata.</p>
                </div>
                <Activity size={22} />
              </div>

              {timeline.length === 0 ? (
                <div className="svl-empty">
                  <Activity size={42} />
                  <h3>No simulations have been run yet.</h3>
                  <p>Run a validation test to see results here.</p>
                </div>
              ) : (
                <div className="svl-timeline-list">
                  {timeline.map((item, index) => (
                    <div key={`${item.test_id}-${item.timestamp}-${index}`} className="svl-timeline-row">
                      <span className={`svl-dot ${item.passed ? 'svl-dot-good' : 'svl-dot-bad'}`} />
                      <div>
                        <strong>{item.attack_name}</strong>
                        <span>{formatTime(item.timestamp)}</span>
                      </div>
                      <em>HTTP {item.actual_status ?? 'N/A'}</em>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="svl-safety">
              <ShieldCheck size={28} />
              <div>
                <h2>Safety Boundary</h2>
                <p>
                  Security Validation Lab runs predefined local simulations only. It does not target external systems and does not allow custom payload input.
                </p>
              </div>
            </section>

            <section className="svl-scope">
              <Server size={24} />
              <div>
                <h2>Control Scope</h2>
                <p>Admin-only UI for WAF and backend control verification.</p>
              </div>
            </section>
          </aside>
        </section>
      </div>

      {selected && (
        <div className="svl-modal-overlay">
          <button className="svl-modal-scrim" aria-label="Close details" onClick={() => setSelected(null)} />
          <motion.section
            initial={{ opacity: 0, scale: 0.96, y: 12 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            className="svl-modal"
          >
            <button className="svl-modal-close" onClick={() => setSelected(null)} aria-label="Close details">
              <X size={22} />
            </button>
            <span className="svl-modal-badge">Sanitized validation details</span>
            <h2>{selected.attack_name}</h2>
            <p className="svl-modal-subtitle">Raw payloads are intentionally hidden. This view only shows safe summaries and control metadata.</p>

            <div className="svl-modal-section">
              <span>Purpose</span>
              <p>{safeSummary(selected.purpose)}</p>
            </div>

            <div className="svl-modal-grid">
              <div>
                <span>Target Endpoint</span>
                <code>{selected.method} {selected.target}</code>
              </div>
              <div>
                <span>Security Control</span>
                <p>{selected.control}</p>
              </div>
              <div>
                <span>Expected Status</span>
                <p>HTTP {selected.expected_status}</p>
              </div>
              <div>
                <span>Actual Status</span>
                <p>{selectedResult ? `HTTP ${selectedResult.actual_status ?? 'N/A'}` : 'Not run yet'}</p>
              </div>
            </div>

            <div className={`svl-modal-result ${selectedResult ? (selectedResult.passed ? 'svl-modal-good' : 'svl-modal-bad') : 'svl-modal-neutral'}`}>
              {selectedResult ? (
                selectedResult.passed ? <CheckCircle size={22} /> : <XCircle size={22} />
              ) : (
                <Activity size={22} />
              )}
              <div>
                <h3>Result Explanation</h3>
                <p>{selectedResult ? safeSummary(selectedResult.explanation || selectedResult.result) : safeSummary(selected.expected_behavior)}</p>
              </div>
            </div>

            <div className="svl-modal-note">
              <Lock size={21} />
              <p>This modal shows sanitized summaries only. Custom payload input and external targeting are not available in this lab.</p>
            </div>
          </motion.section>
        </div>
      )}
    </div>
  );
}
