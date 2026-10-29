import React, { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { X, AlertTriangle, CheckCircle, ExternalLink, Loader, ArrowLeft, Plug } from 'lucide-react';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';

const SEVERITY_OPTIONS = [
  { value: 'P0', label: 'P0 — Critical' },
  { value: 'P1', label: 'P1 — High' },
  { value: 'P2', label: 'P2 — Medium' },
  { value: 'P3', label: 'P3 — Low' },
  { value: 'P4', label: 'P4 — Info' },
];

// ── Jira connector check ──────────────────────────────────────────────────────

function useJiraConnector() {
  const [connector, setConnector] = useState(undefined); // undefined = loading
  const apiClient = createApiClient();

  const check = useCallback(async () => {
    setConnector(undefined);
    try {
      const data = await apiClient.get('/connectors');
      const jira = (data.connectors || []).find((c) => c.type === 'jira' && c.enabled);
      setConnector(jira || null);
    } catch {
      setConnector(null);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return { connector, check };
}

// ── Not-connected prompt ──────────────────────────────────────────────────────

function JiraNotConnected({ onClose, onConnected }) {
  return (
    <div className="flex flex-col items-center justify-center h-full py-10 px-6 text-center gap-4">
      <Plug className="h-12 w-12 text-gray-400" />
      <h3 className="text-base font-semibold text-gray-900 dark:text-white">Jira not connected</h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 max-w-xs">
        Connect your Jira instance in <strong>Connectors</strong> to create tickets directly from scan findings.
      </p>
      <div className="flex gap-3">
        <a
          href="/connectors"
          target="_blank"
          rel="noopener noreferrer"
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium flex items-center gap-2"
          onClick={() => {
            // After they open connectors, poll until connected
            const poll = setInterval(async () => {
              try {
                const apiClient = createApiClient();
                const data = await apiClient.get('/connectors');
                const jira = (data.connectors || []).find((c) => c.type === 'jira' && c.enabled);
                if (jira) { clearInterval(poll); onConnected(); }
              } catch { /* ignore */ }
            }, 3000);
            setTimeout(() => clearInterval(poll), 120000); // stop after 2 min
          }}
        >
          <ExternalLink className="h-4 w-4" />
          Set up Jira connector
        </a>
        <button
          onClick={onClose}
          className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Shared form logic ─────────────────────────────────────────────────────────

function useTicketForm({ finding, serverName, toolName, source, connector }) {
  const { user } = useAuth();
  const apiClient = createApiClient();

  const [loading, setLoading] = useState(false);
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('P1');
  const [projectKey, setProjectKey] = useState('');
  const [assignee, setAssignee] = useState('');
  const [remarks, setRemarks] = useState('');
  const [ticketUrl, setTicketUrl] = useState(null);
  const [ticketKey, setTicketKey] = useState(null);

  useEffect(() => {
    setTicketUrl(null);
    setTicketKey(null);
    if (serverName && toolName) setTitle(`${serverName} — ${toolName}`);
    else if (serverName) setTitle(serverName);
    else if (finding?.vulnerability_type) setTitle(finding.vulnerability_type);
    const severityMap = { critical: 'P0', high: 'P1', medium: 'P2', low: 'P3', info: 'P4' };
    setSeverity(severityMap[(finding?.severity || '').toLowerCase()] || 'P1');
    if (finding?.description) setRemarks(finding.description);
    if (connector?.config?.project_key) setProjectKey(connector.config.project_key);
  }, [finding, serverName, toolName, connector]);

  const getReporter = () => {
    if (user?.id && user.id !== 'local-user') return user.id;
    if (user?.email) return user.email.split('@')[0];
    return user?.name || 'triksha-user';
  };

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const response = await apiClient.post('/jira/ticket', {
        title,
        vulnerability_type: finding?.vulnerability_type || finding?.attack_type || 'Security Vulnerability',
        severity,
        project_key: projectKey,
        tool_name: toolName,
        server_name: serverName,
        scan_name: finding?.scan_name,
        payload: finding?.payload,
        response: finding?.response,
        details: finding?.details,
        recommendation: finding?.recommendation,
        remarks: remarks || undefined,
        assignee: assignee || undefined,
        reporter: getReporter(),
        source: source || 'scan',
      });

      if (response.status === 'success') {
        setTicketUrl(response.ticket_url);
        setTicketKey(response.ticket_key);
        toast.success(`Ticket ${response.ticket_key} created`);
      } else {
        toast.error(response.error || 'Failed to create ticket');
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || error.message);
    } finally {
      setLoading(false);
    }
  };

  return { loading, title, setTitle, severity, setSeverity, projectKey, setProjectKey, assignee, setAssignee, remarks, setRemarks, ticketUrl, ticketKey, submit };
}

// ── Success screen ────────────────────────────────────────────────────────────

function TicketCreated({ ticketKey, ticketUrl, onClose, onBack }) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 p-6 text-center gap-4">
      <CheckCircle className="h-14 w-14 text-green-500" />
      <h2 className="text-xl font-bold text-gray-900 dark:text-white">Ticket created</h2>
      <div className="bg-gray-50 dark:bg-gray-900 rounded-lg px-6 py-3">
        <p className="text-xs text-gray-500 mb-1">Ticket ID</p>
        <p className="text-lg font-mono font-bold text-primary-600 dark:text-primary-400">{ticketKey}</p>
      </div>
      <div className="flex gap-3">
        <a href={ticketUrl} target="_blank" rel="noopener noreferrer"
          className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm flex items-center gap-2">
          <ExternalLink className="h-4 w-4" /> View in Jira
        </a>
        <button onClick={onClose || onBack}
          className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 text-sm">
          Close
        </button>
      </div>
    </div>
  );
}

// ── Form fields (shared by modal and inline) ──────────────────────────────────

function TicketFormFields({ finding, serverName, toolName, form, compact = false }) {
  const { title, setTitle, severity, setSeverity, projectKey, setProjectKey, assignee, setAssignee, remarks, setRemarks, loading, ticketUrl, ticketKey, submit } = form;

  const inputCls = `w-full px-2.5 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg
    bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-primary-500 focus:border-transparent`;

  return (
    <form onSubmit={submit} className={`flex flex-col gap-3 ${compact ? '' : 'p-5'} flex-1 overflow-y-auto`}>
      {/* Vulnerability summary */}
      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs bg-gray-50 dark:bg-gray-900/50 rounded-lg p-3 border border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-1.5">
          <span className="text-gray-500">Type:</span>
          <span className="font-medium text-gray-900 dark:text-white truncate">
            {finding?.vulnerability_type || finding?.attack_type || '—'}
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-gray-500">Severity:</span>
          <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${
            finding?.severity === 'critical' ? 'bg-red-600 text-white' :
            finding?.severity === 'high' ? 'bg-orange-500 text-white' :
            finding?.severity === 'medium' ? 'bg-yellow-500 text-black' :
            'bg-blue-500 text-white'}`}>
            {(finding?.severity || 'medium').toUpperCase()}
          </span>
        </div>
        {serverName && <div className="flex items-center gap-1.5 col-span-2"><span className="text-gray-500">Source:</span><span className="font-medium text-gray-900 dark:text-white truncate">{serverName}{toolName ? ` / ${toolName}` : ''}</span></div>}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Ticket Title <span className="text-red-500">*</span>
          </label>
          <input type="text" value={title} onChange={(e) => setTitle(e.target.value)}
            className={inputCls} placeholder="e.g., Prompt injection in customer chatbot" required />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Severity <span className="text-red-500">*</span>
          </label>
          <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={inputCls} required>
            {SEVERITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
            Project Key <span className="text-red-500">*</span>
          </label>
          <input type="text" value={projectKey} onChange={(e) => setProjectKey(e.target.value.toUpperCase())}
            className={inputCls} placeholder="e.g., SEC" required />
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
          Assignee <span className="text-gray-400">(email, optional)</span>
        </label>
        <input type="email" value={assignee} onChange={(e) => setAssignee(e.target.value)}
          className={inputCls} placeholder="security@yourorg.com" />
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Additional notes</label>
        <textarea value={remarks} onChange={(e) => setRemarks(e.target.value)} rows={3}
          className={`${inputCls} resize-none font-mono text-xs`}
          placeholder="Any additional context…" />
      </div>

      <div className="text-xs text-gray-500 dark:text-gray-400 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-2">
        Payload, response, and recommendations will be auto-included in the ticket description.
      </div>

      <div className="flex gap-3 pt-1">
        <button type="submit" disabled={loading}
          className="flex-1 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 text-sm font-medium
            disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2">
          {loading ? <><Loader className="h-4 w-4 animate-spin" /> Creating…</> : 'Create Ticket'}
        </button>
      </div>
    </form>
  );
}

// ── Modal version (used from ScanResultsModal) ────────────────────────────────

const SecbugModal = ({ isOpen, onClose, finding, serverName, toolName, source }) => {
  const { connector, check } = useJiraConnector();
  const form = useTicketForm({ finding, serverName, toolName, source, connector });

  useEffect(() => { if (isOpen) check(); }, [isOpen, check]);

  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[300] p-4 modal-backdrop-in">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-xl w-full max-h-[85vh] flex flex-col modal-panel-in">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500" />
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Raise Ticket</h2>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        {connector === undefined && (
          <div className="flex items-center justify-center py-12">
            <Loader className="h-6 w-6 animate-spin text-gray-400" />
          </div>
        )}
        {connector === null && <JiraNotConnected onClose={onClose} onConnected={check} />}
        {connector && form.ticketUrl && (
          <TicketCreated ticketKey={form.ticketKey} ticketUrl={form.ticketUrl} onClose={onClose} />
        )}
        {connector && !form.ticketUrl && (
          <TicketFormFields finding={finding} serverName={serverName} toolName={toolName} form={form} compact />
        )}
      </div>
    </div>,
    document.body
  );
};

// ── Inline version (used in sliding panels — AgentScanDAG, MCPSecurityModal) ──

export const SecbugForm = ({ finding, serverName, toolName, source, onBack, onSuccess }) => {
  const { connector, check } = useJiraConnector();
  const form = useTicketForm({ finding, serverName, toolName, source, connector });

  useEffect(() => { check(); }, [check]);

  useEffect(() => {
    if (form.ticketKey && onSuccess) onSuccess(form.ticketKey, form.ticketUrl);
  }, [form.ticketKey]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
        <button onClick={onBack} className="p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors">
          <ArrowLeft className="h-5 w-5 text-gray-600 dark:text-gray-400" />
        </button>
        <AlertTriangle className="h-5 w-5 text-red-500" />
        <h2 className="text-base font-semibold text-gray-900 dark:text-white">Raise Ticket</h2>
      </div>

      {connector === undefined && (
        <div className="flex items-center justify-center flex-1">
          <Loader className="h-6 w-6 animate-spin text-gray-400" />
        </div>
      )}
      {connector === null && <JiraNotConnected onClose={onBack} onConnected={check} />}
      {connector && form.ticketUrl && (
        <TicketCreated ticketKey={form.ticketKey} ticketUrl={form.ticketUrl} onBack={onBack} />
      )}
      {connector && !form.ticketUrl && (
        <div className="flex-1 flex flex-col overflow-y-auto p-4">
          <TicketFormFields finding={finding} serverName={serverName} toolName={toolName} form={form} />
        </div>
      )}
    </div>
  );
};

export default SecbugModal;
