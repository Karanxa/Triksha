import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import { 
  Bot, Play, Clock, CheckCircle, AlertTriangle,
  XCircle, Eye, RefreshCw, Target, Trash2,
  Shield, X, Activity, Info, ChevronLeft, ChevronRight,
  Wrench, Globe, Cpu, Send, MessageSquare, Lock, Puzzle, Link2, Workflow, Users,
  Monitor, ShieldCheck, ShieldAlert, ShieldOff, Terminal, FileCode, Package, Code2,
  ClipboardCopy, Zap, Filter, ChevronDown, ChevronUp, ExternalLink, Radio, StopCircle,
  Plus, Save, Settings, FileText, AlertCircle
} from 'lucide-react';
import toast from 'react-hot-toast';
import AgentScanDAG from '../components/AgentScanDAG';
import LockedOverlay from '../components/LockedOverlay';

// Agent development type options
const AGENT_DEV_TYPES = [
  { value: 'standalone', label: 'Standalone', description: 'Custom-built agent with its own endpoint', icon: Bot, enabled: true },
  { value: 'google-agent-builder', label: 'Google Agent Builder', description: 'Agents built with Google Agent Builder', icon: Cpu, enabled: false },
];

// Agentic framework options
const FRAMEWORK_OPTIONS = [
  { value: 'adk', label: 'ADK', description: 'Google Agent Development Kit', icon: Puzzle, enabled: true },
  { value: 'autogen', label: 'AutoGen', description: 'Microsoft AutoGen Framework', icon: Workflow, enabled: true },
  { value: 'langchain', label: 'LangChain', description: 'LangChain Agent Framework', icon: Link2, enabled: true },
  { value: 'crewai', label: 'CrewAI', description: 'CrewAI multi-agent framework', icon: Users, enabled: false },
];

// Hosting platform options
const HOSTING_OPTIONS = [
  { value: 'gcp', label: 'GCP (Google Cloud Platform)', enabled: true },
  { value: 'aws', label: 'AWS', enabled: false },
  { value: 'azure', label: 'Azure', enabled: false },
];

const Agents = () => {
  const { user, isAdmin, canViewAllScans, hasPermission, canAccessScan } = useAuth();
  const apiClient = createApiClient();
  const location = useLocation();

  // Tab state
  const [activeTab, setActiveTab] = useState('new-scan');
  
  // Predefined agents
  const [predefinedAgents, setPredefinedAgents] = useState([]);

  // Scans state
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [softRefreshing, setSoftRefreshing] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);
  const [actionBusy, setActionBusy] = useState({});

  // Past scans filters
  const [pastSearch, setPastSearch] = useState('');
  const [pastStatus, setPastStatus] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  // Ownership classification for Past Scans (My Scans / Other Scans)
  const [pastSubTab, setPastSubTab] = useState('my-scans');
  const SCANS_PER_PAGE = 20;
  
  // Polling
  const listPollRef = useRef(null);

  // Test modal state
  const [showTestModal, setShowTestModal] = useState(false);
  const [testModalScan, setTestModalScan] = useState(null);
  const [testPrompt, setTestPrompt] = useState('');
  const [testMessages, setTestMessages] = useState([]);
  const [testProcessing, setTestProcessing] = useState(false);
  
  // Scan info modal
  const [showScanInfoModal, setShowScanInfoModal] = useState(false);
  const [scanInfoData, setScanInfoData] = useState(null);

  // Onboarded agent detail modal
  const [showAgentDetailModal, setShowAgentDetailModal] = useState(false);
  const [agentDetailData, setAgentDetailData] = useState(null);

  // Live view state (DAG — works for both live and historical scans)
  const [liveViewScan, setLiveViewScan] = useState(null);

  // Scan mode toggle: 'new-agent' (default) vs 'onboarded'
  const [scanMode, setScanMode] = useState('new-agent');
  // When the user is on the My Agents sub-tab, clicking a card selects it
  // (instead of immediately starting a scan). The Scan Agent button in the
  // card header then triggers the scan against this selection.
  const [selectedCustomAgentId, setSelectedCustomAgentId] = useState(null);
  // Whether to also save the new agent config when scanning
  const [saveOnScan, setSaveOnScan] = useState(true);

  // Custom agent config modal
  const [showCustomAgentModal, setShowCustomAgentModal] = useState(false);
  const [customAgentForm, setCustomAgentForm] = useState({
    name: '',
    curl: '',
    agent_context: '',
  });

  // ---- cURL parser: extracts endpoint, headers, body from a cURL command ----
  const parseCurl = (curlStr) => {
    const result = { endpoint: '', headers: {}, body: '', method: 'POST' };
    if (!curlStr || !curlStr.trim()) return result;

    // Normalise: collapse escaped newlines and continuations
    let s = curlStr.replace(/\\\n/g, ' ').replace(/\\\r\n/g, ' ').trim();

    // Remove leading "curl" if present
    if (s.toLowerCase().startsWith('curl')) s = s.slice(4).trim();

    // Extract URL — either quoted or first bare token that looks like a URL
    const urlPatterns = [
      /['"]?(https?:\/\/[^\s'"]+)['"]?/,   // http(s)://...
    ];
    for (const p of urlPatterns) {
      const m = s.match(p);
      if (m) { result.endpoint = m[1]; break; }
    }

    // Extract -X / --request method
    const methodMatch = s.match(/(?:-X|--request)\s+['"]?(\w+)['"]?/i);
    if (methodMatch) result.method = methodMatch[1].toUpperCase();

    // Extract headers: -H 'Key: Value' or --header 'Key: Value'
    const headerRegex = /(?:-H|--header)\s+['"]([^'"]+)['"]/gi;
    let hm;
    while ((hm = headerRegex.exec(s)) !== null) {
      const colon = hm[1].indexOf(':');
      if (colon > 0) {
        const key = hm[1].slice(0, colon).trim();
        const val = hm[1].slice(colon + 1).trim();
        if (key.toLowerCase() !== 'content-type') {   // skip content-type, we set it ourselves
          result.headers[key] = val;
        }
      }
    }

    // Extract body: -d / --data / --data-raw / --data-binary
    const bodyRegex = /(?:-d|--data-raw|--data-binary|--data)\s+'((?:[^'\\]|\\.)*)'/g;
    const bodyRegex2 = /(?:-d|--data-raw|--data-binary|--data)\s+"((?:[^"\\]|\\.)*)"/g;
    let bm = bodyRegex.exec(s) || bodyRegex2.exec(s);
    if (bm) result.body = bm[1];

    return result;
  };
  // ---- Reconstruct a cURL command from saved agent config fields ----
  const buildCurlFromAgent = (agent) => {
    if (!agent) return '';
    const endpoint = agent.endpoint || '';
    const headers = agent.headers || {};
    const bodyTemplate = agent.request_body_template || '';

    let parts = [`curl --location '${endpoint}'`];

    // Add headers
    Object.entries(headers).forEach(([key, value]) => {
      parts.push(`--header '${key}: ${value}'`);
    });

    // Always add Content-Type if there's a body
    if (bodyTemplate) {
      if (!Object.keys(headers).some(k => k.toLowerCase() === 'content-type')) {
        parts.push("--header 'Content-Type: application/json'");
      }
      parts.push(`--data '${bodyTemplate}'`);
    }

    return parts.join(' \\\n');
  };

  const [savingCustomAgent, setSavingCustomAgent] = useState(false);
  const [deletingAgentId, setDeletingAgentId] = useState(null);

  // ------ Data Fetching ------
  const loadScans = async (soft = false) => {
    if (soft) setSoftRefreshing(true);
    else setListLoading(true);
    try {
      // On the Past Scans tab, fetch only the ownership scope the UI is
      // currently filtering for — backend handles the split.
      const params = new URLSearchParams({ limit: '100' });
      if (activeTab === 'past-scans') {
        params.set('scope', pastSubTab === 'my-scans' ? 'mine' : 'others');
      }
      const data = await apiClient.get(`/agents/scans?${params.toString()}`);
      if (Array.isArray(data)) setScans(data);
    } catch (err) {
      console.warn('Failed to load agent scans', err);
    } finally {
      setListLoading(false);
      setSoftRefreshing(false);
    }
  };

  // Predefined agents only need to load once.
  useEffect(() => {
    loadPredefinedAgents();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Re-fetch AND restart the 5s poll whenever the user flips the tab or
  // ownership scope. Without restarting the interval, the polling closure
  // would keep using the initial `pastSubTab`, silently overwriting freshly
  // fetched "other-scans" data with stale "my-scans" data every tick.
  useEffect(() => {
    loadScans();
    listPollRef.current = setInterval(() => loadScans(true), 5000);
    return () => clearInterval(listPollRef.current);
  }, [activeTab, pastSubTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // Deep-link: ?highlight=<scan_id> — switch to past-scans and open that scan's detail modal
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const highlightId = params.get('highlight');
    if (!highlightId) return;
    window.history.replaceState({}, document.title, location.pathname);
    setActiveTab('past-scans');
    apiClient.get(`/agents/scan/${highlightId}`)
      .then(res => {
        if (res && res.scan_id) {
          setScanInfoData(res);
          setShowScanInfoModal(true);
        }
      })
      .catch(() => {});
  }, [location.search]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadPredefinedAgents = async () => {
    try {
      const data = await apiClient.get('/agents/predefined');
      if (data && data.agents) {
        setPredefinedAgents(data.agents);
      }
    } catch (err) {
      console.warn('Failed to load predefined agents', err);
    }
  };

  // ------ Computed lists ------
  // "My Agents" — only the current user's own onboarded agents. We filter by
  // created_by (set at save time as user.email || user.id) so each user only
  // sees the agents they themselves added.
  const customAgents = useMemo(() => {
    const me = user?.email || user?.id || 'unknown';
    return predefinedAgents.filter(a => a.is_custom && a.created_by === me);
  }, [predefinedAgents, user]);

  const activeScans = useMemo(() =>
    scans.filter(s => ['queued', 'running', 'pending'].includes(s.status)),
    [scans]
  );

  // Ownership match for agent scans (created_by matches current user)
  const isMyAgentScan = (s) => {
    const cb = String(s?.created_by || '').toLowerCase();
    if (!cb) return false;
    if (user?.email && cb === String(user.email).toLowerCase()) return true;
    if (user?.id && cb === String(user.id).toLowerCase()) return true;
    return false;
  };

  const pastScans = useMemo(() => {
    // Ownership scope is applied at the API layer via ?scope=. The list
    // returned by the server already matches the chosen sub-tab.
    let list = scans.filter(s => ['completed', 'failed', 'cancelled', 'error'].includes(s.status));
    if (pastSearch) {
      const q = pastSearch.toLowerCase();
      list = list.filter(s =>
        (s.agent_name || '').toLowerCase().includes(q) ||
        (s.scan_id || '').toLowerCase().includes(q)
      );
    }
    if (pastStatus !== 'all') {
      list = list.filter(s => s.status === pastStatus);
    }
    return list;
  }, [scans, pastSearch, pastStatus, pastSubTab, user]); // eslint-disable-line react-hooks/exhaustive-deps

  const totalPages = Math.ceil(pastScans.length / SCANS_PER_PAGE);
  const paginatedPastScans = pastScans.slice(
    (currentPage - 1) * SCANS_PER_PAGE,
    currentPage * SCANS_PER_PAGE
  );

  // ------ Helpers ------
  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'running': return <Activity className="h-5 w-5 text-blue-500 animate-pulse" />;
      case 'queued':
      case 'pending': return <Clock className="h-5 w-5 text-yellow-500" />;
      case 'failed':
      case 'error': return <XCircle className="h-5 w-5 text-red-500" />;
      case 'cancelled': return <XCircle className="h-5 w-5 text-gray-400" />;
      default: return <Clock className="h-5 w-5 text-gray-400" />;
    }
  };

  const getStatusBadge = (status) => {
    const colors = {
      completed: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
      running: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
      queued: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
      pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
      failed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
      error: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
      cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
    };
    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colors[status] || colors.cancelled}`}>
        {status}
      </span>
    );
  };

  // ------ Test Agent ------
  const sendTestMessage = async () => {
    if (!testPrompt.trim() || testProcessing) return;
    const prompt = testPrompt.trim();
    setTestPrompt('');
    setTestMessages(prev => [...prev, { role: 'user', content: prompt }]);
    setTestProcessing(true);

    try {
      const res = await apiClient.post(`/agents/test`, {
        scan_id: testModalScan?.scan_id,
        prompt,
        endpoint: testModalScan?.agent_endpoint,
      });
      setTestMessages(prev => [...prev, {
        role: 'assistant',
        content: res?.response || JSON.stringify(res, null, 2)
      }]);
    } catch (err) {
      setTestMessages(prev => [...prev, {
        role: 'error',
        content: err?.message || 'Failed to get response from agent'
      }]);
    } finally {
      setTestProcessing(false);
    }
  };

  // ------ Delete Scan ------
  const deleteScan = async (scanId) => {
    if (actionBusy[scanId]) return;
    setActionBusy(prev => ({ ...prev, [scanId]: true }));
    try {
      await apiClient.delete(`/agents/scan/${scanId}`);
      toast.success('Scan deleted');
      loadScans();
    } catch (err) {
      toast.error('Failed to delete scan');
    } finally {
      setActionBusy(prev => ({ ...prev, [scanId]: false }));
    }
  };

  // ------ Cancel Running Scan ------
  const cancelScan = async (scanId) => {
    if (actionBusy[scanId]) return;
    setActionBusy(prev => ({ ...prev, [scanId]: true }));
    try {
      await apiClient.post(`/agents/scan/${scanId}/cancel`);
      toast.success('Scan cancellation requested');
      loadScans();
    } catch (err) {
      toast.error(err?.message || 'Failed to cancel scan');
    } finally {
      setActionBusy(prev => ({ ...prev, [scanId]: false }));
    }
  };
    
  // ------ Helper: build save payload from cURL form (standalone mode) ------
  const buildPayloadFromForm = () => {
    const parsed = parseCurl(customAgentForm.curl);
    if (!parsed.endpoint) return null;

    const bodyTemplate = parsed.body || '';
    if (!bodyTemplate) {
      toast.error('Missing request body — add a -d flag with __PROMPT__ where the prompt should go.');
      return null;
    }
    if (!bodyTemplate.includes('__PROMPT__')) {
      toast.error('Add __PROMPT__ in your cURL body to mark where the prompt text goes.');
      return null;
    }

    return {
      name: customAgentForm.name.trim(),
      description: '',
      endpoint: parsed.endpoint,
      headers: Object.keys(parsed.headers).length > 0 ? parsed.headers : {},
      request_body_template: bodyTemplate,
      response_json_path: '',
      protocol: 'simple',
      init_endpoint: '',
      hosting_platform: 'custom',
      agent_context: customAgentForm.agent_context.trim(),
    };
  };

  const resetForm = () => setCustomAgentForm({ name: '', curl: '', agent_context: '' });

  // ------ Save Custom Agent to My Agents ------
  const saveCustomAgent = async () => {
    const payload = buildPayloadFromForm();
    if (!customAgentForm.name.trim() || !payload) {
      if (!customAgentForm.name.trim()) {
        toast.error('Please provide an agent name.');
      } else {
        toast.error('Please provide a valid cURL command with __PROMPT__ in the body.');
      }
      return;
    }
    setSavingCustomAgent(true);
    try {
      await apiClient.post('/agents/predefined', payload);
      toast.success(`"${payload.name}" added to My Agents`);
      setShowCustomAgentModal(false);
      resetForm();
      loadPredefinedAgents();
    } catch (err) {
      toast.error(err?.message || 'Failed to save custom agent');
    } finally {
      setSavingCustomAgent(false);
    }
  };

  // ------ Scan a previously-onboarded custom agent (from My Agents) ------
  const scanFromCustomAgent = async (agent) => {
    if (!agent) {
      toast.error('Select an agent first.');
      return;
    }
    setLoading(true);
    try {
      const payload = {
        custom_agent_id: agent.id,
        agent_name: agent.name,
        framework: agent.framework,
        agent_context: agent.agent_context || undefined,
        created_by: user?.email || user?.id || 'unknown',
      };
      await apiClient.post('/agents/scan', payload);
      toast.success(`${agent.name} scan started`);
      setActiveTab('scans');
      await loadScans();
    } catch (err) {
      toast.error(err?.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  // ------ Scan New Agent (from inline form) ------
  const scanNewAgent = async () => {
    const payload = buildPayloadFromForm();
    if (!customAgentForm.name.trim() || !payload) {
      if (!customAgentForm.name.trim()) {
        toast.error('Please provide an agent name.');
      } else {
        toast.error('Please provide a valid cURL command with __PROMPT__ in the body.');
      }
      return;
    }

    setLoading(true);
    try {
      // Optionally save as onboarded agent first
      let savedAgentId = null;
      if (saveOnScan) {
        const saveResult = await apiClient.post('/agents/predefined', payload);
        savedAgentId = saveResult?.id || saveResult?.config_id;
        loadPredefinedAgents();
      }

      // Start the scan — send curl_config directly (no endpoint discovery)
      const scanPayload = {
        agent_name: payload.name,
        curl_config: {
          endpoint: payload.endpoint,
          headers: payload.headers || {},
          request_body_template: payload.request_body_template,
          response_json_path: payload.response_json_path || '',
        },
        agent_context: payload.agent_context || undefined,
        created_by: user?.email || user?.id || 'unknown',
        ...(savedAgentId ? { custom_agent_id: savedAgentId } : {}),
      };

      await apiClient.post('/agents/scan', scanPayload);
      toast.success(`${payload.name} scan started${saveOnScan ? ' & saved to My Agents' : ''}`);

      resetForm();
      setActiveTab('scans');
      await loadScans();
    } catch (err) {
      toast.error(err?.message || 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  // ------ Delete Custom Agent from My Agents ------
  const deleteCustomAgent = async (agentId, agentName) => {
    if (deletingAgentId) return;
    setDeletingAgentId(agentId);
    try {
      await apiClient.delete(`/agents/predefined/${agentId}`);
      toast.success(`"${agentName}" removed from My Agents`);
      loadPredefinedAgents();
    } catch (err) {
      toast.error(err?.message || 'Failed to delete agent config');
    } finally {
      setDeletingAgentId(null);
    }
  };
    
    return (
    <div className="space-y-3">
      {/* Header Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Agent Security Scanner</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
              Evaluate the security posture of your GenAI agents
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-primary-600 dark:text-primary-400" />
          </div>
        </div>
              </div>
              
      {/* Tab Navigation */}
        <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('new-scan')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'new-scan'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
            New Scan
            </button>
            <button
            onClick={() => setActiveTab('scans')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'scans'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
              }`}
            >
            Active Scans
            {activeScans.length > 0 && (
              <span className="ml-2 inline-flex items-center justify-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
                {activeScans.length}
                  </span>
                )}
          </button>
          <button
            onClick={() => setActiveTab('past-scans')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'past-scans'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
            }`}
          >
            Past Scans
            </button>
          </nav>
              </div>
              
      {/* Card Content */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
        <div className="p-4">

          {/* ==================== NEW SCAN TAB ==================== */}
        {activeTab === 'new-scan' && (
            <div className="space-y-3">
              {/* Header — Scan Agent action moved here (top-right) so the card
                  doesn't need a tall bottom action row. Only shown in the
                  New Agent form mode; My Agents mode triggers scans by row
                  click. */}
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-3">
                  <Bot className="h-6 w-6 text-primary-600 dark:text-primary-400" />
              <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Scan Agent</h2>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Scan your saved agents or configure a new one</p>
                  </div>
              </div>
              {(() => {
                // Resolve the click handler + disabled state per mode.
                // New Agent  → submit the inline form (needs name + cURL)
                // My Agents  → scan the currently selected card (needs a selection)
                const selectedAgent = customAgents.find(a => a.id === selectedCustomAgentId) || null;
                const isOnboarded = scanMode === 'onboarded';
                const disabled = loading || (
                  isOnboarded
                    ? !selectedAgent
                    : (!customAgentForm.name.trim() || !customAgentForm.curl.trim())
                );
                const onClick = () => isOnboarded
                  ? scanFromCustomAgent(selectedAgent)
                  : scanNewAgent();
                const buttonTitle = isOnboarded && !selectedAgent
                  ? 'Select an agent below first'
                  : '';
                return (
                  <div className="flex flex-col items-end gap-1.5">
                    <button
                      onClick={onClick}
                      disabled={disabled}
                      title={buttonTitle}
                      className="inline-flex items-center px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors shadow-sm"
                    >
                      {loading ? (
                        <>
                          <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full mr-2" />
                          Starting…
                        </>
                      ) : (
                        <>
                          <Play className="h-4 w-4 mr-2" />
                          Scan Agent
                        </>
                      )}
                    </button>
                    {!isOnboarded && (
                      <label className="flex items-center gap-2 text-xs text-gray-600 dark:text-gray-400 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={saveOnScan}
                          onChange={(e) => setSaveOnScan(e.target.checked)}
                          className="rounded border-gray-300 dark:border-gray-600 text-primary-600 focus:ring-primary-500"
                        />
                        Save to My Agents
                      </label>
                    )}
                  </div>
                );
              })()}
            </div>
            
              {/* Sub-toggle: New Agent / My Agents — underline style matching main tabs */}
              <div className="border-b border-gray-200 dark:border-gray-700 -mt-2">
                <nav className="-mb-px flex space-x-6">
            <button
                        type="button"
                    onClick={() => setScanMode('new-agent')}
                    className={`pb-2.5 border-b-2 text-sm font-medium transition-colors flex items-center gap-1.5 ${
                      scanMode === 'new-agent'
                        ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                        : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    New Agent
            </button>
            <button
                        type="button"
                    onClick={() => setScanMode('onboarded')}
                    className={`pb-2.5 border-b-2 text-sm font-medium transition-colors flex items-center gap-1.5 ${
                      scanMode === 'onboarded'
                        ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                        : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                  >
                    <Zap className="h-3.5 w-3.5" />
                    My Agents
                    {customAgents.length > 0 && (
                      <span className="inline-flex items-center justify-center px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300">
                        {customAgents.length}
                    </span>
                )}
            </button>
                </nav>
        </div>
            
              {/* ===== ONBOARDED AGENTS MODE ===== */}
              {scanMode === 'onboarded' && (
              <div className="bg-gradient-to-br from-primary-50 to-blue-50 dark:from-primary-900/20 dark:to-blue-900/20 border-2 border-primary-200 dark:border-primary-800 rounded-xl p-3">
                <p className="text-xs text-gray-600 dark:text-gray-300 mb-2.5">
                  Click any saved agent to instantly start a security scan. Switch to <strong>New Agent</strong> to onboard a new one.
                </p>

                {/* Compact horizontal pill rows — radio-style selection.
                    Each pill: icon + name (single line, truncated) + hover
                    actions on the far right. Multiple pills per row using
                    flex-wrap so the layout breathes naturally as the user
                    onboards more agents. */}
                <div className="flex flex-wrap gap-2">
                  {customAgents.map((agent) => {
                    const isSelected = selectedCustomAgentId === agent.id;
                    const handleSelect = () => setSelectedCustomAgentId(isSelected ? null : agent.id);
                    return (
                      <div
                        key={agent.id}
                        role="button"
                        tabIndex={0}
                        onClick={handleSelect}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            handleSelect();
                          }
                        }}
                        title={agent.description || agent.endpoint || agent.name}
                        className={`group relative inline-flex items-center gap-2 pl-2 pr-2 py-1.5 border rounded-full transition-all max-w-full cursor-pointer ${
                          isSelected
                            ? 'bg-white dark:bg-gray-800 border-primary-500 dark:border-primary-400 ring-2 ring-primary-200 dark:ring-primary-900/40 shadow-sm'
                            : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:border-primary-400 dark:hover:border-primary-600 hover:shadow-sm'
                        }`}
                      >
                        {/* Radio indicator */}
                        <span className={`flex-shrink-0 h-4 w-4 rounded-full border-2 flex items-center justify-center transition-colors ${
                          isSelected
                            ? 'border-primary-500 bg-primary-500'
                            : 'border-gray-300 dark:border-gray-600 group-hover:border-primary-400'
                        }`}>
                          {isSelected && <span className="h-1.5 w-1.5 rounded-full bg-white" />}
                        </span>

                        {/* Icon */}
                        <span className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ${
                          agent.is_custom
                            ? 'bg-gradient-to-br from-emerald-500 to-teal-500'
                            : 'bg-gradient-to-br from-primary-500 to-blue-500'
                        }`}>
                          {agent.is_custom
                            ? <Settings className="h-3 w-3 text-white" />
                            : <Zap className="h-3 w-3 text-white" />}
                        </span>

                        {/* Name + endpoint (single line) */}
                        <span className="flex items-baseline gap-1.5 min-w-0">
                          <span className={`text-xs font-medium truncate max-w-[160px] ${
                            isSelected
                              ? 'text-primary-700 dark:text-primary-300'
                              : 'text-gray-900 dark:text-white'
                          }`}>
                            {agent.name}
                          </span>
                          {/* Endpoint — visible inline, host-only display so the
                              pill stays compact (full URL still in the tooltip). */}
                          {agent.endpoint && (
                            <>
                              <span className="text-gray-300 dark:text-gray-600">·</span>
                              <span className="text-[11px] text-gray-500 dark:text-gray-400 font-mono truncate max-w-[220px]">
                                {(() => {
                                  try { return new URL(agent.endpoint).host; }
                                  catch { return agent.endpoint; }
                                })()}
                              </span>
                            </>
                          )}
                        </span>

                        {/* Hover-only actions */}
                        <span className="flex items-center gap-0.5 ml-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); setAgentDetailData(agent); setShowAgentDetailModal(true); }}
                            className="p-0.5 rounded text-gray-400 hover:text-primary-500"
                            title="View agent details"
                          >
                            <Info className="h-3 w-3" />
                          </button>
                          {isAdmin && (
                            <button
                              type="button"
                              onClick={(e) => { e.stopPropagation(); deleteCustomAgent(agent.id, agent.name); }}
                              disabled={deletingAgentId === agent.id}
                              className="p-0.5 rounded text-gray-400 hover:text-red-500"
                              title="Remove from My Agents"
                            >
                              {deletingAgentId === agent.id
                                ? <span className="animate-spin h-3 w-3 border-2 border-red-400 border-t-transparent rounded-full inline-block" />
                                : <Trash2 className="h-3 w-3" />
                              }
                            </button>
                          )}
                        </span>
                      </div>
                    );
                  })}
                </div>
      
                {customAgents.length === 0 && (
                  <div className="text-center py-8">
                    <Bot className="mx-auto h-10 w-10 text-gray-300 dark:text-gray-600 mb-2" />
                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">No agents in My Agents yet</p>
            <button
                  type="button"
                      onClick={() => setScanMode('new-agent')}
                      className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-primary-600 text-white hover:bg-primary-700 transition-colors"
                >
                      <Plus className="h-4 w-4" />
                      Add Your First Agent
                </button>
                  </div>
                )}

                  </div>
                )}

              {/* ===== NEW AGENT MODE ===== */}
              {scanMode === 'new-agent' && (
              <div className="bg-white dark:bg-gray-800 border-2 border-gray-200 dark:border-gray-700 rounded-xl p-3 space-y-3">
                {/* Agent Name */}
                <div>
                  <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Agent Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={customAgentForm.name}
                    onChange={(e) => setCustomAgentForm(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g. My Shopping Agent"
                    className="w-full px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                  />
                </div>

                {/* cURL Command */}
                <div>
                  <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                    cURL Command <span className="text-red-500">*</span>
                    <span className="ml-2 font-normal text-gray-500 dark:text-gray-400">
                      — use <code className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-primary-600 dark:text-primary-400 text-[10px]">__PROMPT__</code> where the adversarial prompt should go
                    </span>
                  </label>
                  <textarea
                    value={customAgentForm.curl}
                    onChange={(e) => setCustomAgentForm(prev => ({ ...prev, curl: e.target.value }))}
                    placeholder={`curl -X POST 'https://your-agent-host/api/message' \\\n  -H 'Authorization: Bearer <token>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"message": "__PROMPT__"}'`}
                    rows={7}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-primary-500"
                  />
                  <p className="mt-1 flex items-start gap-1.5 text-[11px] text-amber-700 dark:text-amber-400">
                    <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                    <span>This cURL is stored alongside your agent — do <strong>not</strong> paste static secrets. Use short-lived tokens instead.</span>
                  </p>
                </div>

                {/* System Prompt */}
                <div>
                  <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                    System Prompt / Instruction <span className="text-gray-400">(optional)</span>
                  </label>
                  <textarea
                    value={customAgentForm.agent_context}
                    onChange={(e) => setCustomAgentForm(prev => ({ ...prev, agent_context: e.target.value }))}
                    placeholder="Paste the system prompt or instruction given to this agent..."
                    rows={3}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                  />
                </div>

              </div>
            )}
          </div>
        )}
        
          {/* ==================== ACTIVE SCANS TAB ==================== */}
          {activeTab === 'scans' && (
                        <div>
              {listLoading && scans.length === 0 ? (
                <div className="text-center py-12">
                  <div className="animate-spin h-8 w-8 border-2 border-primary-600 border-t-transparent rounded-full mx-auto" />
                  <p className="mt-3 text-sm text-gray-500 dark:text-gray-400">Loading scans...</p>
                  </div>
              ) : activeScans.length === 0 ? (
                <div className="text-center py-12">
                  <Bot className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active scans</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Start a new agent security scan to get going.</p>
                </div>
              ) : (
                <div className={`space-y-4 transition-opacity duration-200 ${softRefreshing ? 'opacity-75' : 'opacity-100'}`}>
                  {activeScans.map((scan) => (
                    <div key={scan.scan_id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          {getStatusIcon(scan.status)}
                          <div>
                            <div className="flex items-center gap-2">
                              <h4 className="text-sm font-medium text-gray-900 dark:text-white">{scan.agent_name || 'Agent Scan'}</h4>
                              {getStatusBadge(scan.status)}
                            </div>
                            <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                              <span>ID: {scan.scan_id}</span>
                              {scan.hosting_platform && (
                                <span className="inline-flex items-center">
                                  <Globe className="h-3 w-3 mr-1" />
                                  {scan.hosting_platform.toUpperCase()}
                                </span>
                              )}
                              {scan.tools_count != null && scan.tools_count > 0 && (
                                <span className="inline-flex items-center">
                                  <Wrench className="h-3 w-3 mr-1" />
                                  {scan.tools_count} tools
                                </span>
                              )}
                            </div>
                  </div>
                </div>
                        <div className="flex items-center space-x-2">
                          {/* Circular progress (replaces linear bar) */}
                          {scan.status === 'running' && scan.progress != null && (() => {
                            const pct = Math.round(scan.progress);
                            const radius = 16;
                            const circumference = 2 * Math.PI * radius;
                            const dash = (pct / 100) * circumference;
                            return (
                              <div className="relative flex-shrink-0" style={{ width: 40, height: 40 }}>
                                <svg width="40" height="40" viewBox="0 0 40 40">
                                  <circle cx="20" cy="20" r={radius} fill="none"
                                    className="stroke-gray-200 dark:stroke-gray-700" strokeWidth="3" />
                                  <circle cx="20" cy="20" r={radius} fill="none"
                                    className="stroke-primary-500" strokeWidth="3"
                                    strokeLinecap="round"
                                    strokeDasharray={`${dash} ${circumference}`}
                                    transform="rotate(-90 20 20)"
                                    style={{ transition: 'stroke-dasharray 0.5s ease' }}
                                  />
                                </svg>
                                <span className="absolute inset-0 flex items-center justify-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                                  {pct}%
                                </span>
                              </div>
                            );
                          })()}
                          {(scan.status === 'running' || scan.status === 'queued') && (
                            <button
                              onClick={() => cancelScan(scan.scan_id)}
                              disabled={actionBusy[scan.scan_id]}
                              className={`inline-flex items-center px-3 py-1.5 text-xs font-medium rounded-md border transition-colors
                                ${actionBusy[scan.scan_id]
                                  ? 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 border-gray-200 dark:border-gray-600 cursor-not-allowed'
                                  : 'bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/50 hover:bg-red-100 dark:hover:bg-red-900/40'
                                }`}
                            >
                              <StopCircle className={`h-3.5 w-3.5 mr-1 ${actionBusy[scan.scan_id] ? 'animate-pulse' : ''}`} />
                              {actionBusy[scan.scan_id] ? 'Cancelling…' : 'Cancel'}
                            </button>
                          )}
                          {(() => {
                            const dagReady = scan.status !== 'running' || (scan.tools_count != null && scan.tools_count > 0);
                            return (
                          <button
                                onClick={() => dagReady && setLiveViewScan(scan)}
                                disabled={!dagReady}
                                title={!dagReady ? 'Waiting for first tool to be identified…' : undefined}
                                className={`inline-flex items-center px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                                  dagReady
                                    ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/30 border-primary-200 dark:border-primary-800/50'
                                    : 'bg-gray-200 dark:bg-gray-700 text-gray-400 dark:text-gray-500 border-gray-300 dark:border-gray-600 cursor-not-allowed'
                                }`}
                              >
                                {!dagReady ? (
                                  <div className="animate-spin h-3.5 w-3.5 border-2 border-gray-400 border-t-transparent rounded-full mr-1" />
                                ) : (
                            <Activity className="h-3.5 w-3.5 mr-1" />
                                )}
                                {!dagReady ? 'Identifying tools…' : scan.status === 'running' ? 'Live DAG' : 'DAG'}
                          </button>
                            );
                          })()}
                  </div>
                </div>
                      </div>
                    ))}
                  </div>
            )}
              </div>
            )}
            
          {/* ==================== PAST SCANS TAB ==================== */}
          {activeTab === 'past-scans' && (
            <div>
            {/* Filters — same toolbar layout as LLM Scan / MCP / Prompts */}
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <select
                  value={pastSubTab}
                  onChange={(e) => { setPastSubTab(e.target.value); setCurrentPage(1); }}
                  className="select h-9 w-auto"
                  aria-label="Filter scans by ownership"
                >
                  <option value="my-scans">My Scans</option>
                  <option value="other-scans">Other Scans</option>
                </select>
                <input
                  type="text"
                  value={pastSearch}
                  onChange={(e) => { setPastSearch(e.target.value); setCurrentPage(1); }}
                  placeholder="Search by name or ID..."
                  className="input h-9 flex-1 min-w-[200px]"
                />
                <select
                  value={pastStatus}
                  onChange={(e) => { setPastStatus(e.target.value); setCurrentPage(1); }}
                  className="select h-9 w-auto"
                >
                  <option value="all">All Status</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
                <button
                  onClick={() => loadScans()}
                  className="p-2 text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
                  title="Refresh"
                >
                  <RefreshCw className="h-4 w-4" />
                </button>
            </div>
            
              {listLoading && scans.length === 0 ? (
                <div className="text-center py-12">
                  <div className="animate-spin h-8 w-8 border-2 border-primary-600 border-t-transparent rounded-full mx-auto" />
              </div>
              ) : paginatedPastScans.length === 0 ? (
                <div className="text-center py-12">
                  <Bot className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No past scans</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    {pastSearch || pastStatus !== 'all' ? 'No scans match your filters.' : 'Completed scans will appear here.'}
                  </p>
              </div>
            ) : (
                <>
                  <div className="space-y-3">
                    {paginatedPastScans.map((scan) => (
                      <div key={scan.scan_id} className="border rounded-lg p-4 border-gray-200 dark:border-gray-700">
                        <div className="flex items-center justify-between gap-3">
                          <div className="flex items-center space-x-3 min-w-0 flex-1">
                            {getStatusIcon(scan.status)}
                            <div className="min-w-0 flex-1">
                              <h4 className="text-sm font-medium text-gray-900 dark:text-white truncate">{scan.agent_name || 'Agent Scan'}</h4>
                              <div className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 mt-0.5 flex-wrap">
                                <span className="truncate max-w-[140px]" title={scan.scan_id}>ID: {scan.scan_id}</span>
                                {scan.results && scan.results.total > 0 && (
                                  <>
                                    <span className="text-gray-300 dark:text-gray-600">·</span>
                                    <span className={`font-semibold ${scan.results.bypass_rate > 0 ? 'text-red-500 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                                      {scan.results.bypass_rate ?? 0}%
                                    </span>
                                    <span className="text-gray-300 dark:text-gray-600">·</span>
                                    <span>{scan.results.bypassed ?? 0}/{scan.results.total} prompts</span>
                                  </>
                                )}
                                {scan.tools_count > 0 && (
                                  <>
                                    <span className="text-gray-300 dark:text-gray-600">·</span>
                                    <span>{scan.tools_count} tools</span>
                                  </>
                                )}
                                {scan.created_by && (
                                  <>
                                    <span className="text-gray-300 dark:text-gray-600">·</span>
                                    <span>by <span className="text-gray-700 dark:text-gray-300">{scan.created_by}</span></span>
                                  </>
                                )}
                              </div>
              </div>
                          </div>
                          <div className="flex items-center space-x-2 flex-shrink-0">
                            <div className="flex space-x-1">
                              {/* Info button */}
                            <button
                              onClick={() => { setScanInfoData(scan); setShowScanInfoModal(true); }}
                                className="btn-outline btn-sm"
                                aria-label={`View configuration for scan ${scan.agent_name}`}
                                title="View scan configuration details"
                            >
                              <Info className="h-4 w-4" />
                            </button>
                              {/* Results + Delete — hidden for other users' scans unless admin */}
                              {(pastSubTab !== 'other-scans' || isAdmin) && (<>
                            {(scan.status === 'completed' || scan.status === 'failed') && (
                              <LockedOverlay locked={!hasPermission('triksha.scan.view-past-results') || !canAccessScan(scan.created_by)} message="You do not have permission to view details of this scan">
                                <button
                                  onClick={() => setLiveViewScan(scan)}
                                  className="btn-outline btn-sm"
                                  aria-label={`View results for scan ${scan.agent_name}`}
                                  title={`View results for scan ${scan.agent_name}`}
                                >
                                  <Eye className="h-4 w-4 mr-1" />
                                  Results
                                </button>
                              </LockedOverlay>
                            )}
                              {hasPermission('triksha.scan.delete') && canAccessScan(scan.created_by) && (
                                <button
                                  onClick={() => deleteScan(scan.scan_id)}
                                  disabled={actionBusy[scan.scan_id]}
                                  className="btn-outline btn-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 border-red-200 dark:border-red-800"
                                  title="Delete scan permanently"
                                >
                                  {actionBusy[scan.scan_id] ? (
                                    <RefreshCw className="h-4 w-4 animate-spin" />
                                  ) : (
                                    <Trash2 className="h-4 w-4" />
                                  )}
                                </button>
                              )}
                              </>)}
          </div>
                        </div>
                        </div>
                      </div>
                    ))}
      </div>
      
                  {/* Pagination */}
                  {totalPages > 1 && (
                    <div className="flex items-center justify-between mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                        Showing {((currentPage - 1) * SCANS_PER_PAGE) + 1}–{Math.min(currentPage * SCANS_PER_PAGE, pastScans.length)} of {pastScans.length}
                  </p>
                      <div className="flex items-center space-x-2">
              <button
                          onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                          disabled={currentPage === 1}
                          className="p-1.5 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <ChevronLeft className="h-4 w-4" />
                        </button>
                        <span className="text-sm text-gray-700 dark:text-gray-300">{currentPage} / {totalPages}</span>
                        <button
                          onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                          disabled={currentPage === totalPages}
                          className="p-1.5 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                          <ChevronRight className="h-4 w-4" />
              </button>
            </div>
              </div>
            )}
                </>
              )}
              </div>
                    )}

        </div>
      </div>

      {/* ==================== SCAN INFO MODAL ==================== */}
      {showScanInfoModal && scanInfoData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop */}
          <div className="fixed inset-0 transition-opacity bg-gray-500/75 dark:bg-gray-900/75" onClick={() => setShowScanInfoModal(false)} />
          
          {/* Modal */}
          <div className="relative bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl w-full max-w-3xl flex flex-col" style={{ maxHeight: '90vh' }}>
            {/* Header - Gradient style matching LLM scan modal */}
            <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 flex-shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Bot className="h-6 w-6 text-white" />
                  <div>
                    <h3 className="text-lg font-semibold text-white">{scanInfoData.agent_name || 'Agent Scan'}</h3>
                    <p className="text-sm text-white/70">Agent Security Scan Details</p>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  {scanInfoData.reference_id && scanInfoData.reference_id !== 'N/A' && (
                    <button
                      onClick={() => window.open(`${(process.env.REACT_APP_JIRA_URL || '').replace(/\/$/, '')}/browse/${scanInfoData.reference_id}`, '_blank')}
                      className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                    >
                      <Shield className="w-4 h-4 mr-2" />
                      {scanInfoData.reference_id}
                    </button>
                  )}
                  <button onClick={() => setShowScanInfoModal(false)} className="text-white hover:text-gray-200">
                    <X className="h-6 w-6" />
              </button>
            </div>
              </div>
            </div>
            
            {/* Sub-header with endpoint info */}
            <div className="bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-3 flex-shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="h-4 w-4 text-gray-500 dark:text-gray-400" />
                    <span className="text-sm text-gray-600 dark:text-gray-400">Endpoint:</span>
                  </div>
                  <code className="px-2.5 py-1 bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 text-xs font-mono rounded-md max-w-md truncate">
                    {scanInfoData.agent_endpoint}
                  </code>
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400">
                  Created by: {scanInfoData.created_by || 'Anonymous'}
                </div>
              </div>
            </div>
            
            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="space-y-6">
                {/* Basic Info Grid */}
                  <div>
                  <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                    <FileText className="h-4 w-4 mr-2 text-primary-600" />
                    Scan Details
                  </h4>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 text-center">
                      <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Status</div>
                      <div className={`text-sm font-semibold capitalize ${
                        scanInfoData.status === 'completed' ? 'text-green-600' : 
                        scanInfoData.status === 'running' ? 'text-blue-600' : 
                        scanInfoData.status === 'failed' ? 'text-red-600' : 
                        scanInfoData.status === 'cancelled' ? 'text-orange-600' : 'text-gray-900 dark:text-white'
                      }`}>
                        {scanInfoData.status}
                </div>
                    </div>
                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 text-center">
                      <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Framework</div>
                      <div className="text-sm font-semibold text-gray-900 dark:text-white">
                        {FRAMEWORK_OPTIONS.find(f => f.value === scanInfoData.framework)?.label || scanInfoData.framework || 'Unknown'}
                      </div>
                    </div>
                    <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 text-center">
                      <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Hosting</div>
                      <div className="text-sm font-semibold text-gray-900 dark:text-white">
                        {(scanInfoData.hosting_platform || 'N/A').toUpperCase()}
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Discovered Tools */}
                {scanInfoData.tools && scanInfoData.tools.length > 0 && (
                <div>
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                      <Wrench className="h-4 w-4 mr-2 text-primary-600" />
                      Discovered Tools ({scanInfoData.tools.length})
                    </h4>
                    <div className="space-y-2">
                      {scanInfoData.tools.map((tool, i) => (
                        <div key={i} className="bg-gradient-to-r from-gray-50 to-gray-100 dark:from-gray-700/50 dark:to-gray-700/30 rounded-lg p-3 border border-gray-200 dark:border-gray-600">
                          <div className="flex items-start space-x-2">
                            <Wrench className="h-4 w-4 text-primary-500 mt-0.5 flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <div className="font-medium text-gray-900 dark:text-white text-sm">{tool.name}</div>
                              {tool.description && (
                                <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">{tool.description}</p>
                              )}
                </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {/* Agent Context */}
                {scanInfoData.agent_context && (
                <div>
                    <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                      <MessageSquare className="h-4 w-4 mr-2 text-primary-600" />
                      Agent Context
                    </h4>
                    <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 rounded-lg p-4 border border-blue-100 dark:border-blue-800">
                      <p className="text-sm text-gray-900 dark:text-white whitespace-pre-wrap">{scanInfoData.agent_context}</p>
                </div>
                  </div>
                )}
                
                {/* Scan ID & Timestamps */}
                <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                  <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
                    <span>Scan ID: <code className="bg-gray-100 dark:bg-gray-700 px-2 py-0.5 rounded">{scanInfoData.scan_id}</code></span>
                    {scanInfoData.created_at && (
                      <span>Created: {new Date(scanInfoData.created_at).toLocaleString()}</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Footer with action buttons */}
            <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between bg-gray-50 dark:bg-gray-900 flex-shrink-0">
              <button
                onClick={() => setShowScanInfoModal(false)}
                className="px-4 py-2 text-sm bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors"
              >
                Close
              </button>
              <div className="flex items-center space-x-2">
                {(scanInfoData.status === 'completed' || scanInfoData.status === 'failed') && (
                  <>
                    <button
                      onClick={() => {
                        setShowScanInfoModal(false);
                        setLiveViewScan(scanInfoData);
                      }}
                      className="inline-flex items-center px-4 py-2 text-sm font-medium bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/30 rounded-md transition-colors"
                    >
                      <Activity className="h-4 w-4 mr-2" />
                      View Results
                    </button>
                    <button
                      onClick={() => window.open(`/agents/scan/${scanInfoData.scan_id}/report`, '_blank')}
                      className="inline-flex items-center px-4 py-2 text-sm font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                    >
                      <FileCode className="h-4 w-4 mr-2" />
                      View Report
                    </button>
                    <button
                      onClick={async () => {
                        try {
                          const resp = await fetch(`/agents/scan/${scanInfoData.scan_id}/report`, { credentials: 'include' });
                          if (!resp.ok) throw new Error('Request failed');
                          const blob = await resp.blob();
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `agent-scan-report-${scanInfoData.scan_id}.html`;
                          a.click();
                          URL.revokeObjectURL(url);
                        } catch (err) {
                          toast.error('Failed to download report');
                        }
                      }}
                      className="inline-flex items-center px-4 py-2 text-sm font-medium bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
                    >
                      <FileText className="h-4 w-4 mr-2" />
                      Download Report
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== AGENT DETAIL MODAL (cURL & Config) ==================== */}
      {showAgentDetailModal && agentDetailData && (() => {
        const curlCmd = buildCurlFromAgent(agentDetailData);
        return (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop */}
            <div className="fixed inset-0 transition-opacity bg-gray-500/75 dark:bg-gray-900/75" onClick={() => setShowAgentDetailModal(false)} />

            {/* Modal */}
            <div className="relative bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl w-full max-w-2xl flex flex-col" style={{ maxHeight: '85vh' }}>
              {/* Header */}
              <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 flex-shrink-0">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    {agentDetailData.is_custom
                      ? <Settings className="h-6 w-6 text-white" />
                      : <Zap className="h-6 w-6 text-white" />
                    }
                <div>
                      <h3 className="text-lg font-semibold text-white">{agentDetailData.name}</h3>
                      <p className="text-sm text-white/70">{agentDetailData.is_custom ? 'Custom Agent' : 'Built-in Agent'}</p>
                  </div>
                  </div>
                  <button onClick={() => setShowAgentDetailModal(false)} className="text-white hover:text-gray-200">
                    <X className="h-6 w-6" />
                  </button>
                </div>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto p-6 space-y-5">
                {/* Endpoint */}
                  <div>
                  <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                    <Globe className="h-3.5 w-3.5" /> Endpoint
                  </h4>
                  <code className="block w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 text-sm font-mono text-gray-800 dark:text-gray-200 rounded-lg border border-gray-200 dark:border-gray-700 break-all">
                    {agentDetailData.endpoint}
                  </code>
                    </div>

                {/* Metadata chips */}
                <div className="flex items-center gap-2 flex-wrap">
                  {agentDetailData.framework && (
                    <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300">
                      <Puzzle className="h-3 w-3 mr-1" />
                      {agentDetailData.framework}
                    </span>
                  )}
                  <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                    <Monitor className="h-3 w-3 mr-1" />
                    {agentDetailData.hosting_platform || 'custom'}
                  </span>
                  {agentDetailData.created_by && (
                    <span className="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                      Created by: {agentDetailData.created_by}
                    </span>
                  )}
                </div>

                {/* cURL Command */}
                {agentDetailData.is_custom && curlCmd && (
                <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 flex items-center gap-1.5">
                        <Terminal className="h-3.5 w-3.5" /> cURL Command
                      </h4>
                      <button
                        type="button"
                        onClick={() => { navigator.clipboard.writeText(curlCmd); toast.success('cURL copied to clipboard'); }}
                        className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-medium text-primary-600 dark:text-primary-400 bg-primary-50 dark:bg-primary-900/20 hover:bg-primary-100 dark:hover:bg-primary-900/30 rounded transition-colors"
                      >
                        <ClipboardCopy className="h-3 w-3" />
                        Copy
                      </button>
                  </div>
                    <pre className="w-full px-4 py-3 bg-gray-900 dark:bg-gray-950 text-green-400 text-xs font-mono rounded-lg border border-gray-700 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {curlCmd}
                    </pre>
              </div>
                )}

                {/* Request Body Template (for custom agents without full cURL) */}
                {agentDetailData.is_custom && agentDetailData.request_body_template && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                      <Code2 className="h-3.5 w-3.5" /> Request Body Template
                    </h4>
                    <pre className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 text-sm font-mono text-gray-800 dark:text-gray-200 rounded-lg border border-gray-200 dark:border-gray-700 overflow-x-auto whitespace-pre-wrap">
                      {(() => {
                        try { return JSON.stringify(JSON.parse(agentDetailData.request_body_template), null, 2); }
                        catch { return agentDetailData.request_body_template; }
                      })()}
                    </pre>
                    </div>
                )}

                {/* Auth Headers */}
                {agentDetailData.headers && Object.keys(agentDetailData.headers).length > 0 && (
                <div>
                    <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                      <Lock className="h-3.5 w-3.5" /> Auth Headers
                    </h4>
                    <div className="space-y-1">
                      {Object.entries(agentDetailData.headers).map(([key, value]) => (
                        <div key={key} className="flex items-start gap-2 px-3 py-1.5 bg-gray-50 dark:bg-gray-900 rounded text-xs font-mono border border-gray-200 dark:border-gray-700">
                          <span className="font-semibold text-gray-700 dark:text-gray-300 flex-shrink-0">{key}:</span>
                          <span className="text-gray-500 dark:text-gray-400 break-all">{String(value).length > 60 ? String(value).slice(0, 60) + '…' : value}</span>
                        </div>
                      ))}
                    </div>
                        </div>
                      )}

                {/* Response JSON Path */}
                {agentDetailData.response_json_path && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2">Response Path</h4>
                    <code className="px-3 py-1.5 bg-gray-50 dark:bg-gray-900 text-sm font-mono text-gray-700 dark:text-gray-300 rounded border border-gray-200 dark:border-gray-700">
                      {agentDetailData.response_json_path}
                    </code>
                  </div>
                )}

                {/* Agent Context */}
                {agentDetailData.agent_context && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                      <FileText className="h-3.5 w-3.5" /> Agent Context
                    </h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border border-gray-200 dark:border-gray-700">
                      {agentDetailData.agent_context}
                    </p>
                  </div>
                )}

                {/* Tools */}
                {agentDetailData.tools && agentDetailData.tools.length > 0 && (
                  <div>
                    <h4 className="text-xs font-semibold uppercase text-gray-500 dark:text-gray-400 mb-2 flex items-center gap-1.5">
                      <Wrench className="h-3.5 w-3.5" /> Known Tools ({agentDetailData.tools.length})
                    </h4>
                    <div className="grid grid-cols-2 gap-2">
                      {agentDetailData.tools.map((tool, i) => (
                        <div key={i} className="px-3 py-2 bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700">
                          <span className="text-xs font-semibold text-gray-800 dark:text-gray-200">{tool.name}</span>
                          {tool.description && (
                            <p className="text-[10px] text-gray-500 dark:text-gray-400 mt-0.5">{tool.description}</p>
                          )}
                  </div>
                        ))}
                    </div>
                        </div>
                      )}
                    </div>

              {/* Footer */}
              <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-3 flex items-center justify-between flex-shrink-0">
                <button
                  onClick={() => setShowAgentDetailModal(false)}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
                >
                  Close
                </button>
                <button
                  onClick={async () => {
                    setShowAgentDetailModal(false);
                    setLoading(true);
                    try {
                      const payload = {
                        custom_agent_id: agentDetailData.id,
                        agent_name: agentDetailData.name,
                        framework: agentDetailData.framework,
                        agent_context: agentDetailData.agent_context || undefined,
                        created_by: user?.email || user?.id || 'unknown',
                      };
                      await apiClient.post('/agents/scan', payload);
                      toast.success(`${agentDetailData.name} scan started`);
                      setActiveTab('scans');
                      await loadScans();
                    } catch (err) {
                      toast.error(err?.message || 'Failed to start scan');
                    } finally {
                      setLoading(false);
                    }
                  }}
                  disabled={loading || !hasPermission('triksha.scan.run')}
                  className="inline-flex items-center px-4 py-2 text-sm font-medium bg-primary-600 text-white hover:bg-primary-700 rounded-md transition-colors disabled:opacity-50"
                >
                  <Play className="h-4 w-4 mr-2" />
                  Start Scan
                </button>
                {!hasPermission('triksha.scan.run') && (
                  <span className="ml-2 inline-flex items-center gap-1 text-xs text-gray-400"><Lock className="h-3 w-3" /> You do not have permission to run scans</span>
                )}
                    </div>
                        </div>
          </div>
        );
      })()}
                
      {/* ==================== CUSTOM AGENT CONFIG MODAL ==================== */}
      {showCustomAgentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b border-gray-200 dark:border-gray-700 sticky top-0 bg-white dark:bg-gray-800 z-10 rounded-t-xl">
              <div className="flex items-center gap-2">
                <Settings className="h-5 w-5 text-primary-600 dark:text-primary-400" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Add Agent to My Agents</h3>
              </div>
              <button onClick={() => setShowCustomAgentModal(false)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="p-5 space-y-5">
              {/* Name */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Agent Name <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  value={customAgentForm.name}
                  onChange={(e) => setCustomAgentForm(prev => ({ ...prev, name: e.target.value }))}
                  placeholder="e.g. My Shopping Agent"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                />
              </div>

              {/* cURL Command */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  cURL Command <span className="text-red-500">*</span>
                </label>
                <textarea
                  value={customAgentForm.curl}
                  onChange={(e) => setCustomAgentForm(prev => ({ ...prev, curl: e.target.value }))}
                  placeholder={`curl -X POST 'https://your-agent-host/api/message' \\\n  -H 'Authorization: Bearer <token>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"message": "__PROMPT__"}'`}
                  rows={6}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono focus:ring-2 focus:ring-primary-500"
                />
                <p className="mt-1.5 text-xs text-gray-500 dark:text-gray-400">
                  Use <code className="px-1 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-primary-600 dark:text-primary-400">__PROMPT__</code> in the body where the adversarial prompt should be injected.
                </p>
              </div>

              {/* System Prompt / Instruction */}
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  System Prompt / Instruction <span className="text-xs text-gray-400">(optional)</span>
                </label>
                <textarea
                  value={customAgentForm.agent_context}
                  onChange={(e) => setCustomAgentForm(prev => ({ ...prev, agent_context: e.target.value }))}
                  placeholder="Paste the system prompt or instruction given to this agent..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500"
                />
              </div>
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between p-5 border-t border-gray-200 dark:border-gray-700 sticky bottom-0 bg-white dark:bg-gray-800 rounded-b-xl">
              <button
                type="button"
                onClick={() => setShowCustomAgentModal(false)}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={saveCustomAgent}
                disabled={savingCustomAgent || !customAgentForm.name.trim() || !customAgentForm.curl.trim()}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors shadow-sm text-sm"
              >
                {savingCustomAgent ? (
                  <>
                    <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                    Saving...
                  </>
                ) : (
                  <>
                    <Save className="h-4 w-4" />
                    Save to My Agents
                  </>
                )}
              </button>
                    </div>
                    </div>
                        </div>
                      )}
                
      {/* ==================== TEST AGENT MODAL ==================== */}
      {showTestModal && testModalScan && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full mx-4 h-[600px] flex flex-col">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-2">
                <Send className="h-5 w-5 text-primary-600" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Test Agent</h3>
                <span className="text-sm text-gray-500 dark:text-gray-400">— {testModalScan.agent_name}</span>
                    </div>
              <button onClick={() => setShowTestModal(false)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {testMessages.length === 0 && (
                <div className="text-center py-8">
                  <MessageSquare className="h-10 w-10 mx-auto text-gray-300 dark:text-gray-600 mb-2" />
                  <p className="text-sm text-gray-500 dark:text-gray-400">Send a message to test the agent</p>
                  </div>
                )}
              {testMessages.map((msg, idx) => (
                <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  {msg.role === 'user' ? (
                    <div className="max-w-[70%] bg-primary-600 text-white rounded-lg px-4 py-2">
                      <p className="text-sm whitespace-pre-wrap">{msg.content}</p>
              </div>
                  ) : msg.role === 'error' ? (
                    <div className="max-w-[70%] bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg px-4 py-2 border border-red-200 dark:border-red-800">
                      <XCircle className="h-4 w-4 inline mr-2" />
                      {msg.content}
            </div>
                  ) : (
                    <div className="max-w-[70%] bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2">
                      <pre className="text-sm whitespace-pre-wrap text-gray-900 dark:text-white font-sans">{msg.content}</pre>
                        </div>
                      )}
                        </div>
              ))}
              {testProcessing && (
                <div className="flex justify-start">
                  <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-2">
                    <div className="flex items-center space-x-2">
                      <div className="animate-spin h-4 w-4 border-2 border-primary-600 border-t-transparent rounded-full" />
                      <span className="text-sm text-gray-500 dark:text-gray-400">Agent responding...</span>
                        </div>
          </div>
        </div>
                )}
            </div>

            {/* Input */}
            <div className="border-t border-gray-200 dark:border-gray-700 p-3">
              <div className="flex space-x-3">
                <input
                  type="text"
                  value={testPrompt}
                  onChange={(e) => setTestPrompt(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && !testProcessing && sendTestMessage()}
                  placeholder="Send a message to the agent..."
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                />
                <button
                  onClick={sendTestMessage}
                  disabled={!testPrompt.trim() || testProcessing}
                  className="px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-400 text-white font-medium rounded-lg transition-colors"
                >
                  <Send className="h-4 w-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
                )}

      {/* DAG overlay — works for both live and historical scans */}
      {liveViewScan && (
        <AgentScanDAG
          scanId={liveViewScan.scan_id}
          agentName={liveViewScan.agent_name}
          onClose={() => setLiveViewScan(null)}
          onCancel={cancelScan}
          apiBaseUrl=""
        />
      )}
    </div>
  );
};

export default Agents;
