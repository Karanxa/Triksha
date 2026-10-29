import React, { useState, useEffect, useMemo, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import { 
  FileText, Server, CheckCircle, XCircle, Clock, 
  AlertTriangle, RefreshCw, ChevronDown, ChevronUp, ChevronLeft, ChevronRight,
  Wrench, MessageSquare, FileCode, Layers, Eye, Play,
  X, Download, Activity, BarChart3, Info, BookOpen, Shield, Trash2, StopCircle
} from 'lucide-react';
import toast from 'react-hot-toast';
import MCPSecurityModal from '../components/MCPSecurityModal';
import LockedOverlay from '../components/LockedOverlay';

const MCPScanner = () => {
  const { user, hasPermission, canAccessScan, isAdmin, canViewAllScans } = useAuth();
  const location = useLocation();
  
  // Tab state
  const [activeTab, setActiveTab] = useState('new-scan');
  
  // Scan form state
  const [loading, setLoading] = useState(false);
  const [timeout, setTimeout] = useState(30);

  // Form fields
  const [serverName, setServerName] = useState('');
  const [serverType, setServerType] = useState('http'); // http or sse
  const [serverUrl, setServerUrl] = useState('');
  const [headers, setHeaders] = useState([{ key: '', value: '' }]);
  const [urlTypeWarning, setUrlTypeWarning] = useState(null); // Validation warning for URL type mismatch
  
  // Scan history state
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [expandedServers, setExpandedServers] = useState({});
  
  // Filters for past scans
  const [pastSearch, setPastSearch] = useState('');
  const [pastStatus, setPastStatus] = useState('all'); // all | success | error
  const [currentPage, setCurrentPage] = useState(1);
  // My Scans vs Other Scans classification (matches LLM Scan / Prompts pattern)
  const [pastSubTab, setPastSubTab] = useState('my-scans');
  const SCANS_PER_PAGE = 20;
  
  // Modal state
  const [showResultsModal, setShowResultsModal] = useState(false);
  const [modalScan, setModalScan] = useState(null);
  const [showScanInfoModal, setShowScanInfoModal] = useState(false);
  const [scanInfoData, setScanInfoData] = useState(null);
  const [showTestModal, setShowTestModal] = useState(false);
  const [testModalScan, setTestModalScan] = useState(null);
  
  // Test modal state
  const [selectedTool, setSelectedTool] = useState(null);
  const [toolArgs, setToolArgs] = useState({});
  const [executing, setExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  
  // Agent state
  const [agentRunning, setAgentRunning] = useState(false);
  const [agentLogs, setAgentLogs] = useState([]);
  const [showAgentLogs, setShowAgentLogs] = useState(true);
  const [agentReport, setAgentReport] = useState(null);
  
  // Client simulation state
  const [testMode, setTestMode] = useState('client'); // 'manual' | 'client'
  const [clientPrompt, setClientPrompt] = useState('');
  const [clientMessages, setClientMessages] = useState([]);
  const [clientProcessing, setClientProcessing] = useState(false);
  const [clientAbortController, setClientAbortController] = useState(null);
  const [trikshaAgentRunning, setTrikshaAgentRunning] = useState(false);
  
  // Auto-active scan: track scan that should auto-fire agent when passive scan completes
  const [pendingActiveScanId, setPendingActiveScanId] = useState(null);
  const [activeScanStreaming, setActiveScanStreaming] = useState(null); // scan_id of active scan being streamed
  const [activeScanMessagesMap, setActiveScanMessagesMap] = useState({}); // messages per scan ID: { scanId: [messages] }
  const [inlineAgentRunning, setInlineAgentRunning] = useState(false); // track if inline agent is running
  const [agentRunningScanId, setAgentRunningScanId] = useState(null); // scan ID that has agent running (keeps scan in active tab)
  const activeScanLogRef = useRef(null); // for auto-scroll
  const agentFiredForScanRef = useRef(null); // ref guard: tracks which scan ID has already triggered agent (prevents double-fire on stale closure)
  // Active findings the BACKEND saved (active runs in the scan worker now): { scanId: [findings] }
  const [savedActiveResults, setSavedActiveResults] = useState({});

  const apiClient = createApiClient();

  // Load scan history from database on mount, on tab switch, and on
  // ownership-scope change so the DB does the filtering.
  useEffect(() => {
    loadScansFromDatabase();
  }, [activeTab, pastSubTab]); // eslint-disable-line react-hooks/exhaustive-deps

  // Handle prefilled config from navigation state
  useEffect(() => {
    if (location.state?.prefillConfig) {
      // Parse the JSON config and populate form fields
      try {
        const parsed = JSON.parse(location.state.prefillConfig);
        const servers = parsed.servers || parsed.mcpServers || {};
        const firstKey = Object.keys(servers)[0];
        if (firstKey) {
          const srv = servers[firstKey];
          setServerName(firstKey);
          setServerUrl(srv.url || srv.command || '');
          setServerType(srv.type || 'http');
          if (srv.headers && typeof srv.headers === 'object') {
            const hdrs = Object.entries(srv.headers).map(([k, v]) => ({ key: k, value: String(v) }));
            setHeaders(hdrs.length ? hdrs : [{ key: '', value: '' }]);
          }
        }
      } catch {
        // If JSON is unparseable, just prefill the server name
        if (location.state.prefillServerName) setServerName(location.state.prefillServerName);
      }

      if (location.state.prefillServerName) setServerName(location.state.prefillServerName);

      toast.success('Config pre-filled. Review and start scan.');
      window.history.replaceState({}, document.title);
    }
  }, [location.state]);

  // Deep-link: ?highlight=<scan_id> — switch to past-scans and open that scan's modal
  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const highlightId = params.get('highlight');
    if (!highlightId) return;
    window.history.replaceState({}, document.title, location.pathname);
    setActiveTab('past-scans');
    apiClient.get(`/mcp/scan/${highlightId}`)
      .then(res => {
        const scan = res?.scan;
        if (!scan) return;
        setSelectedScan({
          id: scan.scan_id,
          scan_id: scan.scan_id,
          timestamp: scan.created_at,
          fileName: scan.file_name,
          scanName: scan.scan_name || scan.file_name,
          status: scan.status,
          message: scan.message,
          data: scan.results || null,
          completedAt: scan.completed_at,
          createdBy: scan.created_by,
          referenceId: scan.reference_id,
        });
      })
      .catch(() => {});
  }, [location.search]); // eslint-disable-line react-hooks/exhaustive-deps

  const loadScansFromDatabase = async () => {
    try {
      // Build the query string ourselves — apiClient.get's second arg is
      // fetch options, NOT query params. Without this the scope=mine filter
      // never reaches the backend and Other users' scans show up under
      // "My Scans".
      const params = new URLSearchParams({ limit: '50' });
      if (activeTab === 'past-scans') {
        params.set('scope', pastSubTab === 'my-scans' ? 'mine' : 'others');
      }
      const response = await apiClient.get(`/mcp/scans?${params.toString()}`);
      if (response.status === 'ok' && response.scans) {
        // Transform database scans to match our local format
        const transformedScans = response.scans.map(scan => ({
          id: scan.scan_id,
          scan_id: scan.scan_id,
          timestamp: scan.created_at,
          fileName: scan.file_name,
          scanName: scan.scan_name || scan.file_name,
          status: scan.status,
          message: scan.message,
          data: scan.results || null,
          completedAt: scan.completed_at,
          createdBy: scan.created_by,
          referenceId: scan.reference_id
        }));
        // Active scanning now runs in the BACKEND scan worker (both passive and
        // active run by default). When the passive scan completes, just clear the
        // pending flag and refresh saved active results — do NOT fire the agent
        // client-side (that would double-run it).
        if (pendingActiveScanId) {
          const completedScan = transformedScans.find(
            s => s.id === pendingActiveScanId && s.status === 'completed' && s.data
          );
          if (completedScan && agentFiredForScanRef.current !== completedScan.id) {
            agentFiredForScanRef.current = completedScan.id;
            setPendingActiveScanId(null);
            // Pull whatever active findings the backend has saved so far.
            loadActiveResults(completedScan.id);
          }
        }

        setScanHistory(transformedScans);
      }
    } catch (error) {
      console.error('Failed to load MCP scans:', error);
      // Fallback to localStorage if API fails
      const saved = localStorage.getItem('mcp_scan_history');
      if (saved) {
        try {
          setScanHistory(JSON.parse(saved));
        } catch (e) {
          console.error('Failed to parse scan history:', e);
        }
      }
    }
  };

  // Save scan history to localStorage
  const saveScanToHistory = (scanData) => {
    const newScan = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      fileName: serverName || 'Manual Config',
      ...scanData
    };
    
    const updated = [newScan, ...scanHistory].slice(0, 50); // Keep last 50 scans
    setScanHistory(updated);
    localStorage.setItem('mcp_scan_history', JSON.stringify(updated));
    return newScan;
  };

  // Filter scans for active/past tabs
  const activeScans = useMemo(() => {
    // Show scans that are in progress OR waiting for agent OR agent is running
    return scanHistory.filter(scan => 
      scan.status === 'scanning' || 
      scan.status === 'queued' || 
      scan.status === 'running' ||
      // Keep scan in active tab while waiting for agent to start (passive done, agent pending)
      scan.id === pendingActiveScanId ||
      // Keep scan in active tab while agent is running
      scan.id === agentRunningScanId
    );
  }, [scanHistory, pendingActiveScanId, agentRunningScanId]);

  // Identifiers used to match scans against the current user.
  const isMyMcpScan = (scan) => {
    const cb = String(scan?.createdBy || scan?.created_by || '').toLowerCase();
    if (!cb) return false;
    if (user?.email && cb === String(user.email).toLowerCase()) return true;
    if (user?.id && cb === String(user.id).toLowerCase()) return true;
    return false;
  };

  const pastScans = useMemo(() => {
    // Exclude active scans (queued, running, scanning) AND scans waiting for/running agent
    let filtered = scanHistory.filter(scan =>
      scan.status !== 'scanning' &&
      scan.status !== 'queued' &&
      scan.status !== 'running' &&
      // Don't show in past if waiting for agent to start
      scan.id !== pendingActiveScanId &&
      // Don't show in past if agent is running
      scan.id !== agentRunningScanId
    );

    // Ownership is now enforced at the API call (via the scope query param)
    // — no need to filter client-side a second time.

    // Apply search filter
    if (pastSearch.trim()) {
      const search = pastSearch.toLowerCase();
      filtered = filtered.filter(scan =>
        scan.fileName.toLowerCase().includes(search) ||
        scan.id.toLowerCase().includes(search)
      );
    }

    // Apply status filter
    if (pastStatus !== 'all') {
      filtered = filtered.filter(scan => {
        if (pastStatus === 'success') {
          return scan.data && scan.data.summary && scan.data.summary.successful > 0;
        } else if (pastStatus === 'error') {
          return scan.data && scan.data.summary && (scan.data.summary.failed + scan.data.summary.timeout) > 0;
        }
        return true;
      });
    }

    return filtered;
  }, [scanHistory, pastSearch, pastStatus, pastSubTab, pendingActiveScanId, agentRunningScanId, user]); // eslint-disable-line react-hooks/exhaustive-deps

  // Pagination for past scans
  const totalPages = Math.ceil(pastScans.length / SCANS_PER_PAGE);
  const paginatedPastScans = useMemo(() => {
    const startIndex = (currentPage - 1) * SCANS_PER_PAGE;
    const endIndex = startIndex + SCANS_PER_PAGE;
    return pastScans.slice(startIndex, endIndex);
  }, [pastScans, currentPage]);

  // Reset to page 1 when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [pastSearch, pastStatus]);

  // Clear modals when switching tabs
  useEffect(() => {
    setSelectedScan(null);
    setExpandedServers({});
  }, [activeTab]);

  // Poll for active scans updates (faster when waiting for agent)
  useEffect(() => {
    if (activeScans.length === 0 && !pendingActiveScanId) return;

    // Poll faster when waiting for passive scan to complete so agent can start
    const interval = pendingActiveScanId ? 1500 : 3000;

    const pollInterval = setInterval(() => {
      loadScansFromDatabase();
    }, interval);

    return () => clearInterval(pollInterval);
  }, [activeScans.length, pendingActiveScanId]);

  // Validate URL type matches selected server type
  const validateUrlType = (url, type) => {
    if (!url) {
      setUrlTypeWarning(null);
      return true;
    }
    
    const urlLower = url.toLowerCase();
    
    // Patterns that suggest SSE endpoint
    const ssePatterns = ['/sse', '/events', '/stream', '/subscribe', 'sse=true', 'type=sse'];
    const looksLikeSSE = ssePatterns.some(pattern => urlLower.includes(pattern));
    
    // Patterns that suggest HTTP endpoint  
    const httpPatterns = ['/mcp', '/api', '/rpc', '/json'];
    const looksLikeHTTP = httpPatterns.some(pattern => urlLower.includes(pattern)) && !looksLikeSSE;
    
    if (looksLikeSSE && type === 'http') {
      setUrlTypeWarning({
        type: 'sse-suggested',
        message: 'This URL appears to be an SSE endpoint. Consider selecting "SSE" as the connection type.'
      });
      return false;
    }
    
    if (looksLikeHTTP && type === 'sse') {
      setUrlTypeWarning({
        type: 'http-suggested',
        message: 'This URL appears to be an HTTP endpoint. Consider selecting "HTTP" as the connection type.'
      });
      return false;
    }
    
    setUrlTypeWarning(null);
    return true;
  };
  
  // Build config from form
  const buildConfigFromForm = () => {
    if (!serverName.trim() || !serverUrl.trim()) {
      return null;
    }
    
    const serverConfig = {
      type: serverType,
      url: serverUrl.trim()
    };
    
    // Add headers if any are filled
    const filledHeaders = headers.filter(h => h.key.trim() && h.value.trim());
    if (filledHeaders.length > 0) {
      serverConfig.headers = {};
      filledHeaders.forEach(h => {
        serverConfig.headers[h.key.trim()] = h.value.trim();
      });
    } else {
      serverConfig.headers = {};
    }
    
    return {
      servers: {
        [serverName.trim()]: serverConfig
      }
    };
  };
  
  // Header management
  const addHeader = () => {
    setHeaders([...headers, { key: '', value: '' }]);
  };
  
  const removeHeader = (index) => {
    setHeaders(headers.filter((_, i) => i !== index));
  };
  
  const updateHeader = (index, field, value) => {
    const updated = [...headers];
    updated[index][field] = value;
    setHeaders(updated);
  };

  const handleScan = async () => {
    if (urlTypeWarning) {
      toast.error('Please resolve the URL type mismatch before scanning. Check the highlighted warning below the URL field.');
      return;
    }

    const builtConfig = buildConfigFromForm();
    if (!builtConfig) {
      toast.error('Please fill in all required fields');
      return;
    }
    const finalConfig = JSON.stringify(builtConfig, null, 2);

    // Create a pending scan entry immediately
    const pendingScan = {
      id: Date.now().toString(),
      timestamp: new Date().toISOString(),
      fileName: serverName,
      status: 'scanning',
      message: 'Scanning in progress...',
      data: null
    };
    
    // Add to history immediately
    const updated = [pendingScan, ...scanHistory].slice(0, 50);
    setScanHistory(updated);
    localStorage.setItem('mcp_scan_history', JSON.stringify(updated));
    
    // Set as selected scan and switch to active tab
    setSelectedScan(pendingScan);
    setActiveTab('active-scans');
    setLoading(true);

    try {
      const response = await apiClient.post('/mcp/scan', {
        config_file: finalConfig,
        file_name: serverName,
        scan_name: serverName,
        timeout: timeout
      });

      // Check if scan was successfully queued (backend returns status: "queued")
      if (response.scan_id || response.status === 'queued' || response.status === 'ok') {
        // Set pending for auto-active scan when passive completes
        if (response.scan_id) {
          agentFiredForScanRef.current = null; // reset guard for new scan
          setPendingActiveScanId(response.scan_id);
        }
        
        // Reload scans from database
        await loadScansFromDatabase();
        
        // Find the queued scan and set as selected
        const queuedScan = scanHistory.find(s => s.id === response.scan_id) || {
          ...pendingScan,
          id: response.scan_id,
          status: response.status || 'queued',
          data: response.data,
          message: response.message,
          completedAt: null
        };
        
        setSelectedScan(queuedScan);
        toast.success(response.message || 'Scan queued successfully!');
      } else {
        // Reload scans from database to get updated status
        await loadScansFromDatabase();
        toast.error(response.message || 'Scan failed');
      }
    } catch (error) {
      console.error('MCP scan error:', error);
      await loadScansFromDatabase();
      // Server returned a structured error — show it directly
      // Client-side failures (network down, etc.) get a generic message
      if (error.status) {
        toast.error(error.message, { duration: 6000 });
      } else {
        toast.error('Scan could not be started. Check your network and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const cancelScan = async (scanId) => {
    try {
      await apiClient.delete(`/mcp/scan/${scanId}`);
      toast.success('Scan cancelled successfully');
      // Reload scans from database
      await loadScansFromDatabase();
    } catch (error) {
      console.error('Error cancelling scan:', error);
      toast.error(error.status ? error.message : 'Failed to cancel scan');
    }
  };

  // DELETE FUNCTIONALITY - Admin only
  const deleteScan = async (scanId, scanName) => {
    if (!window.confirm(`Are you sure you want to permanently delete scan "${scanName}"? This action cannot be undone.`)) {
      return;
    }

    try {
      await apiClient.delete(`/mcp/scan/${scanId}`);
      toast.success('Scan deleted successfully');
      // Reload scans from database
      await loadScansFromDatabase();
    } catch (error) {
      console.error('Error deleting scan:', error);
      const errorMessage = error.status ? error.message : 'Failed to delete scan. You may not have permission.';
      toast.error(errorMessage);
    }
  };

  const toggleServer = (serverName) => {
    setExpandedServers(prev => ({
      ...prev,
      [serverName]: !prev[serverName]
    }));
  };

  const getStatusBadge = (status) => {
    const configs = {
      success: { icon: CheckCircle, color: 'bg-green-100 text-green-800', label: 'Success' },
      error: { icon: XCircle, color: 'bg-red-100 text-red-800', label: 'Error' },
      timeout: { icon: Clock, color: 'bg-yellow-100 text-yellow-800', label: 'Timeout' }
    };

    const config = configs[status] || configs.error;
    const Icon = config.icon;

    return (
      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${config.color}`}>
        <Icon className="w-3 h-3 mr-1" />
        {config.label}
      </span>
    );
  };

  const getScanStatusIcon = (status) => {
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

  const getScanStatusBadge = (status) => {
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

  // Helper to format date
  const formatDate = (isoString) => {
    const date = new Date(isoString);
    return date.toLocaleString();
  };

  // Modal functions
  const openResultsModal = (scan) => {
    setModalScan(scan);
    setShowResultsModal(true);
  };

  const closeResultsModal = () => {
    setShowResultsModal(false);
    setModalScan(null);
  };

  // Load the active findings the backend saved for a scan (active now runs
  // automatically in the scan worker alongside passive).
  const loadActiveResults = async (scanId) => {
    if (!scanId) return [];
    try {
      const resp = await apiClient.get(`/mcp/scan/${scanId}/active-results`);
      const findings = (resp && (resp.results || resp.findings || resp.active_results)) || [];
      const arr = Array.isArray(findings) ? findings : [];
      setSavedActiveResults(prev => ({ ...prev, [scanId]: arr }));
      return arr;
    } catch (e) {
      console.error('Failed to load active scan results:', e);
      return [];
    }
  };

  // When the Security Assessment modal opens for a scan (no live stream running),
  // pull the backend-saved active-scan findings — and keep polling for a few
  // minutes since active testing runs in the background after the passive scan.
  useEffect(() => {
    if (!activeScanStreaming) return;
    if (activeScanMessagesMap[activeScanStreaming] && activeScanMessagesMap[activeScanStreaming].length > 0) return;
    let cancelled = false;
    let tries = 0;
    loadActiveResults(activeScanStreaming);
    const iv = setInterval(async () => {
      tries += 1;
      const f = await loadActiveResults(activeScanStreaming);
      if (cancelled || (f && f.length > 0) || tries >= 40) clearInterval(iv); // ~4 min @ 6s
    }, 6000);
    return () => { cancelled = true; clearInterval(iv); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeScanStreaming]);

  const openTestModal = (scan) => {
    setTestModalScan(scan);
    setShowTestModal(true);
    // Pull backend-saved active results for this scan into the Active tab.
    loadActiveResults(scan.scan_id || scan.id);
  };

  const closeTestModal = () => {
    setShowTestModal(false);
    setTestModalScan(null);
    setSelectedTool(null);
    setToolArgs({});
    setExecutionResult(null);
    // Clear client simulation state
    setClientMessages([]);
    setClientPrompt('');
    setTrikshaAgentRunning(false);
    // Cancel any running simulation
    if (clientAbortController) {
      clientAbortController.abort();
      setClientAbortController(null);
    }
  };

  const generateSampleValues = (tool) => {
    if (!tool || !tool.input_schema || !tool.input_schema.properties) {
      return {};
    }
    
    const sampleValues = {};
    const properties = tool.input_schema.properties;
    
    Object.entries(properties).forEach(([argName, argSpec]) => {
      const lowerArgName = argName.toLowerCase();
      const description = (argSpec.description || '').toLowerCase();
      
      // Generate intelligent sample values based on argument name and type
      if (argSpec.type === 'boolean') {
        sampleValues[argName] = true;
      } else if (argSpec.type === 'number' || argSpec.type === 'integer') {
        if (lowerArgName.includes('port')) {
          sampleValues[argName] = 8080;
        } else if (lowerArgName.includes('timeout')) {
          sampleValues[argName] = 30;
        } else if (lowerArgName.includes('limit') || lowerArgName.includes('max')) {
          sampleValues[argName] = 10;
        } else {
          sampleValues[argName] = 1;
        }
      } else if (argSpec.type === 'array') {
        if (lowerArgName.includes('tag')) {
          sampleValues[argName] = ['example', 'test'];
        } else if (lowerArgName.includes('id')) {
          sampleValues[argName] = ['id1', 'id2'];
        } else {
          sampleValues[argName] = ['item1', 'item2'];
        }
      } else {
        // String type - most common
        if (lowerArgName.includes('repo') || description.includes('repository')) {
          sampleValues[argName] = 'facebook/react';
        } else if (lowerArgName.includes('url') || lowerArgName.includes('endpoint')) {
          sampleValues[argName] = 'https://api.example.com';
        } else if (lowerArgName.includes('email')) {
          sampleValues[argName] = 'user@example.com';
        } else if (lowerArgName.includes('key')) {
          sampleValues[argName] = 'example_key';
        } else if (lowerArgName.includes('id')) {
          sampleValues[argName] = 'example-id-123';
        } else if (lowerArgName.includes('name')) {
          sampleValues[argName] = 'example_name';
        } else if (lowerArgName.includes('path')) {
          sampleValues[argName] = '/path/to/resource';
        } else if (lowerArgName.includes('query') || lowerArgName.includes('question')) {
          sampleValues[argName] = 'What is this?';
        } else if (lowerArgName.includes('message') || lowerArgName.includes('text')) {
          sampleValues[argName] = 'Sample message';
        } else if (argSpec.enum && argSpec.enum.length > 0) {
          sampleValues[argName] = argSpec.enum[0];
        } else {
          sampleValues[argName] = `sample_${argName}`;
        }
      }
    });
    
    return sampleValues;
  };

  const fillSampleValues = () => {
    if (!selectedTool) return;
    const samples = generateSampleValues(selectedTool);
    setToolArgs(samples);
    toast.success('Sample values filled');
  };

  const handleExecuteTool = async () => {
    if (!selectedTool || !testModalScan) return;

    // Get server with tools
    const serverWithTools = testModalScan.data.servers.find(s => s.tools && s.tools.length > 0);
    if (!serverWithTools) {
      const failedServer = testModalScan.data.servers?.find(s => s.error_message);
      toast.error(failedServer ? failedServer.error_message : 'No server found with tools');
      return;
    }
    
    if (!serverWithTools.server_url) {
      toast.error('Server URL is missing');
      return;
    }
    
    setExecuting(true);
    setExecutionResult(null);
    
    console.log('Executing tool:', {
      server_url: serverWithTools.server_url,
      server_type: serverWithTools.server_type || 'http',
      tool_name: selectedTool.name,
      arguments: toolArgs
    });
    
    try {
      // apiClient.post returns the JSON response directly, not wrapped in .data
      const data = await apiClient.post('/mcp/tool/execute', {
        server_url: serverWithTools.server_url,
        server_type: serverWithTools.server_type || 'http',
        tool_name: selectedTool.name,
        arguments: toolArgs,
        headers: {}
      });
      
      console.log('Response received:', data);
      
      if (!data) {
        throw new Error('No response data received');
      }
      
      if (data.status === 'ok') {
        setExecutionResult({ success: true, data: data.result });
        toast.success('Tool executed successfully');
      } else {
        setExecutionResult({ success: false, error: data.message || 'Execution failed' });
        toast.error(data.message || 'Execution failed');
      }
    } catch (error) {
      console.error('Tool execution error:', error);
      const errorMsg = error.response?.data?.detail || error.response?.data?.message || error.message || 'Failed to execute tool';
      setExecutionResult({ success: false, error: errorMsg });
      toast.error(errorMsg);
    } finally {
      setExecuting(false);
    }
  };

  const handleAgentTakeover = async () => {
    if (!selectedTool || !testModalScan) return;

    // Get server with tools
    const serverWithTools = testModalScan.data.servers.find(s => s.tools && s.tools.length > 0);
    if (!serverWithTools) {
      const failedServer = testModalScan.data.servers?.find(s => s.error_message);
      toast.error(failedServer ? failedServer.error_message : 'No server found with tools');
      return;
    }
    
    if (!serverWithTools.server_url) {
      toast.error('Server URL is missing');
      return;
    }
    
    setAgentRunning(true);
    setAgentLogs([]);
    setAgentReport(null);
    setExecutionResult(null);
    setShowAgentLogs(true);
    
    console.log('Starting agent takeover for tool:', selectedTool.name);
    
    try {
      // Connect to SSE endpoint
      const response = await fetch('/mcp/tool/agent-test', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          server_url: serverWithTools.server_url,
          server_type: serverWithTools.server_type || 'http',
          tool_name: selectedTool.name,
          tool_description: selectedTool.description || '',
          tool_input_schema: selectedTool.input_schema || {},
          security_tests: testModalScan.data.security_summary?.tests || [],
          headers: {},
          // Pass FULL scan context for contextual analysis
          server_context: {
            server_name: serverWithTools.server_name,
            server_info: {
              capabilities: serverWithTools.capabilities || [],
              version: serverWithTools.version || 'unknown'
            },
            security_findings: {
              [selectedTool.name]: {
                pattern_based: serverWithTools.security_findings?.filter(f => f.tool_name === selectedTool.name) || [],
                capability_concerns: serverWithTools.capability_concerns || [],
                llm_threats: serverWithTools.llm_analysis?.threats || []
              }
            },
            all_tools: serverWithTools.tools?.map(t => t.name) || [],
            scan_summary: testModalScan.data.summary || {}
          }
        })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      // Read SSE stream
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      
      while (true) {
        const { done, value } = await reader.read();
        
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.substring(6));
              
              // Add log entry
              setAgentLogs(prev => [...prev, {
                type: data.type,
                timestamp: new Date().toISOString(),
                ...data.data
              }]);
              
              // Handle completion
              if (data.type === 'complete') {
                setAgentReport(data.data.report);
                toast.success('Agent testing complete!');
              }
              
              // Handle errors
              if (data.type === 'error') {
                toast.error(data.data.message);
              }

              // Active scanning needs an LLM API key — call it out clearly.
              if (data.type === 'needs_api_key') {
                toast.error('Active scan needs an LLM API key — set it up in Settings (your name → Settings).', { duration: 7000 });
              }

            } catch (e) {
              console.error('Error parsing SSE data:', e);
            }
          }
        }
      }

    } catch (error) {
      console.error('Agent error:', error);
      setAgentLogs(prev => [...prev, {
        type: 'error',
        timestamp: new Date().toISOString(),
        message: `Error: ${error.message}`
      }]);
      toast.error('Agent testing failed');
    } finally {
      setAgentRunning(false);
    }
  };

  // Client simulation - LLM-driven tool calling
  const handleClientSimulation = async () => {
    if (!clientPrompt.trim() || !testModalScan) return;
    
    const serverWithTools = testModalScan.data.servers.find(s => s.tools && s.tools.length > 0);
    if (!serverWithTools || !serverWithTools.server_url) {
      const failedServer = testModalScan.data.servers?.find(s => s.error_message);
      toast.error(failedServer ? failedServer.error_message : 'No server found with tools');
      return;
    }

    const userMessage = clientPrompt.trim();
    setClientPrompt('');
    setClientMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setClientProcessing(true);
    
    // Create abort controller for cancellation
    const abortController = new AbortController();
    setClientAbortController(abortController);
    
    try {
      const response = await fetch('/mcp/client/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        signal: abortController.signal,
        body: JSON.stringify({
          server_url: serverWithTools.server_url,
          server_type: serverWithTools.server_type || 'http',
          user_prompt: userMessage,
          tools: serverWithTools.tools || [],
          conversation_history: clientMessages,
          headers: {}
        })
      });
      
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      
      // Read SSE stream for real-time updates
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let assistantResponse = '';
      let toolCalls = [];
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.substring(6));
              
              if (data.type === 'thinking') {
                setClientMessages(prev => {
                  const last = prev[prev.length - 1];
                  if (last?.role === 'assistant' && last?.thinking) {
                    return [...prev.slice(0, -1), { ...last, content: data.data.message }];
                  }
                  return [...prev, { role: 'assistant', thinking: true, content: data.data.message }];
                });
              } else if (data.type === 'tool_call') {
                toolCalls.push(data.data);
                setClientMessages(prev => [...prev, { 
                  role: 'tool', 
                  tool_name: data.data.tool_name,
                  arguments: data.data.arguments,
                  status: 'calling'
                }]);
              } else if (data.type === 'tool_result') {
                setClientMessages(prev => prev.map(msg => 
                  msg.role === 'tool' && msg.tool_name === data.data.tool_name && msg.status === 'calling'
                    ? { ...msg, result: data.data.result, status: 'complete' }
                    : msg
                ));
              } else if (data.type === 'response') {
                assistantResponse = data.data.message;
              } else if (data.type === 'complete') {
                setClientMessages(prev => {
                  // Remove thinking message if present
                  const filtered = prev.filter(m => !m.thinking);
                  return [...filtered, { role: 'assistant', content: assistantResponse || data.data.message }];
                });
              } else if (data.type === 'needs_api_key') {
                const m = (data.data && data.data.message) || 'Client simulation needs an LLM API key — set it up in Settings (your name → Settings).';
                setClientMessages(prev => [...prev.filter(x => !x.thinking), { role: 'error', content: m }]);
                toast.error('Client simulation needs an LLM API key — set it up in Settings.', { duration: 7000 });
              }
            } catch (e) {
              console.error('Error parsing SSE:', e);
            }
          }
        }
      }
    } catch (error) {
      console.error('Client simulation error:', error);
      
      // Check if it was aborted
      if (error.name === 'AbortError') {
        setClientMessages(prev => [...prev, { 
          role: 'error', 
          content: 'Simulation cancelled by user' 
        }]);
        // Simulation cancelled - no toast needed
      } else {
        setClientMessages(prev => [...prev, { 
          role: 'error', 
          content: `Error: ${error.message}` 
        }]);
        toast.error('Client simulation failed');
      }
    } finally {
      setClientProcessing(false);
      setClientAbortController(null);
    }
  };

  const cancelClientSimulation = () => {
    if (clientAbortController) {
      clientAbortController.abort();
      setClientAbortController(null);
    }
  };

  const clearClientChat = () => {
    setClientMessages([]);
    setClientPrompt('');
    // Cancel any ongoing simulation
    if (clientProcessing || trikshaAgentRunning) {
      cancelClientSimulation();
      setTrikshaAgentRunning(false);
    }
  };

  // Fire Triksha Agent - Autonomous multi-turn security testing
  const fireTrikshaAgent = async () => {
    if (!testModalScan) return;
    
    const serverWithTools = testModalScan.data.servers.find(s => s.tools && s.tools.length > 0);
    if (!serverWithTools || !serverWithTools.server_url) {
      const failedServer = testModalScan.data.servers?.find(s => s.error_message);
      toast.error(failedServer ? failedServer.error_message : 'No server found with tools');
      return;
    }

    setTrikshaAgentRunning(true);
    setClientMessages([{ role: 'system', content: 'Triksha Agent activated - Starting autonomous security assessment...' }]);
    
    const abortController = new AbortController();
    setClientAbortController(abortController);
    
    try {
      const response = await fetch('/mcp/client/triksha-agent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        signal: abortController.signal,
        body: JSON.stringify({
          server_url: serverWithTools.server_url,
          server_type: serverWithTools.server_type || 'http',
          tools: serverWithTools.tools || [],
          server_context: {
            server_name: serverWithTools.server_name,
            security_findings: serverWithTools.security_findings || [],
            capability_concerns: serverWithTools.capability_concerns || [],
            scan_summary: testModalScan.data.summary || {}
          },
          headers: {}
        })
      });
      
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.substring(6));
              
              if (data.type === 'thinking') {
                setClientMessages(prev => [...prev, { 
                  role: 'agent', 
                  thinking: true, 
                  content: data.data.message 
                }]);
              } else if (data.type === 'attack_prompt') {
                setClientMessages(prev => [...prev, { 
                  role: 'attack', 
                  content: data.data.prompt,
                  attack_type: data.data.attack_type,
                  target_tool: data.data.target_tool
                }]);
              } else if (data.type === 'tool_call') {
                setClientMessages(prev => [...prev, { 
                  role: 'tool', 
                  tool_name: data.data.tool_name,
                  arguments: data.data.arguments,
                  status: 'calling'
                }]);
              } else if (data.type === 'tool_result') {
                setClientMessages(prev => prev.map(msg => 
                  msg.role === 'tool' && msg.tool_name === data.data.tool_name && msg.status === 'calling'
                    ? { ...msg, result: data.data.result, status: 'complete' }
                    : msg
                ));
              } else if (data.type === 'analysis') {
                setClientMessages(prev => [...prev, { 
                  role: 'analysis', 
                  content: data.data.message,
                  vulnerability_found: data.data.vulnerability_found,
                  severity: data.data.severity
                }]);
              } else if (data.type === 'turn_complete') {
                // Skip turn separators - don't show in UI
              } else if (data.type === 'vulnerability') {
                setClientMessages(prev => [...prev, { 
                  role: 'vulnerability', 
                  vulnerability_type: data.data.vulnerability_type,
                  severity: data.data.severity,
                  details: data.data.details,
                  recommendation: data.data.recommendation
                }]);
              } else if (data.type === 'complete') {
                console.log('[Test Modal] Complete event received:', {
                  message: data.data.message,
                  summary: data.data.summary,
                  hasSummary: !!data.data.summary
                });
                setClientMessages(prev => [...prev, { 
                  role: 'complete', 
                  content: data.data.message,
                  summary: data.data.summary
                }]);
                // Save findings to database when agent completes
                if (data.data.findings_for_db && data.data.findings_for_db.length > 0) {
                  const scanId = testModalScan?.scan_id || testModalScan?.id;
                  if (scanId) {
                    apiClient.post(`/mcp/scan/${scanId}/active-results`, {
                      findings: data.data.findings_for_db
                    }).then(() => {
                      console.log(`Active scan findings saved (${data.data.findings_for_db.length} results)`);
                      toast.success(`Saved ${data.data.findings_for_db.length} test results`);
                    }).catch(err => {
                      console.error('Failed to save active scan findings:', err);
                      toast.error('Failed to save test results');
                    });
                  }
                }
              } else if (data.type === 'error') {
                setClientMessages(prev => [...prev, {
                  role: 'error',
                  content: data.data.message
                }]);
              } else if (data.type === 'needs_api_key') {
                const m = (data.data && data.data.message) || 'Active scanning needs an LLM API key — set it up in Settings (your name → Settings).';
                setClientMessages(prev => [...prev, { role: 'error', content: m }]);
                toast.error('Active scanning needs an LLM API key — set it up in Settings.', { duration: 7000 });
              }
            } catch (e) {
              console.error('Error parsing SSE:', e);
            }
          }
        }
      }
    } catch (error) {
      if (error.name === 'AbortError') {
        setClientMessages(prev => [...prev, { role: 'error', content: 'Agent stopped by user' }]);
        // Agent stopped - no toast needed
      } else {
        console.error('Triksha agent error:', error);
        setClientMessages(prev => [...prev, { role: 'error', content: `Error: ${error.message}` }]);
        toast.error('Agent failed');
      }
    } finally {
      setTrikshaAgentRunning(false);
      setClientAbortController(null);
    }
  };

  // Auto-fire Triksha Agent inline in Active Scans tab (after passive scan completes)
  const autoFireTrikshaAgentInline = async (scan) => {
    if (!scan || !scan.data) return;
    
    const scanId = scan.id; // Get scan ID from the scan object
    
    const serverWithTools = scan.data.servers?.find(s => s.tools && s.tools.length > 0);
    if (!serverWithTools || !serverWithTools.server_url) {
      // Show the actual server error instead of generic message
      const failedServer = scan.data.servers?.find(s => s.error_message);
      const errorMsg = failedServer
        ? `${failedServer.server_name}: ${failedServer.error_message}`
        : 'No server found with tools for active scan';
      toast.error(errorMsg, { duration: 6000 });
      setActiveScanStreaming(null);
      setAgentRunningScanId(null); // Allow scan to move to past scans
      setInlineAgentRunning(false);
      agentFiredForScanRef.current = null; // reset guard so future scans work
      return;
    }
    
    // Active scan started - no additional toast needed (initial scan notification is sufficient)
    setInlineAgentRunning(true);
    setActiveScanMessagesMap(prev => ({
      ...prev,
      [scanId]: [{ role: 'system', content: 'Active Scan started - Triksha Agent performing security assessment...' }]
    }));
    
    const abortController = new AbortController();
    setClientAbortController(abortController);
    
    try {
      const response = await fetch('/mcp/client/triksha-agent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        signal: abortController.signal,
        body: JSON.stringify({
          scan_id: scanId,  // Pass scan ID for backend to save results directly
          server_url: serverWithTools.server_url,
          server_type: serverWithTools.server_type || 'http',
          tools: serverWithTools.tools || [],
          server_context: {
            server_name: serverWithTools.server_name,
            security_findings: serverWithTools.security_findings || [],
            capability_concerns: serverWithTools.capability_concerns || [],
            scan_summary: scan.data.summary || {}
          },
          headers: {}
        })
      });
      
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.substring(6));
              
              if (data.type === 'thinking') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'agent', thinking: true, content: data.data.message }]
                }));
              } else if (data.type === 'attack_prompt') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { 
                    role: 'attack', content: data.data.prompt, attack_type: data.data.attack_type, 
                    target_tool: data.data.target_tool, reasoning: data.data.reasoning 
                  }]
                }));
              } else if (data.type === 'tool_call') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'tool', tool_name: data.data.tool_name, arguments: data.data.arguments, status: 'calling' }]
                }));
              } else if (data.type === 'tool_result') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: (prev[scanId] || []).map(msg => 
                    msg.role === 'tool' && msg.tool_name === data.data.tool_name && msg.status === 'calling'
                      ? { ...msg, result: data.data.result, status: 'complete' } : msg
                  )
                }));
              } else if (data.type === 'analysis') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'analysis', content: data.data.message, vulnerability_found: data.data.vulnerability_found, severity: data.data.severity }]
                }));
              } else if (data.type === 'turn_complete') {
                // Skip turn separators - don't show in UI
              } else if (data.type === 'vulnerability') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'vulnerability', ...data.data }]
                }));
              } else if (data.type === 'complete') {
                console.log('[Active Scan] Complete event received:', {
                  message: data.data.message,
                  summary: data.data.summary,
                  hasSummary: !!data.data.summary,
                  scanId
                });
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'complete', content: data.data.message, summary: data.data.summary }]
                }));
                setInlineAgentRunning(false);
                setAgentRunningScanId(null); // Allow scan to move to past scans
                // Active scan complete - save findings to database
                if (data.data.findings_for_db && data.data.findings_for_db.length > 0) {
                  const saveScanId = scan.scan_id || scan.id || scanId;
                  console.log(`[Active Scan] Saving ${data.data.findings_for_db.length} findings for scan ${saveScanId}`);
                  if (saveScanId) {
                    apiClient.post(`/mcp/scan/${saveScanId}/active-results`, { findings: data.data.findings_for_db })
                      .then((response) => {
                        console.log(`[Active Scan] Successfully saved findings:`, response);
                        toast.success(`Saved ${data.data.findings_for_db.length} active scan results`);
                      })
                      .catch(err => {
                        console.error('[Active Scan] Failed to save findings:', err);
                        toast.error('Failed to save active scan results');
                      });
                  } else {
                    console.error('[Active Scan] No scan ID available for saving findings');
                  }
                } else {
                  console.log('[Active Scan] No findings to save (findings_for_db is empty or undefined)');
                }
              } else if (data.type === 'error') {
                setActiveScanMessagesMap(prev => ({
                  ...prev,
                  [scanId]: [...(prev[scanId] || []), { role: 'error', content: data.data.message }]
                }));
              }
            } catch (e) {
              console.error('Error parsing SSE:', e);
            }
          }
        }
      }
    } catch (error) {
      if (error.name !== 'AbortError') {
        console.error('Auto Triksha agent error:', error);
        setActiveScanMessagesMap(prev => ({
          ...prev,
          [scanId]: [...(prev[scanId] || []), { role: 'error', content: `Error: ${error.message}` }]
        }));
        toast.error('Active scan failed');
      }
    } finally {
      setInlineAgentRunning(false);
      setAgentRunningScanId(null); // Allow scan to move to past scans
      setClientAbortController(null);
      agentFiredForScanRef.current = null; // reset guard so future scans work
    }
  };

  // Auto-scroll inline agent log
  useEffect(() => {
    if (activeScanLogRef.current) {
      activeScanLogRef.current.scrollTop = activeScanLogRef.current.scrollHeight;
    }
  }, [activeScanMessagesMap]);

  const exportJSON = (scan) => {
    const dataStr = JSON.stringify(scan.data, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `mcp-scan-${scan.scanName || scan.fileName}-${scan.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Report exported as JSON');
  };

  const exportPDF = (scan) => {
    if (!scan || !scan.data) return;
    
    const summary = scan.data.summary;
    const servers = scan.data.servers || [];
    
    // Create printable HTML
    const printWindow = window.open('', '_blank');
    printWindow.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>MCP Scan Report - ${scan.scanName || scan.fileName}</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            padding: 40px;
            color: #333;
          }
          h1 {
            color: #2563eb;
            border-bottom: 3px solid #2563eb;
            padding-bottom: 10px;
          }
          h2 {
            color: #1e40af;
            margin-top: 30px;
          }
          .summary {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 20px 0;
          }
          .summary-card {
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
          }
          .summary-value {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
          }
          .summary-label {
            font-size: 14px;
            color: #6b7280;
          }
          .server {
            border: 1px solid #d1d5db;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            page-break-inside: avoid;
          }
          .server-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
          }
          .server-name {
            font-size: 18px;
            font-weight: bold;
          }
          .status-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
          }
          .status-success {
            background: #dcfce7;
            color: #166534;
          }
          .status-error {
            background: #fee2e2;
            color: #991b1b;
          }
          .info-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 15px;
          }
          .info-item {
            background: #f9fafb;
            padding: 10px;
            border-radius: 6px;
          }
          .info-label {
            font-size: 12px;
            color: #6b7280;
            margin-bottom: 5px;
          }
          .info-value {
            font-size: 16px;
            font-weight: 600;
          }
          @media print {
            body {
              padding: 20px;
            }
          }
        </style>
      </head>
      <body>
        <h1>MCP Scan Report</h1>
        <p><strong>Scan Name:</strong> ${scan.scanName || scan.fileName}</p>
        <p><strong>Scan Date:</strong> ${formatDate(scan.timestamp)}</p>
        <p><strong>Created By:</strong> ${scan.createdBy || 'anonymous'}</p>
        
        <h2>Summary</h2>
        <div class="summary">
          <div class="summary-card">
            <div class="summary-value">${summary.total_servers}</div>
            <div class="summary-label">Total Servers</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #16a34a">${summary.successful}</div>
            <div class="summary-label">Successful</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #dc2626">${summary.failed + summary.timeout}</div>
            <div class="summary-label">Failed/Timeout</div>
          </div>
          <div class="summary-card">
            <div class="summary-value" style="color: #2563eb">${summary.total_tools}</div>
            <div class="summary-label">Tools Discovered</div>
          </div>
        </div>
        
        <h2>Server Details</h2>
        ${servers.map(server => `
          <div class="server">
            <div class="server-header">
              <div class="server-name">${server.server_name}</div>
              <span class="status-badge status-${server.status === 'success' ? 'success' : 'error'}">
                ${server.status.toUpperCase()}
              </span>
            </div>
            <p><strong>Type:</strong> ${server.server_type}</p>
            ${server.error_message ? `<p style="color: #dc2626"><strong>Error:</strong> ${server.error_message}</p>` : ''}
            <div class="info-grid">
              <div class="info-item">
                <div class="info-label">Tools</div>
                <div class="info-value">${server.tools.length}</div>
              </div>
              <div class="info-item">
                <div class="info-label">Prompts</div>
                <div class="info-value">${server.prompts.length}</div>
              </div>
              <div class="info-item">
                <div class="info-label">Resources</div>
                <div class="info-value">${server.resources.length}</div>
              </div>
            </div>
          </div>
        `).join('')}
      </body>
      </html>
    `);
    
    printWindow.document.close();
    setTimeout(() => {
      printWindow.print();
      toast.success('Opening print dialog for PDF export');
    }, 250);
  };

  // Helper to render scan results
  const renderScanResults = (scan) => {
    if (!scan || !scan.data) return null;

    const scanData = scan.data;

    return (
      <>
        {/* Summary */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700 p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Summary</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <div className="text-2xl font-bold text-gray-900 dark:text-gray-100">{scanData.summary.total_servers}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Total Servers</div>
            </div>
            <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{scanData.summary.successful}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Successful</div>
            </div>
            <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <div className="text-2xl font-bold text-red-600">{scanData.summary.failed + scanData.summary.timeout}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Failed</div>
            </div>
            <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{scanData.summary.total_tools}</div>
              <div className="text-sm text-gray-600 dark:text-gray-400">Total Tools</div>
            </div>
          </div>
        </div>

        {/* Server Results */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border dark:border-gray-700">
          <div className="border-b border-gray-200 dark:border-gray-700 px-6 py-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Scanned Servers</h3>
          </div>
          
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {scanData.servers.map((server, index) => (
              <div key={index} className="p-6">
                {/* Server Header */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <Server className="w-5 h-5 text-gray-400" />
                    <div>
                      <h4 className="text-lg font-semibold text-gray-900 dark:text-gray-100">{server.server_name}</h4>
                      <p className="text-sm text-gray-500 dark:text-gray-400">Type: {server.server_type}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3">
                    {getStatusBadge(server.status)}
                    {server.status === 'success' && (
                      <button
                        onClick={() => toggleServer(server.server_name)}
                        className="text-primary-600 hover:text-primary-800 flex items-center text-sm font-medium"
                      >
                        {expandedServers[server.server_name] ? (
                          <>
                            <ChevronUp className="w-4 h-4 mr-1" />
                            Hide Details
                          </>
                        ) : (
                          <>
                            <ChevronDown className="w-4 h-4 mr-1" />
                            Show Details
                          </>
                        )}
                      </button>
                    )}
                  </div>
                </div>

                {/* Error Message */}
                {server.error_message && (
                  <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg flex items-start">
                    <AlertTriangle className="w-5 h-5 text-red-600 mr-2 flex-shrink-0 mt-0.5" />
                    <div className="text-sm text-red-800 dark:text-red-200">{server.error_message}</div>
                  </div>
                )}

                {/* Connection proof banner — shown on success so user knows the MCP handshake ran */}
                {server.status === 'success' && server.server_info && (
                  <div className="mb-4 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                    <div className="flex items-center gap-2 mb-1">
                      <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400 flex-shrink-0" />
                      <span className="text-xs font-semibold text-green-800 dark:text-green-300">MCP handshake completed</span>
                      <span className="text-xs text-green-700 dark:text-green-400 ml-1">
                        — {server.server_info.name} v{server.server_info.version} · protocol {server.protocol_version}
                      </span>
                    </div>
                    {server.capabilities && (
                      <div className="flex flex-wrap gap-2 mt-1.5">
                        {['tools', 'prompts', 'resources', 'logging'].map(cap => (
                          <span key={cap} className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                            server.capabilities[cap]
                              ? 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-300'
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 line-through'
                          }`}>
                            {cap}
                          </span>
                        ))}
                      </div>
                    )}
                    {server.status === 'success' && server.tools.length === 0 && !server.error_message && (
                      <p className="text-xs text-green-700 dark:text-green-400 mt-2">
                        {server.capabilities?.tools === false
                          ? 'Server did not advertise tools capability in its initialize response — list_tools was not called.'
                          : 'Server advertises tools capability but has no tools registered.'}
                      </p>
                    )}
                  </div>
                )}

                {/* Server Info (collapsed) */}
                {server.status === 'success' && !expandedServers[server.server_name] && (
                  <div className="grid grid-cols-4 gap-4">
                    <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
                      <Wrench className="w-5 h-5 text-blue-600 mx-auto mb-1" />
                      <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">{server.tools.length}</div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Tools</div>
                    </div>
                    <div className="text-center p-3 bg-purple-50 dark:bg-purple-900/20 rounded">
                      <MessageSquare className="w-5 h-5 text-purple-600 mx-auto mb-1" />
                      <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">{server.prompts.length}</div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Prompts</div>
                    </div>
                    <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded">
                      <FileCode className="w-5 h-5 text-green-600 mx-auto mb-1" />
                      <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">{server.resources.length}</div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Resources</div>
                    </div>
                    <div className="text-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                      <Layers className="w-5 h-5 text-yellow-600 mx-auto mb-1" />
                      <div className="text-lg font-semibold text-gray-900 dark:text-gray-100">{server.resource_templates.length}</div>
                      <div className="text-xs text-gray-600 dark:text-gray-400">Templates</div>
                    </div>
                  </div>
                )}

                {/* Expanded Details */}
                {server.status === 'success' && expandedServers[server.server_name] && (
                  <div className="space-y-6">
                    {/* Server Metadata */}
                    {server.server_info && (
                      <div>
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2">Server Information</h5>
                        <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-3 space-y-1">
                          <div className="text-sm text-gray-900 dark:text-gray-100"><span className="font-medium">Name:</span> {server.server_info.name}</div>
                          <div className="text-sm text-gray-900 dark:text-gray-100"><span className="font-medium">Version:</span> {server.server_info.version}</div>
                          <div className="text-sm text-gray-900 dark:text-gray-100"><span className="font-medium">Protocol:</span> {server.protocol_version}</div>
                        </div>
                      </div>
                    )}

                    {/* Tools */}
                    {server.tools.length > 0 && (
                      <div>
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center">
                          <Wrench className="w-4 h-4 mr-2 text-blue-600" />
                          Tools ({server.tools.length})
                        </h5>
                        <div className="space-y-2">
                          {server.tools.map((tool, idx) => (
                            <div key={idx} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <div className="font-medium text-gray-900 dark:text-gray-100">{tool.name}</div>
                              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{tool.description}</div>
                              {tool.input_schema && (
                                <details className="mt-2">
                                  <summary className="text-xs text-primary-600 cursor-pointer hover:text-primary-800">
                                    View Schema
                                  </summary>
                                  <pre className="mt-2 text-xs bg-gray-50 dark:bg-gray-900 p-2 rounded overflow-x-auto">
                                    {JSON.stringify(tool.input_schema, null, 2)}
                                  </pre>
                                </details>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Prompts */}
                    {server.prompts.length > 0 && (
                      <div>
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center">
                          <MessageSquare className="w-4 h-4 mr-2 text-purple-600" />
                          Prompts ({server.prompts.length})
                        </h5>
                        <div className="space-y-2">
                          {server.prompts.map((prompt, idx) => (
                            <div key={idx} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <div className="font-medium text-gray-900 dark:text-gray-100">{prompt.name}</div>
                              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{prompt.description}</div>
                              {prompt.arguments && prompt.arguments.length > 0 && (
                                <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                                  Arguments: {prompt.arguments.map(arg => arg.name).join(', ')}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Resources */}
                    {server.resources.length > 0 && (
                      <div>
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center">
                          <FileCode className="w-4 h-4 mr-2 text-green-600" />
                          Resources ({server.resources.length})
                        </h5>
                        <div className="space-y-2">
                          {server.resources.map((resource, idx) => (
                            <div key={idx} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <div className="font-medium text-gray-900 dark:text-gray-100">{resource.name}</div>
                              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{resource.uri}</div>
                              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{resource.description}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Resource Templates */}
                    {server.resource_templates.length > 0 && (
                      <div>
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-2 flex items-center">
                          <Layers className="w-4 h-4 mr-2 text-yellow-600" />
                          Resource Templates ({server.resource_templates.length})
                        </h5>
                        <div className="space-y-2">
                          {server.resource_templates.map((template, idx) => (
                            <div key={idx} className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <div className="font-medium text-gray-900 dark:text-gray-100">{template.name}</div>
                              <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">{template.uri_template}</div>
                              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{template.description}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </>
    );
  };

  return (
    <div className="space-y-3">
      {/* Header Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">MCP Security Scanner</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-0.5">
              Scan Model Context Protocol servers to discover and test tools, prompts, and resources
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Server className="h-8 w-8 text-primary-600 dark:text-primary-400" />
          </div>
        </div>
      </div>

      {/* Tab Navigation - Outside card to match Contextual Scan style */}
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
            onClick={() => setActiveTab('active-scans')}
            className={`py-4 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'active-scans'
                ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
            }`}
          >
            Active Scans {activeScans.length > 0 && `(${activeScans.length})`}
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
        <div className="p-6">
          {/* New Scan Tab */}
          {activeTab === 'new-scan' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Scan Configuration</h3>
                <div className="flex items-center space-x-3">
                  <LockedOverlay locked={!hasPermission('triksha.scan.run')} message="You do not have permission to run scans">
                    <button
                      onClick={handleScan}
                      disabled={loading || !serverName.trim() || !serverUrl.trim()}
                      className={`inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                        !loading && serverName.trim() && serverUrl.trim()
                          ? 'bg-primary-600 hover:bg-primary-700 text-white cursor-pointer'
                          : 'bg-gray-300 dark:bg-gray-600 text-gray-500 dark:text-gray-400 cursor-not-allowed'
                      }`}
                    >
                      {loading ? (
                        <>
                          <RefreshCw className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                          Starting Scan...
                        </>
                      ) : (
                        <>
                          <Play className="mr-1.5 h-3.5 w-3.5" />
                          Run Scan
                        </>
                      )}
                    </button>
                  </LockedOverlay>
                </div>
              </div>
              
              <>
                  {/* Form fields in grid layout like Scan.js */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Server Name */}
                  <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                        Server Name *
                    </label>
                    <input
                      type="text"
                      value={serverName}
                      onChange={(e) => setServerName(e.target.value)}
                      placeholder="e.g., deepwiki"
                        className="input"
                    />
                    </div>
        </div>
        
                  {/* Server Type and URL in grid */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                  {/* Server Type */}
                  <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                        Server Type *
                    </label>
                      <select
                        value={serverType}
                          onChange={(e) => {
                            setServerType(e.target.value);
                            validateUrlType(serverUrl, e.target.value);
                          }}
                        className="input"
                      >
                        <option value="http">HTTP</option>
                        <option value="sse">SSE (Server-Sent Events)</option>
                      </select>
                  </div>
                  
                  {/* Server URL */}
                    <div className="md:col-span-3">
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                        Server URL *
                    </label>
                    <input
                      type="url"
                      value={serverUrl}
                      onChange={(e) => {
                        setServerUrl(e.target.value);
                        validateUrlType(e.target.value, serverType);
                      }}
                      placeholder="https://mcp.example.com/mcp"
                        className={`input ${
                        urlTypeWarning 
                          ? 'border-yellow-500 dark:border-yellow-400 ring-2 ring-yellow-200 dark:ring-yellow-900' 
                            : ''
                        }`}
                    />
                    {urlTypeWarning && (
                      <div className="mt-2 flex items-start space-x-2 p-2 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                        <AlertTriangle className="h-4 w-4 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                        <div className="flex-1">
                          <p className="text-sm text-yellow-700 dark:text-yellow-300">{urlTypeWarning.message}</p>
                          <button
                            type="button"
                            onClick={() => {
                              const suggestedType = urlTypeWarning.type === 'sse-suggested' ? 'sse' : 'http';
                              setServerType(suggestedType);
                              setUrlTypeWarning(null);
                            }}
                            className="mt-1 text-xs font-medium text-yellow-800 dark:text-yellow-200 underline hover:no-underline"
                          >
                            Switch to {urlTypeWarning.type === 'sse-suggested' ? 'SSE' : 'HTTP'}
                          </button>
                        </div>
                      </div>
                    )}
                    </div>
                  </div>
                  
                  {/* Headers and Timeout in a row */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    {/* Timeout */}
                  <div>
                      <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                        Timeout (seconds)
                      </label>
                      <input
                        type="number"
                        value={timeout}
                        onChange={(e) => setTimeout(parseInt(e.target.value) || 30)}
                        min="5"
                        max="120"
                        className="input"
                      />
                    </div>
                    
                    {/* Headers */}
                    <div className="md:col-span-3">
                    <div className="flex items-center justify-between mb-2">
                        <label className="block text-sm font-medium text-gray-900 dark:text-gray-100">
                        Headers (Optional)
                      </label>
                      <button
                        onClick={addHeader}
                        className="text-xs text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
                      >
                        + Add Header
                      </button>
                    </div>
                    <div className="space-y-2">
                      {headers.map((header, index) => (
                        <div key={index} className="flex items-center space-x-2">
                          <input
                            type="text"
                            value={header.key}
                            onChange={(e) => updateHeader(index, 'key', e.target.value)}
                            placeholder="Header name"
                              className="input flex-1 text-sm"
                          />
                          <input
                            type="text"
                            value={header.value}
                            onChange={(e) => updateHeader(index, 'value', e.target.value)}
                            placeholder="Header value"
                              className="input flex-1 text-sm"
                          />
                          {headers.length > 1 && (
                            <button
                              onClick={() => removeHeader(index)}
                              className="p-2 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                  </div>
              </>

            </div>
          )}

          {/* Active Scans Tab */}
          {activeTab === 'active-scans' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Active Scans</h3>
                <button 
                  onClick={loadScansFromDatabase} 
                  className="btn-outline btn-sm"
                  disabled={loading}
                  aria-label="Refresh scans list"
                >
                  <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
                  {loading ? 'Refreshing…' : 'Refresh'}
                </button>
              </div>

              {loading ? (
                <div className="space-y-2">
                  {[...Array(3)].map((_, i) => (
                    <div key={i} className="animate-pulse h-16 bg-gray-100 dark:bg-gray-700 rounded-md border border-gray-200 dark:border-gray-600" />
                  ))}
                </div>
              ) : activeScans.length === 0 ? (
                <div className="text-center py-12">
                  <Server className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active scans</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Get started by creating a new MCP security scan.</p>
                </div>
              ) : (
                <div className={`space-y-4 transition-opacity duration-200 ${loading ? 'opacity-75' : 'opacity-100'}`}>
                  {activeScans.map((scan) => {
                    const isAgentRunning = scan.id === agentRunningScanId;
                    const isStartingAgent = scan.id === pendingActiveScanId && scan.status === 'completed';
                    const isPassiveScanning = !isAgentRunning && !isStartingAgent;
                    const effectiveStatus = isAgentRunning ? 'running' : isStartingAgent ? 'pending' : scan.status;
                    
                    return (
                    <div key={scan.id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          {getScanStatusIcon(effectiveStatus)}
                          <div>
                            <div className="flex items-center gap-2">
                              <h4 className="text-sm font-medium text-gray-900 dark:text-white">{scan.scanName || scan.fileName}</h4>
                              {isAgentRunning ? (
                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
                                  <Activity className="h-3 w-3 mr-1 animate-pulse" />
                                  Agent Running
                                </span>
                              ) : isStartingAgent ? (
                                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300">
                                  <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
                                  Starting Agent
                                </span>
                              ) : (
                                getScanStatusBadge(scan.status)
                              )}
                            </div>
                            <div className="flex items-center gap-3 text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                              <span>ID: {scan.id}</span>
                              {scan.createdBy && (
                                <span className="inline-flex items-center">
                                  by {scan.createdBy}
                                </span>
                              )}
                              {scan.serverCount != null && (
                                <span className="inline-flex items-center">
                                  <Server className="h-3 w-3 mr-1" />
                                  {scan.serverCount} servers
                                </span>
                              )}
                              {scan.toolCount != null && (
                                <span className="inline-flex items-center">
                                  <Wrench className="h-3 w-3 mr-1" />
                                  {scan.toolCount} tools
                                </span>
                              )}
                            </div>
                            {/* Show error message when scan failed/cancelled */}
                            {(scan.status === 'failed' || scan.status === 'cancelled') && scan.message && (
                              <p className="text-xs text-red-600 dark:text-red-400 mt-1">{scan.message}</p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {/* Circular progress for passive scans */}
                          {scan.progress !== undefined && isPassiveScanning && scan.status === 'running' && (() => {
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
                          {(scan.status === 'running' || scan.status === 'queued' || isAgentRunning || isStartingAgent) && (() => {
                            const canCancel = isAdmin || scan.createdBy === user?.id || scan.createdBy === user?.email;
                            return (
                            <button
                              onClick={() => {
                                if (!canCancel) {
                                  toast.error('You do not have permission to cancel this scan');
                                  return;
                                }
                                cancelScan(scan.id);
                              }}
                              disabled={!canCancel}
                              className={`inline-flex items-center px-3 py-1.5 text-xs font-medium rounded-md border transition-colors
                                ${!canCancel
                                  ? 'bg-gray-100 dark:bg-gray-700 text-gray-400 dark:text-gray-500 border-gray-200 dark:border-gray-600 cursor-not-allowed'
                                  : 'bg-red-50 dark:bg-red-950/40 text-red-600 dark:text-red-400 border-red-200 dark:border-red-800/50 hover:bg-red-100 dark:hover:bg-red-900/40'
                                }`}
                              title={canCancel ? 'Cancel scan' : 'You do not have permission to cancel this scan'}
                            >
                              <StopCircle className="h-3.5 w-3.5 mr-1" />
                              Cancel
                            </button>
                            );
                          })()}
                          <button
                            onClick={() => {
                              if (activeScanStreaming === scan.id) {
                                setActiveScanStreaming(null);
                              } else {
                                setActiveScanStreaming(scan.id);
                              }
                            }}
                            className={`inline-flex items-center px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                              activeScanStreaming === scan.id
                                ? 'bg-primary-100 dark:bg-primary-900/40 text-primary-700 dark:text-primary-300 border-primary-200 dark:border-primary-800/50'
                                : isAgentRunning
                                  ? 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/30 border-primary-200 dark:border-primary-800/50 animate-pulse'
                                  : 'bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300 hover:bg-primary-100 dark:hover:bg-primary-900/30 border-primary-200 dark:border-primary-800/50'
                            }`}
                            title={activeScanStreaming === scan.id ? "Hide conversation" : isAgentRunning ? "View live agent activity" : "Show activity"}
                          >
                            <Eye className="h-3.5 w-3.5 mr-1" />
                            {activeScanStreaming === scan.id ? 'Hide' : isAgentRunning ? 'Live View' : 'View'}
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Past Scans Tab */}
          {activeTab === 'past-scans' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between gap-3 flex-wrap">
                {/* Ownership classification — same pattern as LLM Scan / Prompts. */}
                <select
                  className="select h-9 w-auto"
                  value={pastSubTab}
                  onChange={(e) => setPastSubTab(e.target.value)}
                  aria-label="Filter scans by ownership"
                >
                  <option value="my-scans">My Scans</option>
                  <option value="other-scans">Other Scans</option>
                </select>
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <input
                    type="text"
                    className="input h-9 flex-1 min-w-0"
                    placeholder="Search by name or ID"
                    value={pastSearch}
                    onChange={(e) => setPastSearch(e.target.value)}
                    aria-label="Search past scans"
                  />
                  <select
                    className="select h-9 w-auto"
                    value={pastStatus}
                    onChange={(e) => setPastStatus(e.target.value)}
                    aria-label="Filter by status"
                  >
                    <option value="all">All statuses</option>
                    <option value="success">Successful</option>
                    <option value="error">Failed</option>
                  </select>
                </div>
              </div>

              {pastScans.length === 0 ? (
                <div className="text-center py-12">
                  <Server className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No past scans</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    {pastSearch || pastStatus !== 'all' 
                      ? 'No scans match your filters.' 
                      : 'Your scan history will appear here.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-4">
                  {paginatedPastScans.map((scan) => {
                    // Check if we have results data
                    const hasResults = scan.data && scan.data.summary;

                    // Get server type from first server
                    const serverType = hasResults && scan.data.servers?.[0]?.server_type;

                    
                    // Get status icon based on scan status
                    const getStatusIcon = () => {
                      if (scan.status === 'completed') {
                        return <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />;
                      } else if (scan.status === 'failed') {
                        return <XCircle className="w-5 h-5 text-red-600 dark:text-red-400" />;
                      } else if (scan.status === 'cancelled') {
                        return <XCircle className="w-5 h-5 text-orange-600 dark:text-orange-400" />;
                      }
                      return <Clock className="w-5 h-5 text-gray-400" />;
                    };
                    
                    return (
                      <div key={scan.id} className={`border rounded-lg p-4 ${
                        scan.status === 'failed' || scan.status === 'cancelled'
                          ? 'border-red-200 dark:border-red-800/50'
                          : 'border-gray-200 dark:border-gray-700'
                      }`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            {getStatusIcon()}
                            <div>
                              <h4 className="text-sm font-medium text-gray-900 dark:text-white">{scan.scanName || scan.fileName}</h4>
                              <p className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-2 flex-wrap">
                                <span>ID: {scan.id}</span>
                                {serverType && (
                                  <span className="uppercase font-medium text-primary-600 dark:text-primary-400">• {serverType}</span>
                                )}
                                {scan.createdBy && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="text-gray-300 dark:text-gray-600">·</span>
                                    by <span className="text-gray-700 dark:text-gray-300">{scan.createdBy}</span>
                                  </span>
                                )}
                              </p>
                                </div>
                              </div>
                          <div className="flex items-center space-x-2">
                            <div className="flex space-x-1">
                              {/* Info button — always visible */}
                              <button
                                onClick={() => { setScanInfoData(scan); setShowScanInfoModal(true); }}
                                className="btn-outline btn-sm"
                                title="View scan configuration details"
                              >
                                <Info className="h-4 w-4" />
                              </button>
                              {/* Results, Test, Delete — hidden for other users' scans unless admin */}
                              {(pastSubTab !== 'other-scans' || isAdmin) && (<>
                            {(hasResults || (scan.status === 'failed' && scan.data)) && (
                              <LockedOverlay locked={!hasPermission('triksha.scan.view-past-results') || !canAccessScan(scan.createdBy)} message="You do not have permission to view details of this scan">
                                <button
                                  onClick={() => openResultsModal(scan)}
                                  className="btn-outline btn-sm"
                                  title="View results"
                                >
                                  <Eye className="h-4 w-4 mr-1" />
                                  Results
                                </button>
                              </LockedOverlay>
                            )}
                            {hasResults && scan.data?.servers?.some(s => s.tools?.length > 0) && (
                              <LockedOverlay locked={!hasPermission('triksha.scan.run') || !canAccessScan(scan.createdBy)} message="You do not have permission to test this scan">
                                <button
                                  onClick={() => openTestModal(scan)}
                                  className="btn-outline btn-sm"
                                  title="Test the MCP server yourself"
                                >
                                  <Activity className="h-4 w-4 mr-1" />
                                  Test Server
                                </button>
                              </LockedOverlay>
                            )}
                            <LockedOverlay locked={!hasPermission('triksha.scan.delete') || !canAccessScan(scan.createdBy)} message="You do not have permission to delete this scan">
                              <button
                                onClick={() => deleteScan(scan.id, scan.scan_name)}
                                className="btn-outline btn-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30"
                                title="Delete scan permanently"
                              >
                                <Trash2 className="h-4 w-4" />
                              </button>
                            </LockedOverlay>
                              </>)}
                          </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}

                  {/* Pagination Controls */}
                  {pastScans.length > SCANS_PER_PAGE && (
                    <div className="flex items-center justify-between mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
                      <div className="text-sm text-gray-700 dark:text-gray-300">
                        Showing <span className="font-medium">{((currentPage - 1) * SCANS_PER_PAGE) + 1}</span> to{' '}
                        <span className="font-medium">{Math.min(currentPage * SCANS_PER_PAGE, pastScans.length)}</span> of{' '}
                        <span className="font-medium">{pastScans.length}</span> scans
                      </div>
                      
                      <div className="flex items-center gap-2">
                        {/* Previous Button */}
                        <button
                          onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                          disabled={currentPage === 1}
                          className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          aria-label="Previous page"
                        >
                          <ChevronLeft className="h-4 w-4" />
                        </button>

                        {/* Page Numbers */}
                        <div className="flex items-center gap-1">
                          {Array.from({ length: totalPages }, (_, i) => i + 1).map(pageNum => {
                            // Show first page, last page, current page, and pages around current
                            const showPage = 
                              pageNum === 1 || 
                              pageNum === totalPages || 
                              (pageNum >= currentPage - 1 && pageNum <= currentPage + 1);
                            
                            const showEllipsis = 
                              (pageNum === 2 && currentPage > 3) || 
                              (pageNum === totalPages - 1 && currentPage < totalPages - 2);

                            if (!showPage && !showEllipsis) return null;

                            if (showEllipsis) {
                              return (
                                <span key={pageNum} className="px-2 text-gray-500 dark:text-gray-400">
                                  ...
                                </span>
                              );
                            }

                            return (
                              <button
                                key={pageNum}
                                onClick={() => setCurrentPage(pageNum)}
                                className={`min-w-[2.5rem] px-3 py-2 text-sm font-medium rounded-md transition-colors ${
                                  currentPage === pageNum
                                    ? 'bg-primary-600 text-white'
                                    : 'text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700'
                                }`}
                                aria-label={`Go to page ${pageNum}`}
                                aria-current={currentPage === pageNum ? 'page' : undefined}
                              >
                                {pageNum}
                              </button>
                            );
                          })}
                        </div>

                        {/* Next Button */}
                        <button
                          onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                          disabled={currentPage === totalPages}
                          className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                          aria-label="Next page"
                        >
                          <ChevronRight className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Show selected scan results */}
              {selectedScan && (
                <div className="mt-6">
                  {renderScanResults(selectedScan)}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {/* Security Results Modal */}
      {showResultsModal && modalScan && modalScan.data && (
        <MCPSecurityModal 
          scan={modalScan} 
          onClose={closeResultsModal}
        />
      )}

      {/* Agent Conversation Modal */}
      {activeScanStreaming && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center">
          <div className="fixed inset-0 bg-black/50" onClick={() => setActiveScanStreaming(null)} />
          <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl border border-gray-200 dark:border-gray-700 w-full max-w-5xl max-h-[85vh] overflow-hidden z-[101] flex flex-col">
            {/* Header */}
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between flex-shrink-0">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Security Assessment
                </h3>
                {inlineAgentRunning && (
                  <span className="inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    Running
                  </span>
                )}
                {!inlineAgentRunning && (activeScanMessagesMap[activeScanStreaming]?.some(m => m.role === 'complete')
                  || savedActiveResults[activeScanStreaming]?.length > 0) && (
                  <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300">
                    Complete
                  </span>
                )}
              </div>
              <button
                onClick={() => setActiveScanStreaming(null)}
                className="btn-outline btn-sm"
              >
                Close
              </button>
            </div>
            
            {/* Conversation Body */}
            <div ref={activeScanLogRef} className="flex-1 overflow-y-auto p-6 space-y-3 bg-gray-50 dark:bg-gray-900">
              {(!activeScanMessagesMap[activeScanStreaming] || activeScanMessagesMap[activeScanStreaming].length === 0) ? (
                (savedActiveResults[activeScanStreaming] && savedActiveResults[activeScanStreaming].length > 0) ? (
                  <div className="space-y-3">
                    {savedActiveResults[activeScanStreaming].map((f, idx) => (
                      <div key={idx} className={`rounded-xl border p-4 ${f.vulnerability_found
                        ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
                        : 'border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800'}`}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-sm font-semibold text-gray-800 dark:text-gray-100">
                            {f.tool_name || 'tool'}{f.attack_type ? ` · ${String(f.attack_type).replace(/_/g, ' ')}` : ''}
                          </span>
                          {f.severity && (
                            <span className={`text-xs px-2 py-0.5 rounded-full ${/(high|critical)/i.test(f.severity)
                              ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                              : /medium/i.test(f.severity)
                                ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300'
                                : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300'}`}>
                              {f.severity}
                            </span>
                          )}
                        </div>
                        {f.vulnerability_type && (
                          <div className="text-xs text-red-600 dark:text-red-400 mb-1">{f.vulnerability_type}</div>
                        )}
                        {f.details && (
                          <div className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{f.details}</div>
                        )}
                        {f.recommendation && (
                          <div className="mt-2 text-xs text-gray-500 dark:text-gray-400"><b>Fix:</b> {f.recommendation}</div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-sm text-gray-500 dark:text-gray-400 text-center py-12">
                    <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-3 text-primary-500" />
                    <div className="italic">Active testing is running in the background…</div>
                    <div className="text-xs mt-1">The autonomous agent probes each tool over multiple turns — this can take a few minutes. Results appear here automatically (this view refreshes every few seconds). Requires an LLM API key in Settings.</div>
                  </div>
                )
              ) : (
                activeScanMessagesMap[activeScanStreaming].filter(msg => 
                  // Filter out turn separators and "Ready to run X tests" messages
                  msg.role !== 'turn_separator' && 
                  !(msg.role === 'agent' && msg.thinking && msg.content.includes('Ready to run'))
                ).map((msg, idx) => (
                  <div key={idx} className={`flex ${(msg.role === 'user' || msg.role === 'attack') ? 'justify-end' : (msg.role === 'system' || msg.role === 'complete') ? 'justify-center' : 'justify-start'}`}>
                    {msg.role === 'system' ? (
                      <span className="text-xs text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 px-3 py-1 rounded-full">
                        {msg.content}
                      </span>
                    ) : msg.role === 'agent' ? (
                      <div className="max-w-2xl bg-gray-100 dark:bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-2 text-gray-700 dark:text-gray-200 text-sm">
                        {msg.content}
                      </div>
                    ) : msg.role === 'attack' ? (
                      <div className="max-w-2xl bg-blue-500 text-white rounded-2xl rounded-br-sm px-4 py-2">
                        <div className="text-xs text-blue-200 mb-1">{msg.attack_type?.replace(/_/g, ' ')}</div>
                        <div className="text-sm">{msg.content}</div>
                      </div>
                    ) : msg.role === 'tool' ? (
                      msg.status === 'calling' ? (
                        <div className="text-gray-400 text-sm italic">typing...</div>
                      ) : (
                        <div className="max-w-2xl bg-gray-100 dark:bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-2">
                          <div className="text-sm text-gray-700 dark:text-gray-300 font-mono overflow-x-auto max-h-32">
                            <pre className="whitespace-pre-wrap text-xs">{typeof msg.result === 'string' ? msg.result : JSON.stringify(msg.result?.content?.[0]?.text || msg.result, null, 2)}</pre>
                          </div>
                        </div>
                      )
                    ) : msg.role === 'analysis' ? (
                      <div className={`max-w-2xl rounded-2xl rounded-bl-sm px-4 py-2 ${
                        msg.vulnerability_found 
                          ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' 
                          : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                      }`}>
                        {msg.vulnerability_found && msg.severity && (
                          <span className={`inline-block text-xs px-2 py-0.5 rounded mr-2 ${
                            msg.severity === 'critical' ? 'bg-red-600 text-white' :
                            msg.severity === 'high' ? 'bg-orange-500 text-white' :
                            'bg-yellow-500 text-black'
                          }`}>
                            {msg.severity.toUpperCase()}
                          </span>
                        )}
                        <span className="text-sm">{msg.content}</span>
                      </div>
                    ) : msg.role === 'vulnerability' ? (
                      <div className="max-w-2xl bg-red-100 dark:bg-red-900/30 border-l-4 border-red-500 rounded-r-lg px-4 py-2">
                        <div className="font-medium text-red-700 dark:text-red-300 text-sm">{msg.vulnerability_type || msg.title}</div>
                        <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">{msg.details || msg.description}</div>
                      </div>
                    ) : msg.role === 'complete' ? (
                      <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-3">
                        <div className="font-medium text-gray-800 dark:text-gray-200 text-sm">Assessment Complete</div>
                        {msg.summary && (
                          <div className="flex gap-3 text-xs mt-1 text-gray-500">
                            <span>{msg.summary.total_tests || 0} tests</span>
                            <span className={msg.summary.vulnerabilities > 0 ? 'text-red-600' : 'text-green-600'}>
                              {msg.summary.vulnerabilities || 0} issues
                            </span>
                          </div>
                        )}
                      </div>
                    ) : msg.role === 'error' ? (
                      <div className="max-w-2xl bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg px-4 py-2 text-sm">
                        {msg.content}
                      </div>
                    ) : null}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* API Test Modal */}
      {showTestModal && testModalScan && testModalScan.data && (() => {
        // Get first server with tools
        const serverWithTools = testModalScan.data.servers.find(s => s.tools && s.tools.length > 0);
        
        if (!serverWithTools) {
          return null;
        }
        
        return (
          <div className="fixed inset-0 z-50 overflow-y-auto">
            <div className="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
              {/* Backdrop */}
              <div className="fixed inset-0 transition-opacity bg-gray-500 dark:bg-gray-900 bg-opacity-75" onClick={closeTestModal} />
              
              {/* Modal */}
              <div className="inline-block align-bottom bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-7xl sm:w-full">
                {/* Header */}
                <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Activity className="h-6 w-6 text-white" />
                      <div>
                        <h3 className="text-lg font-semibold text-white">Test MCP Tools - {testModalScan.scanName}</h3>
                        <p className="text-sm text-primary-100 mt-1">
                          {serverWithTools.server_url || 'MCP Server'}
                        </p>
                      </div>
                    </div>
                    <button onClick={closeTestModal} className="text-white hover:text-gray-200">
                      <X className="h-6 w-6" />
                    </button>
                  </div>
                </div>
                
                {/* Mode Toggle */}
                <div className="px-6 py-3 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700">
                  <div className="flex items-center space-x-4">
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Mode:</span>
                    <div className="flex rounded-lg bg-gray-200 dark:bg-gray-700 p-1">
                      <button
                        onClick={() => setTestMode('manual')}
                        className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all ${
                          testMode === 'manual'
                            ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow'
                            : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                        }`}
                      >
                        Manual Testing
                      </button>
                      <button
                        onClick={() => setTestMode('client')}
                        className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all ${
                          testMode === 'client'
                            ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow'
                            : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                        }`}
                      >
                        Client Simulation
                      </button>
                    </div>
                    {testMode === 'client' && (
                      <span className="text-xs text-gray-500 dark:text-gray-400">
                        💡 The LLM decides which tool to call based on your natural language request
                      </span>
                    )}
                  </div>
                </div>
                
                {/* Split View Content */}
                <div className="flex" style={{ height: 'calc(85vh - 130px)' }}>
                  {testMode === 'client' ? (
                    /* CLIENT SIMULATION MODE */
                    <div className="w-full flex flex-col relative">
                      {/* Chat Messages */}
                      <div className="flex-1 overflow-y-auto p-6 space-y-4">
                        {clientMessages.length === 0 ? (
                          <div className="text-center py-12">
                            <MessageSquare className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                            <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                              Client Simulation Mode
                            </h4>
                            <p className="text-gray-500 dark:text-gray-400 max-w-md mx-auto">
                              Type a natural language request and the LLM will decide which tool to call.
                              This simulates how a real MCP client would interact with the server.
                            </p>
                            <div className="mt-4 text-sm text-gray-400">
                              <p>Example requests:</p>
                              <p className="text-green-600 dark:text-green-400">"Get information about user john"</p>
                              <p className="text-green-600 dark:text-green-400">"What credentials are stored?"</p>
                            </div>
                          </div>
                        ) : (
                          clientMessages.filter(msg => 
                            // Filter out turn separators and "Ready to run" messages, but keep "Found X tool(s)"
                            msg.role !== 'turn_separator' &&
                            !(msg.role === 'agent' && msg.thinking && msg.content.includes('Ready to run'))
                          ).map((msg, idx) => (
                            <div key={idx} className={`flex ${(msg.role === 'user' || msg.role === 'attack') ? 'justify-end' : (msg.role === 'system' || msg.role === 'complete') ? 'justify-center' : 'justify-start'}`}>
                              {msg.role === 'user' ? (
                                <div className="max-w-2xl bg-blue-600 text-white rounded-lg px-4 py-2">
                                  {msg.content}
                                </div>
                              ) : msg.role === 'assistant' ? (
                                <div className={`max-w-2xl rounded-lg px-4 py-2 ${
                                  msg.thinking 
                                    ? 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 italic'
                                    : 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                                }`}>
                                  {msg.content}
                                </div>
                              ) : msg.role === 'system' ? (
                                <span className="text-xs text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 px-3 py-1 rounded-full">
                                  {msg.content}
                                </span>
                              ) : msg.role === 'agent' ? (
                                <div className="max-w-md bg-gray-100 dark:bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-2 text-gray-700 dark:text-gray-200 text-sm">
                                  {msg.content}
                                </div>
                              ) : msg.role === 'attack' ? (
                                <div className="max-w-md bg-blue-500 text-white rounded-2xl rounded-br-sm px-4 py-2">
                                  <div className="text-xs text-blue-200 mb-1">{msg.attack_type?.replace(/_/g, ' ')}</div>
                                  <div className="text-sm">{msg.content}</div>
                                </div>
                              ) : msg.role === 'tool' ? (
                                msg.status === 'calling' ? (
                                  <div className="text-gray-400 text-sm italic">typing...</div>
                                ) : (
                                  <div className="max-w-md bg-gray-100 dark:bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-2">
                                    <div className="text-sm text-gray-700 dark:text-gray-300 font-mono overflow-x-auto max-h-24">
                                      <pre className="whitespace-pre-wrap text-xs">{typeof msg.result === 'string' ? msg.result : JSON.stringify(msg.result?.content?.[0]?.text || msg.result, null, 2)}</pre>
                                    </div>
                                  </div>
                                )
                              ) : msg.role === 'analysis' ? (
                                <div className={`max-w-md rounded-2xl rounded-bl-sm px-4 py-2 ${
                                  msg.vulnerability_found 
                                    ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' 
                                    : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                                }`}>
                                  {msg.vulnerability_found && msg.severity && (
                                    <span className={`inline-block text-xs px-2 py-0.5 rounded mr-2 ${
                                      msg.severity === 'critical' ? 'bg-red-600 text-white' :
                                      msg.severity === 'high' ? 'bg-orange-500 text-white' :
                                      'bg-yellow-500 text-black'
                                    }`}>
                                      {msg.severity.toUpperCase()}
                                    </span>
                                  )}
                                  <span className="text-sm">{msg.content}</span>
                                </div>
                              ) : msg.role === 'vulnerability' ? (
                                <div className="max-w-md bg-red-100 dark:bg-red-900/30 border-l-4 border-red-500 rounded-r-lg px-4 py-2">
                                  <div className="font-medium text-red-700 dark:text-red-300 text-sm">{msg.vulnerability_type}</div>
                                  <div className="text-xs text-gray-600 dark:text-gray-400 mt-1">{msg.details}</div>
                                </div>
                              ) : msg.role === 'complete' ? (
                                <div className="bg-gray-100 dark:bg-gray-700 rounded-lg px-4 py-3">
                                  <div className="font-medium text-gray-800 dark:text-gray-200 text-sm">Assessment Complete</div>
                                  {msg.summary && (
                                    <div className="flex gap-3 text-xs mt-1 text-gray-500">
                                      <span>{msg.summary.total_tests || 0} tests</span>
                                      <span className={msg.summary.vulnerabilities > 0 ? 'text-red-600' : 'text-green-600'}>
                                        {msg.summary.vulnerabilities || 0} issues
                                      </span>
                                    </div>
                                  )}
                                </div>
                              ) : msg.role === 'error' ? (
                                <div className="max-w-2xl bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg px-4 py-2">
                                  {msg.content}
                                </div>
                              ) : null}
                            </div>
                          ))
                        )}
                        {(clientProcessing || trikshaAgentRunning) && (
                          <div className="flex justify-start">
                            <div className={`rounded-lg px-4 py-2 ${trikshaAgentRunning ? 'bg-gradient-to-r from-orange-100 to-red-100 dark:from-orange-900/30 dark:to-red-900/30' : 'bg-gray-100 dark:bg-gray-700'}`}>
                              <div className="flex items-center space-x-2">
                                <div className={`animate-spin h-4 w-4 border-2 border-t-transparent rounded-full ${trikshaAgentRunning ? 'border-orange-600' : 'border-green-600'}`}></div>
                                <span className={`${trikshaAgentRunning ? 'text-orange-600 dark:text-orange-400 font-medium' : 'text-gray-500 dark:text-gray-400'}`}>
                                  {trikshaAgentRunning ? 'Agent executing security assessment...' : 'Processing...'}
                                </span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                      
                      {/* Chat Input */}
                      <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-white dark:bg-gray-800">
                        {trikshaAgentRunning ? (
                          /* When agent is running - only show stop button */
                          <div className="flex justify-center">
                            <button
                              onClick={cancelClientSimulation}
                              className="px-8 py-2.5 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors flex items-center space-x-2"
                            >
                              <X className="h-4 w-4" />
                              <span>Stop Agent</span>
                            </button>
                          </div>
                        ) : (
                          /* Normal input bar */
                          <div className="flex space-x-3">
                            <input
                              type="text"
                              value={clientPrompt}
                              onChange={(e) => setClientPrompt(e.target.value)}
                              onKeyPress={(e) => e.key === 'Enter' && !clientProcessing && handleClientSimulation()}
                              placeholder="Type your request... (e.g., 'Get info about user admin')"
                              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-green-500"
                              disabled={clientProcessing}
                            />
                            {clientProcessing ? (
                              <button
                                onClick={cancelClientSimulation}
                                className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors flex items-center space-x-2"
                              >
                                <X className="h-4 w-4" />
                                <span>Cancel</span>
                              </button>
                            ) : (
                              <button
                                onClick={handleClientSimulation}
                                disabled={!clientPrompt.trim()}
                                className="px-6 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-400 text-white font-medium rounded-lg transition-colors"
                              >
                                Send
                              </button>
                            )}
                            {clientMessages.length > 0 && !clientProcessing && (
                              <button
                                onClick={clearClientChat}
                                className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                              >
                                Clear
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                  /* MANUAL TESTING MODE (existing code) */
                  <>
                  {/* LEFT: Tool List */}
                  <div className="w-1/3 border-r border-gray-200 dark:border-gray-700 overflow-y-auto bg-gray-50 dark:bg-gray-900">
                    <div className="p-4">
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        Available Tools ({serverWithTools.tools.length})
                      </h4>
                      <div className="space-y-2">
                        {serverWithTools.tools.map((tool, idx) => (
                          <div
                            key={idx}
                            onClick={() => {
                              setSelectedTool(tool);
                              setToolArgs({});
                              setExecutionResult(null);
                            }}
                            className={`p-3 rounded-lg cursor-pointer border-2 transition-all ${
                              selectedTool?.name === tool.name
                                ? 'bg-primary-50 dark:bg-primary-900/20 border-primary-500'
                                : 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:border-primary-300'
                            }`}
                          >
                            <div className="text-sm font-medium text-gray-900 dark:text-white">{tool.name}</div>
                            {tool.description && (
                              <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 line-clamp-2">
                                {tool.description.split('\n')[0]}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                  
                  {/* RIGHT: Tool Testing Interface */}
                  <div className="w-2/3 overflow-y-auto bg-white dark:bg-gray-800">
                    <div className="p-6">
                      {selectedTool ? (
                        <div>
                          {/* Tool Header */}
                          <div className="mb-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <h4 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedTool.name}</h4>
                                {selectedTool.description && (
                                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
                                    {selectedTool.description.split('\n')[0]}
                                  </p>
                                )}
                              </div>
                              {selectedTool.input_schema?.properties && Object.keys(selectedTool.input_schema.properties).length > 0 && (
                                <button
                                  onClick={fillSampleValues}
                                  className="ml-4 flex items-center space-x-2 px-3 py-2 text-xs font-medium text-primary-700 dark:text-primary-400 bg-primary-50 dark:bg-primary-900/20 hover:bg-primary-100 dark:hover:bg-primary-900/30 border border-primary-200 dark:border-primary-800 rounded-md transition-colors"
                                >
                                  <Wrench className="h-3.5 w-3.5" />
                                  <span>Fill Sample Values</span>
                                </button>
                              )}
                            </div>
                          </div>
                          
                          {/* Dynamic Form */}
                          <div className="mb-6">
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Tool Arguments</h5>
                            {selectedTool.input_schema?.properties && Object.keys(selectedTool.input_schema.properties).length > 0 ? (
                              <div className="space-y-3">
                                {Object.entries(selectedTool.input_schema.properties).map(([argName, argSpec]) => {
                                  const isRequired = selectedTool.input_schema.required?.includes(argName);
                                  return (
                                    <div key={argName}>
                                      <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">
                                        {argName}
                                        {isRequired && <span className="text-red-600 ml-1">*</span>}
                                        {argSpec.description && (
                                          <span className="font-normal text-gray-500 dark:text-gray-400 ml-2">
                                            - {argSpec.description}
                                          </span>
                                        )}
                                      </label>
                                      {argSpec.type === 'boolean' ? (
                                        <select
                                          value={toolArgs[argName] || 'false'}
                                          onChange={(e) => setToolArgs({...toolArgs, [argName]: e.target.value === 'true'})}
                                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                        >
                                          <option value="false">false</option>
                                          <option value="true">true</option>
                                        </select>
                                      ) : argSpec.type === 'number' || argSpec.type === 'integer' ? (
                                        <input
                                          type="number"
                                          value={toolArgs[argName] || ''}
                                          onChange={(e) => setToolArgs({...toolArgs, [argName]: Number(e.target.value)})}
                                          placeholder={`Enter ${argName}`}
                                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                        />
                                      ) : argSpec.type === 'array' ? (
                                        <textarea
                                          value={toolArgs[argName] || ''}
                                          onChange={(e) => setToolArgs({...toolArgs, [argName]: e.target.value.split(',').map(v => v.trim()).filter(v => v)})}
                                          placeholder="Enter comma-separated values"
                                          rows={2}
                                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono"
                                        />
                                      ) : (
                                        <input
                                          type="text"
                                          value={toolArgs[argName] || ''}
                                          onChange={(e) => setToolArgs({...toolArgs, [argName]: e.target.value})}
                                          placeholder={`Enter ${argName}`}
                                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                                        />
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            ) : (
                              <p className="text-sm text-gray-500 dark:text-gray-400">This tool requires no arguments</p>
                            )}
                          </div>
                          
                          {/* Execute Buttons */}
                          <div className="mb-6 space-y-3">
                            <button
                              onClick={handleExecuteTool}
                              disabled={executing || agentRunning}
                              className="w-full px-4 py-3 text-sm font-medium text-white bg-green-600 hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed rounded-md transition-colors flex items-center justify-center space-x-2"
                            >
                              {executing ? (
                                <>
                                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                                  <span>Executing...</span>
                                </>
                              ) : (
                                <>
                                  <Activity className="h-4 w-4" />
                                  <span>Execute Tool</span>
                                </>
                              )}
                            </button>
                          </div>
                          
                          {/* Agent Verbose Logs */}
                          {agentLogs.length > 0 && (
                            <div className="mb-6">
                              <button
                                onClick={() => setShowAgentLogs(!showAgentLogs)}
                                className="w-full flex items-center justify-between p-3 bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-purple-900/20 dark:to-indigo-900/20 border border-purple-200 dark:border-purple-800 rounded-lg hover:from-purple-100 hover:to-indigo-100 dark:hover:from-purple-900/30 dark:hover:to-indigo-900/30 transition-colors"
                              >
                                <div className="flex items-center space-x-2">
                                  <Shield className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                  <span className="text-sm font-semibold text-purple-900 dark:text-purple-200">
                                    Agent Activity Log ({agentLogs.length} events)
                                  </span>
                                </div>
                                {showAgentLogs ? (
                                  <ChevronUp className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                ) : (
                                  <ChevronDown className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                )}
                              </button>
                              
                              {showAgentLogs && (
                                <div className="mt-2 bg-gray-900 dark:bg-gray-950 rounded-lg p-4 min-h-[120px] relative overflow-hidden">
                                  {/* Show only the most recent log with fade-in animation */}
                                  {agentLogs.length > 0 && (() => {
                                    const latestLog = agentLogs[agentLogs.length - 1];
                                    return (
                                      <div 
                                        key={agentLogs.length}
                                        className="animate-fade-in-replace"
                                      >
                                        <div className="flex items-start space-x-2 text-xs font-mono">
                                          <span className="text-gray-600 flex-shrink-0 text-[10px]">
                                            [{new Date(latestLog.timestamp).toLocaleTimeString()}]
                                          </span>
                                          <div className="flex-1">
                                            <div className={`${
                                              latestLog.type === 'error' ? 'text-red-400' :
                                              latestLog.type === 'vulnerability' ? 'text-red-500 font-bold' :
                                              latestLog.type === 'test_pass' ? 'text-green-400' :
                                              latestLog.type === 'phase' ? 'text-cyan-400 font-bold' :
                                              latestLog.type === 'complete' ? 'text-green-400 font-bold' :
                                              latestLog.type === 'test_start' ? 'text-yellow-400' :
                                              latestLog.technical ? 'text-blue-300' :
                                              'text-gray-300'
                                            }`}>
                                              {latestLog.message}
                                            </div>
                                            {latestLog.details && (
                                              <div className="text-gray-500 text-[10px] mt-1 ml-2">
                                                → {latestLog.details}
                                              </div>
                                            )}
                                            {latestLog.payload && (
                                              <div className="text-purple-400 text-[10px] mt-1 ml-2 font-mono bg-gray-800 p-1.5 rounded">
                                                Payload: {latestLog.payload}
                                              </div>
                                            )}
                                            {latestLog.recommendation && (
                                              <div className="text-orange-300 text-[10px] mt-1 ml-2">
                                                💡 {latestLog.recommendation}
                                              </div>
                                            )}
                                          </div>
                                        </div>
                                      </div>
                                    );
                                  })()}
                                  
                                  {/* Progress indicator */}
                                  {agentRunning && (
                                    <div className="absolute bottom-4 right-4 flex items-center space-x-2 text-xs text-cyan-400">
                                      <div className="w-2 h-2 bg-cyan-400 rounded-full animate-ping"></div>
                                      <span className="animate-pulse">Agent working...</span>
                                    </div>
                                  )}
                                  
                                  {/* Event counter */}
                                  <div className="absolute top-4 right-4 text-xs text-gray-600">
                                    Event {agentLogs.length}
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                          
                          {/* Agent Report */}
                          {agentReport && (
                            <div className="mb-6">
                              <div className="bg-gradient-to-r from-purple-50 to-indigo-50 dark:from-purple-900/20 dark:to-indigo-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-4">
                                <h5 className="text-sm font-semibold text-purple-900 dark:text-purple-200 mb-3 flex items-center space-x-2">
                                  <Shield className="h-4 w-4" />
                                  <span>Agent Security Report</span>
                                </h5>
                                <div className="space-y-3">
                                  <div className="grid grid-cols-2 gap-3">
                                    <div className="bg-white dark:bg-gray-800 rounded p-3">
                                      <div className="text-xs text-gray-500 dark:text-gray-400">Tests Run</div>
                                      <div className="text-lg font-bold text-gray-900 dark:text-white">{agentReport.total_tests}</div>
                                    </div>
                                    <div className="bg-white dark:bg-gray-800 rounded p-3">
                                      <div className="text-xs text-gray-500 dark:text-gray-400">Vulnerabilities</div>
                                      <div className={`text-lg font-bold ${agentReport.vulnerabilities_found > 0 ? 'text-red-600' : 'text-green-600'}`}>
                                        {agentReport.vulnerabilities_found}
                                      </div>
                                    </div>
                                  </div>
                                  
                                  {agentReport.vulnerabilities_found > 0 && (
                                    <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                                      <div className="text-xs font-semibold text-red-900 dark:text-red-200 mb-2">Severity Breakdown</div>
                                      <div className="grid grid-cols-4 gap-2 text-xs">
                                        {Object.entries(agentReport.severity_breakdown).map(([severity, count]) => (
                                          count > 0 && (
                                            <div key={severity} className="text-center">
                                              <div className="font-bold text-red-700 dark:text-red-300">{count}</div>
                                              <div className="text-gray-600 dark:text-gray-400 capitalize">{severity}</div>
                                            </div>
                                          )
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  
                                  <div className={`text-center py-2 px-3 rounded font-semibold text-sm ${
                                    agentReport.overall_risk === 'critical' ? 'bg-red-100 dark:bg-red-900/30 text-red-900 dark:text-red-200' :
                                    agentReport.overall_risk === 'high' ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-900 dark:text-orange-200' :
                                    agentReport.overall_risk === 'medium' ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-900 dark:text-yellow-200' :
                                    'bg-green-100 dark:bg-green-900/30 text-green-900 dark:text-green-200'
                                  }`}>
                                    Overall Risk: {agentReport.overall_risk.toUpperCase()}
                                  </div>
                                </div>
                              </div>
                            </div>
                          )}
                          
                          {/* Execution Results */}
                          {executionResult && (
                            <div className="mb-4">
                              <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Execution Result</h5>
                              {executionResult.success ? (
                                <div className="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                                  <div className="flex items-start space-x-2 mb-3">
                                    <CheckCircle className="h-5 w-5 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
                                    <div>
                                      <div className="text-sm font-semibold text-green-900 dark:text-green-200">Success</div>
                                      <div className="text-xs text-green-700 dark:text-green-300 mt-1">Tool executed successfully</div>
                                    </div>
                                  </div>
                                  <div className="bg-gray-900 dark:bg-gray-950 rounded p-3 overflow-x-auto max-h-96">
                                    <pre className="text-xs text-green-400 font-mono">
{JSON.stringify(executionResult.data, null, 2)}
                                    </pre>
                                  </div>
                                </div>
                              ) : (
                                <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                                  <div className="flex items-start space-x-2">
                                    <XCircle className="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
                                    <div>
                                      <div className="text-sm font-semibold text-red-900 dark:text-red-200">Error</div>
                                      <div className="text-xs text-red-700 dark:text-red-300 mt-1">{executionResult.error}</div>
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="flex items-center justify-center h-full text-center">
                          <div>
                            <Activity className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                            <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-1">Select a tool</h4>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              Click on a tool from the left to test it
                            </p>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                  </>
                  )}
                </div>
              </div>
            </div>
          </div>
        );
      })()}
      
      {/* OLD MODAL - KEEPING FOR REFERENCE, REMOVE LATER */}
      {false && showResultsModal && modalScan && modalScan.data && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex-1">
                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                  {modalScan.scanName || modalScan.fileName}
                </h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Scanned on {formatDate(modalScan.timestamp)} by {modalScan.createdBy || 'anonymous'}
                </p>
              </div>
              <div className="flex items-center space-x-2">
                <button
                  onClick={() => exportJSON(modalScan)}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                  title="Export as JSON"
                >
                  <Download className="h-5 w-5" />
                </button>
                <button
                  onClick={() => exportPDF(modalScan)}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                  title="Export as PDF"
                >
                  <FileText className="h-5 w-5" />
                </button>
                <button
                  onClick={closeResultsModal}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                {/* Total Servers Card */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Servers</span>
                    <Server className="h-5 w-5 text-primary-600" />
                  </div>
                  <div className="text-3xl font-bold text-gray-900 dark:text-white">
                    {modalScan.data.summary.total_servers}
                  </div>
                </div>

                {/* Successful Card */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Successful</span>
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  </div>
                  <div className="text-3xl font-bold text-green-600 dark:text-green-400">
                    {modalScan.data.summary.successful}
                  </div>
                </div>

                {/* Failed Card */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Failed/Timeout</span>
                    <XCircle className="h-5 w-5 text-red-500" />
                  </div>
                  <div className="text-3xl font-bold text-red-600 dark:text-red-400">
                    {modalScan.data.summary.failed + modalScan.data.summary.timeout}
                  </div>
                </div>

                {/* Tools Discovered Card */}
                <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Tools</span>
                    <Wrench className="h-5 w-5 text-primary-600" />
                  </div>
                  <div className="text-3xl font-bold text-gray-900 dark:text-white">
                    {modalScan.data.summary.total_tools}
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {modalScan.data.summary.total_prompts} prompts, {modalScan.data.summary.total_resources} resources
                  </div>
                </div>
              </div>

              {/* Visualization - Bar Chart */}
              {modalScan.data.summary.total_servers > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 mb-6">
                  <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-6 flex items-center">
                    <BarChart3 className="h-5 w-5 mr-2 text-primary-600" />
                    Server Status Distribution
                  </h4>
                  <div className="flex items-end justify-center space-x-8 h-64 mb-4">
                    {/* Successful servers bar */}
                    <div className="flex flex-col items-center w-32">
                      <div className="w-full flex flex-col justify-end h-48 mb-4 relative">
                        {(() => {
                          const percentage = (modalScan.data.summary.successful / modalScan.data.summary.total_servers) * 100;
                          const barHeight = Math.max(percentage, 5);
                          
                          return (
                            <div 
                              className="w-full bg-gradient-to-t from-green-500 to-green-400 rounded-t-lg shadow-lg transition-all duration-500"
                              style={{ height: `${barHeight}%` }}
                            ></div>
                          );
                        })()}
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                          {((modalScan.data.summary.successful / modalScan.data.summary.total_servers) * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mt-1">Successful</div>
                      </div>
                    </div>
                    
                    {/* Failed servers bar */}
                    <div className="flex flex-col items-center w-32">
                      <div className="w-full flex flex-col justify-end h-48 mb-4 relative">
                        {(() => {
                          const failedCount = modalScan.data.summary.failed + modalScan.data.summary.timeout;
                          const percentage = (failedCount / modalScan.data.summary.total_servers) * 100;
                          const barHeight = Math.max(percentage, 5);
                          
                          return (
                            <div 
                              className="w-full bg-gradient-to-t from-red-500 to-red-400 rounded-t-lg shadow-lg transition-all duration-500"
                              style={{ height: `${barHeight}%` }}
                            ></div>
                          );
                        })()}
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                          {(((modalScan.data.summary.failed + modalScan.data.summary.timeout) / modalScan.data.summary.total_servers) * 100).toFixed(1)}%
                        </div>
                        <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mt-1">Failed/Timeout</div>
                      </div>
                    </div>
                  </div>
                  <div className="border-t-2 border-gray-300 dark:border-gray-600"></div>
                </div>
              )}

              {/* Server Details */}
              <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
                <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                  <Server className="h-5 w-5 mr-2 text-primary-600" />
                  Server Details ({modalScan.data.servers?.length || 0})
                </h4>
                <div className="space-y-4">
                  {(modalScan.data.servers || []).map((server, index) => (
                    <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div>
                          <h5 className="font-semibold text-gray-900 dark:text-white">{server.server_name}</h5>
                          <p className="text-sm text-gray-500 dark:text-gray-400">Type: {server.server_type}</p>
                        </div>
                        <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          server.status === 'success' 
                            ? 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400' 
                            : 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400'
                        }`}>
                          {server.status.toUpperCase()}
                        </span>
                      </div>
                      {server.error_message && (
                        <div className="mb-3 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
                          <p className="text-sm text-red-600 dark:text-red-400">{server.error_message}</p>
                        </div>
                      )}
                      <div className="grid grid-cols-3 gap-4 mt-3">
                        <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded">
                          <div className="text-xs text-gray-600 dark:text-gray-400">Tools</div>
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">{server.tools.length}</div>
                        </div>
                        <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded">
                          <div className="text-xs text-gray-600 dark:text-gray-400">Prompts</div>
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">{server.prompts.length}</div>
                        </div>
                        <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded">
                          <div className="text-xs text-gray-600 dark:text-gray-400">Resources</div>
                          <div className="text-lg font-semibold text-gray-900 dark:text-white">{server.resources.length}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end p-6 border-t border-gray-200 dark:border-gray-700">
              <button
                onClick={closeResultsModal}
                className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Scan Info Modal */}
      {showScanInfoModal && scanInfoData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="fixed inset-0 transition-opacity bg-gray-500/75 dark:bg-gray-900/75" onClick={() => setShowScanInfoModal(false)} />
          <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg overflow-hidden">
            <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Info className="h-5 w-5 text-white" />
                <div>
                  <h3 className="text-base font-semibold text-white">{scanInfoData.scanName || scanInfoData.fileName || 'MCP Scan'}</h3>
                  <p className="text-xs text-white/70">Scan Configuration Details</p>
                </div>
              </div>
              <button onClick={() => setShowScanInfoModal(false)} className="text-white hover:text-gray-200">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                  <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Status</div>
                  <div className={`text-sm font-semibold capitalize ${
                    scanInfoData.status === 'completed' ? 'text-green-600' :
                    scanInfoData.status === 'running'   ? 'text-blue-600' :
                    scanInfoData.status === 'failed'    ? 'text-red-600'  :
                    scanInfoData.status === 'cancelled' ? 'text-orange-600' : 'text-gray-900 dark:text-white'
                  }`}>{scanInfoData.status}</div>
                </div>
                <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3">
                  <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Server Type</div>
                  <div className="text-sm font-semibold text-gray-900 dark:text-white uppercase">
                    {scanInfoData.data?.servers?.[0]?.server_type || 'N/A'}
                  </div>
                </div>
              </div>
              {scanInfoData.data?.servers?.[0]?.server_url && (
                <div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">Server URL</div>
                  <code className="block w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded text-xs font-mono text-gray-700 dark:text-gray-300 truncate">
                    {scanInfoData.data.servers[0].server_url}
                  </code>
                </div>
              )}
              <div className="text-xs text-gray-500 dark:text-gray-400">
                Created by: <span className="text-gray-700 dark:text-gray-300">{scanInfoData.createdBy || 'Anonymous'}</span>
                {scanInfoData.created_at && (
                  <span className="ml-3">on {new Date(scanInfoData.created_at).toLocaleString()}</span>
                )}
              </div>
              {scanInfoData.data?.summary && (
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: 'Tools', val: scanInfoData.data.summary.total_tools },
                    { label: 'Findings', val: scanInfoData.data.summary.total_findings },
                    { label: 'Servers', val: scanInfoData.data.servers?.length },
                  ].map(({ label, val }) => val != null && (
                    <div key={label} className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-3 text-center">
                      <div className="text-xs text-gray-500 dark:text-gray-400 uppercase mb-1">{label}</div>
                      <div className="text-sm font-semibold text-gray-900 dark:text-white">{val}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MCPScanner;

