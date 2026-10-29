import React, { useState, useEffect, useMemo } from 'react';
import { Upload, Database, AlertCircle, CheckCircle, XCircle, Clock, Search, FileText, Shield, X, Download, TrendingUp, TrendingDown, Activity } from 'lucide-react';
import { createApiClient, useAuth } from '../contexts/AuthContext';
import toast from 'react-hot-toast';
import LockedOverlay from '../components/LockedOverlay';

const Dataset = () => {
  const { user, hasPermission, canAccessScan, isAdmin, canViewAllScans } = useAuth();
  
  // Tab state
  const [activeTab, setActiveTab] = useState('new-analysis');
  
  // File upload state
  const [uploadedFile, setUploadedFile] = useState(null);
  const [scanName, setScanName] = useState('');
  const [loading, setLoading] = useState(false);
  
  // Analysis history state
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [selectedAnalysis, setSelectedAnalysis] = useState(null);
  
  // Modal state
  const [showResultsModal, setShowResultsModal] = useState(false);
  const [modalAnalysis, setModalAnalysis] = useState(null);
  
  // Search and filter state
  const [activeSearch, setActiveSearch] = useState('');
  const [pastSearch, setPastSearch] = useState('');
  const [pastStatus, setPastStatus] = useState('all'); // all | safe | poisoned | failed
  
  const apiClient = createApiClient();

  // Filter analyses (defined early so they can be used in useEffect)
  const activeAnalyses = useMemo(() => {
    return analysisHistory
      .filter(a => a.status === 'analyzing' || a.status === 'queued' || a.status === 'running')
      .filter(a => !activeSearch || a.fileName.toLowerCase().includes(activeSearch.toLowerCase()));
  }, [analysisHistory, activeSearch]);

  const pastAnalyses = useMemo(() => {
    return analysisHistory
      .filter(a => a.status !== 'analyzing' && a.status !== 'queued' && a.status !== 'running')
      .filter(a => {
        if (pastStatus === 'all') return true;
        if (pastStatus === 'safe') return a.isPoisoned === false;
        if (pastStatus === 'poisoned') return a.isPoisoned === true;
        if (pastStatus === 'failed') return a.status === 'failed';
        return true;
      })
      .filter(a => !pastSearch || a.fileName.toLowerCase().includes(pastSearch.toLowerCase()));
  }, [analysisHistory, pastSearch, pastStatus]);

  // Load analysis history from database on mount
  useEffect(() => {
    loadAnalysesFromDatabase();
  }, []);

  // Poll for active analyses updates
  useEffect(() => {
    if (activeAnalyses.length === 0) return;

    const pollInterval = setInterval(() => {
      loadAnalysesFromDatabase();
    }, 3000); // Poll every 3 seconds

    return () => clearInterval(pollInterval);
  }, [activeAnalyses.length]);

  const loadAnalysesFromDatabase = async () => {
    try {
      // Build query string ourselves — apiClient.get's second arg is fetch
      // options, not query params, so passing { limit: 50 } there was a no-op.
      const params = new URLSearchParams({ limit: '50' });
      const response = await apiClient.get(`/dataset/analyses?${params.toString()}`);
      if (response.status === 'ok' && response.analyses) {
        // Transform database analyses to match our local format
        const transformedAnalyses = response.analyses.map(analysis => ({
          id: analysis.analysis_id,
          timestamp: analysis.created_at,
          scanName: analysis.scan_name || analysis.file_name,
          fileName: analysis.file_name,
          fileSize: analysis.file_size,
          status: analysis.status,
          message: analysis.message,
          isPoisoned: analysis.is_poisoned,
          securityScore: analysis.security_score,
          totalEntries: analysis.total_entries,
          suspiciousEntries: analysis.suspicious_entries,
          results: analysis.results || null,
          completedAt: analysis.completed_at,
          createdBy: analysis.created_by || 'unknown'
        }));
        setAnalysisHistory(transformedAnalyses);
      }
    } catch (error) {
      console.error('Failed to load dataset analyses:', error);
      toast.error('Failed to load analysis history');
    }
  };

  // Handle file upload
  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      // Validate file type
      const allowedTypes = ['text/csv', 'application/json', 'text/plain'];
      const allowedExtensions = ['.csv', '.json', '.jsonl', '.txt'];
      
      const fileExtension = '.' + file.name.split('.').pop().toLowerCase();
      const isValidType = allowedTypes.includes(file.type) || allowedExtensions.includes(fileExtension);
      
      if (!isValidType) {
        toast.error('Please upload a CSV, JSON, JSONL, or TXT file');
        return;
      }
      
      // Validate file size (max 10MB)
      if (file.size > 10 * 1024 * 1024) {
        toast.error('File size must be less than 10MB');
        return;
      }
      
      setUploadedFile(file);
      toast.success(`File "${file.name}" uploaded successfully`);
    }
  };

  // Analyze dataset for poisoning
  const analyzePoisoning = async () => {
    if (!uploadedFile) {
      toast.error('Please upload a file first');
      return;
    }

    // Use scan name or default to filename
    const finalScanName = scanName.trim() || uploadedFile.name;

    // Create a pending analysis entry immediately
    const pendingAnalysis = {
      id: `pending-${Date.now()}`,
      timestamp: new Date().toISOString(),
      scanName: finalScanName,
      fileName: uploadedFile.name,
      fileSize: uploadedFile.size,
      status: 'analyzing',
      message: 'Analysis in progress...',
      isPoisoned: null,
      securityScore: null,
      totalEntries: null,
      suspiciousEntries: null,
      results: null,
      completedAt: null,
      createdBy: user?.id || ''
    };

    // Add to history and switch to active tab
    setAnalysisHistory(prev => [pendingAnalysis, ...prev]);
    setSelectedAnalysis(pendingAnalysis);
    setActiveTab('active-analyses');
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('dataset_file', uploadedFile);
      formData.append('scan_name', finalScanName);

      // Don't set Content-Type manually - let the browser set it with the boundary
      const response = await apiClient.post('/dataset/analyze-poisoning', formData);

      if (response.analysis_id) {
        // Update the pending analysis with the real ID
        const analysisEntry = {
          ...pendingAnalysis,
          id: response.analysis_id,
          status: 'analyzing',
          message: response.message || 'Analysis in progress...'
        };
        
        setAnalysisHistory(prev => [analysisEntry, ...prev.filter(a => a.id !== pendingAnalysis.id)]);
        setSelectedAnalysis(analysisEntry);
        
        // Clear uploaded file and scan name
        setUploadedFile(null);
        setScanName('');
        
        toast.success('Analysis started! You can navigate away and check back later.');
        
        // Reload to get latest from database
        await loadAnalysesFromDatabase();
      } else {
        // Reload analyses from database to get updated status
        await loadAnalysesFromDatabase();
        toast.error('Failed to start analysis');
      }
    } catch (error) {
      console.error('Dataset analysis error:', error);
      
      // Reload analyses from database to get updated status
      await loadAnalysesFromDatabase();
      toast.error(error.response?.data?.detail || 'Failed to analyze dataset');
    } finally {
      setLoading(false);
    }
  };

  const cancelAnalysis = async (analysisId) => {
    try {
      await apiClient.delete(`/dataset/analysis/${analysisId}`);
      toast.success('Analysis cancelled successfully');
      // Reload analyses from database
      await loadAnalysesFromDatabase();
    } catch (error) {
      console.error('Error cancelling analysis:', error);
      toast.error(error.response?.data?.detail || 'Failed to cancel analysis');
    }
  };

  const viewAnalysisDetails = (analysis) => {
    setSelectedAnalysis(analysis);
  };

  const openResultsModal = (analysis) => {
    setModalAnalysis(analysis);
    setShowResultsModal(true);
  };

  const closeResultsModal = () => {
    setShowResultsModal(false);
    setModalAnalysis(null);
  };

  const exportReport = async (format = 'pdf') => {
    if (!modalAnalysis) return;
    
    try {
      // Create report data
      const reportData = {
        fileName: modalAnalysis.fileName,
        analysisDate: new Date(modalAnalysis.timestamp).toLocaleString(),
        completedAt: modalAnalysis.completedAt ? new Date(modalAnalysis.completedAt).toLocaleString() : 'N/A',
        securityScore: modalAnalysis.securityScore,
        isPoisoned: modalAnalysis.isPoisoned,
        totalEntries: modalAnalysis.totalEntries,
        suspiciousEntries: modalAnalysis.suspiciousEntries,
        results: modalAnalysis.results
      };

      if (format === 'json') {
        // Export as JSON
        const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `dataset-analysis-${modalAnalysis.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Report exported as JSON');
      } else {
        // Calculate percentages for chart
        const safePercentage = (((reportData.totalEntries - reportData.suspiciousEntries) / reportData.totalEntries) * 100).toFixed(1);
        const suspiciousPercentage = ((reportData.suspiciousEntries / reportData.totalEntries) * 100).toFixed(1);
        const safeHeight = Math.max(parseFloat(safePercentage), 5);
        const suspiciousHeight = Math.max(parseFloat(suspiciousPercentage), 5);
        
        // For PDF, we'll create a printable HTML version
        const printWindow = window.open('', '_blank');
        printWindow.document.write(`
          <html>
            <head>
              <title>Dataset Poisoning Analysis Report</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                h1 { color: #1e40af; }
                h2 { color: #3b82f6; margin-top: 30px; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #f3f4f6; }
                .safe { color: #10b981; font-weight: bold; }
                .danger { color: #ef4444; font-weight: bold; }
                .score { font-size: 24px; font-weight: bold; }
                .metadata { background-color: #f9fafb; padding: 15px; border-radius: 8px; margin: 20px 0; }
                .chart-container { 
                  background: white; 
                  padding: 30px; 
                  border-radius: 8px; 
                  border: 1px solid #e5e7eb;
                  margin: 20px 0;
                }
                .chart-title {
                  font-size: 16px;
                  font-weight: 600;
                  color: #1f2937;
                  margin-bottom: 20px;
                }
                .bars-container {
                  display: flex;
                  align-items: flex-end;
                  justify-content: center;
                  gap: 40px;
                  height: 250px;
                  margin-bottom: 20px;
                }
                .bar-wrapper {
                  display: flex;
                  flex-direction: column;
                  align-items: center;
                  width: 120px;
                }
                .bar-container {
                  width: 100%;
                  height: 200px;
                  display: flex;
                  flex-direction: column;
                  justify-content: flex-end;
                  margin-bottom: 15px;
                }
                .bar {
                  width: 100%;
                  border-radius: 8px 8px 0 0;
                  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                }
                .bar-safe {
                  background: linear-gradient(to top, #10b981, #34d399);
                }
                .bar-danger {
                  background: linear-gradient(to top, #ef4444, #f87171);
                }
                .bar-label {
                  text-align: center;
                }
                .bar-value {
                  font-size: 24px;
                  font-weight: bold;
                  margin-bottom: 5px;
                }
                .bar-value.safe { color: #10b981; }
                .bar-value.danger { color: #ef4444; }
                .bar-text {
                  font-size: 14px;
                  color: #4b5563;
                  font-weight: 500;
                }
                .chart-baseline {
                  border-top: 2px solid #9ca3af;
                  margin-top: 10px;
                }
              </style>
            </head>
            <body>
              <h1>Dataset Poisoning Analysis Report</h1>
              
              <div class="metadata">
                <p><strong>File Name:</strong> ${reportData.fileName}</p>
                <p><strong>Analysis Date:</strong> ${reportData.analysisDate}</p>
                <p><strong>Completed:</strong> ${reportData.completedAt}</p>
              </div>

              <h2>Analysis Results</h2>
              <table>
                <tr>
                  <th>Metric</th>
                  <th>Value</th>
                </tr>
                <tr>
                  <td>Security Score</td>
                  <td class="score ${reportData.securityScore >= 80 ? 'safe' : 'danger'}">${reportData.securityScore}/100</td>
                </tr>
                <tr>
                  <td>Dataset Status</td>
                  <td class="${reportData.isPoisoned ? 'danger' : 'safe'}">${reportData.isPoisoned ? 'Potentially Poisoned' : 'Safe'}</td>
                </tr>
                <tr>
                  <td>Total Entries</td>
                  <td>${reportData.totalEntries}</td>
                </tr>
                <tr>
                  <td>Suspicious Entries</td>
                  <td class="${reportData.suspiciousEntries > 0 ? 'danger' : 'safe'}">${reportData.suspiciousEntries}</td>
                </tr>
              </table>

              <h2>Entry Distribution</h2>
              <div class="chart-container">
                <div class="bars-container">
                  <div class="bar-wrapper">
                    <div class="bar-container">
                      <div class="bar bar-safe" style="height: ${safeHeight}%"></div>
                    </div>
                    <div class="bar-label">
                      <div class="bar-value safe">${safePercentage}%</div>
                      <div class="bar-text">Safe Entries</div>
                    </div>
                  </div>
                  <div class="bar-wrapper">
                    <div class="bar-container">
                      <div class="bar bar-danger" style="height: ${suspiciousHeight}%"></div>
                    </div>
                    <div class="bar-label">
                      <div class="bar-value danger">${suspiciousPercentage}%</div>
                      <div class="bar-text">Suspicious</div>
                    </div>
                  </div>
                </div>
                <div class="chart-baseline"></div>
              </div>

              ${reportData.results?.semantic_analysis ? `
                <h2>AI Analysis Summary</h2>
                <div class="metadata">
                  <p>${reportData.results.semantic_analysis.summary || 'No summary available'}</p>
                </div>
              ` : ''}

              <p style="margin-top: 40px; color: #6b7280; font-size: 12px;">
                Generated by Triksha AI Security Platform - ${new Date().toLocaleString()}
              </p>
            </body>
          </html>
        `);
        printWindow.document.close();
        printWindow.print();
        toast.success('Opening print dialog for PDF export');
      }
    } catch (error) {
      console.error('Export error:', error);
      toast.error('Failed to export report');
    }
  };

  const formatBytes = (bytes) => {
    if (!bytes) return 'N/A';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    return new Date(timestamp).toLocaleString();
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'analyzing': return 'text-blue-600';
      case 'completed': return 'text-green-600';
      case 'failed': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'analyzing': return <Clock className="h-5 w-5 animate-spin" />;
      case 'completed': return <CheckCircle className="h-5 w-5" />;
      case 'failed': return <XCircle className="h-5 w-5" />;
      default: return <Database className="h-5 w-5" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Card */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dataset Poisoning Detection</h1>
            <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
              Analyze datasets for poisoning attacks using hybrid ML-LLM detection
            </p>
          </div>
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-primary-600 dark:text-primary-400" />
          </div>
        </div>
      </div>

      {/* Card Content */}
      <div className="card">
        {/* Sub-tab Navigation - Inside card */}
        <div className="border-b border-gray-200 dark:border-gray-700 px-6">
          <nav className="-mb-px flex space-x-8" aria-label="Tabs">
            <button
              onClick={() => setActiveTab('new-analysis')}
              className={`${
                activeTab === 'new-analysis'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-300'
              } whitespace-nowrap border-b-2 py-4 px-1 text-sm font-medium`}
            >
              <div className="flex items-center space-x-2">
                <Upload className="h-4 w-4" />
                <span>New Analysis</span>
              </div>
            </button>

            <button
              onClick={() => setActiveTab('active-analyses')}
              className={`${
                activeTab === 'active-analyses'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-300'
              } whitespace-nowrap border-b-2 py-4 px-1 text-sm font-medium`}
            >
              <div className="flex items-center space-x-2">
                <Clock className="h-4 w-4" />
                <span>Active Analyses</span>
                {activeAnalyses.length > 0 && (
                  <span className="ml-2 rounded-full bg-primary-100 dark:bg-primary-900 px-2 py-0.5 text-xs font-medium text-primary-600 dark:text-primary-400">
                    {activeAnalyses.length}
                  </span>
                )}
              </div>
            </button>

            <button
              onClick={() => setActiveTab('past-analyses')}
              className={`${
                activeTab === 'past-analyses'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-300'
              } whitespace-nowrap border-b-2 py-4 px-1 text-sm font-medium`}
            >
              <div className="flex items-center space-x-2">
                <Database className="h-4 w-4" />
                <span>Past Analyses</span>
                {pastAnalyses.length > 0 && (
                  <span className="ml-2 rounded-full bg-gray-100 dark:bg-gray-700 px-2 py-0.5 text-xs font-medium text-gray-600 dark:text-gray-300">
                    {pastAnalyses.length}
                  </span>
                )}
              </div>
            </button>
          </nav>
        </div>

        <div className="p-6">
          {/* New Analysis Tab */}
          {activeTab === 'new-analysis' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Upload Dataset</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Upload your dataset to analyze it for potential poisoning attacks. 
                  Supported formats: CSV, JSON, JSONL, TXT (max 10MB).
                </p>
              </div>

              {/* File Upload Section */}
              <div className="space-y-6">
                <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6">
                  <div className="text-center">
                    <Upload className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                    <div className="mt-4">
                      <label htmlFor="dataset-upload" className="cursor-pointer">
                        <span className="mt-2 block text-sm font-medium text-gray-900 dark:text-white">
                          Upload dataset file
                        </span>
                        <span className="mt-1 block text-sm text-gray-500 dark:text-gray-400">
                          CSV, JSON, JSONL, or TXT up to 10MB
                        </span>
                      </label>
                      <input
                        id="dataset-upload"
                        type="file"
                        className="sr-only"
                        accept=".csv,.json,.jsonl,.txt"
                        onChange={handleFileUpload}
                      />
                    </div>
                    <div className="mt-4">
                      <button
                        type="button"
                        onClick={() => document.getElementById('dataset-upload').click()}
                        className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 shadow-sm text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                      >
                        <Upload className="h-4 w-4 mr-2" />
                        Choose File
                      </button>
                    </div>
                  </div>
                </div>

                {/* Scan Name Input */}
                <div>
                  <label htmlFor="scan-name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Scan Name
                  </label>
                  <input
                    id="scan-name"
                    type="text"
                    placeholder="e.g., Customer Data Q4 Review"
                    value={scanName}
                    onChange={(e) => setScanName(e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
                  />
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Give your analysis a descriptive name to easily identify it later
                  </p>
                </div>

                {/* Uploaded File Info */}
                {uploadedFile && (
                  <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                    <div className="flex items-start">
                      <FileText className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5 mr-3" />
                      <div className="flex-1">
                        <h4 className="text-sm font-medium text-blue-900 dark:text-blue-100">
                          File Ready for Analysis
                        </h4>
                        <div className="mt-2 text-sm text-blue-700 dark:text-blue-300 space-y-1">
                          <div><strong>Name:</strong> {uploadedFile.name}</div>
                          <div><strong>Size:</strong> {formatBytes(uploadedFile.size)}</div>
                          <div><strong>Type:</strong> {uploadedFile.type || 'Unknown'}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Analyze Button */}
                <div>
                  <button
                    onClick={analyzePoisoning}
                    disabled={!uploadedFile || loading}
                    className="w-full inline-flex items-center justify-center px-4 py-3 border border-transparent text-base font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <>
                        <Clock className="animate-spin h-5 w-5 mr-2" />
                        Analyzing Dataset...
                      </>
                    ) : (
                      <>
                        <Shield className="h-5 w-5 mr-2" />
                        Analyze for Poisoning
                      </>
                    )}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Active Analyses Tab */}
          {activeTab === 'active-analyses' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Ongoing Analyses</h3>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search analyses..."
                    value={activeSearch}
                    onChange={(e) => setActiveSearch(e.target.value)}
                    className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  />
                </div>
              </div>

              {activeAnalyses.length === 0 ? (
                <div className="text-center py-12">
                  <Clock className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No active analyses</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Upload a dataset to start a new analysis
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {activeAnalyses.map(analysis => (
                    <div key={analysis.id} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:border-primary-500 dark:hover:border-primary-400 transition-colors">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <div className="flex items-center space-x-3">
                            <div className={getStatusColor(analysis.status)}>
                              {getStatusIcon(analysis.status)}
                            </div>
                            <div className="flex-1">
                              <h4 className="text-sm font-medium text-gray-900 dark:text-white">{analysis.scanName || analysis.fileName}</h4>
                              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{analysis.message}</p>
                            </div>
                          </div>
                          <div className="mt-3 text-xs text-gray-500 dark:text-gray-400">
                            <span>Started: {formatDate(analysis.timestamp)}</span>
                            <span className="mx-2">•</span>
                            <span>Size: {formatBytes(analysis.fileSize)}</span>
                          </div>
                          
                          {/* Progress Bar */}
                          {analysis.progress !== undefined && (
                            <div className="mt-3">
                              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400 mb-1">
                                <span>Progress</span>
                                <span>{analysis.progress.toFixed(1)}%</span>
                              </div>
                              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                                <div
                                  className="bg-primary-600 dark:bg-primary-500 h-2 rounded-full transition-all duration-300"
                                  style={{ width: `${analysis.progress}%` }}
                                />
                              </div>
                            </div>
                          )}
                        </div>
                        
                        {/* Cancel Button */}
                        <LockedOverlay locked={!hasPermission('triksha.scan.cancel-own') || !canAccessScan(analysis.createdBy)} message="You do not have permission to cancel this analysis">
                          <button
                            onClick={() => cancelAnalysis(analysis.id)}
                            className="ml-4 p-2 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-md transition-colors"
                            title="Cancel analysis"
                          >
                            <XCircle className="h-5 w-5" />
                          </button>
                        </LockedOverlay>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Past Analyses Tab */}
          {activeTab === 'past-analyses' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Analysis History</h3>
                <div className="flex items-center space-x-4">
                  <select
                    value={pastStatus}
                    onChange={(e) => setPastStatus(e.target.value)}
                    className="border border-gray-300 dark:border-gray-600 rounded-md px-3 py-2 text-sm focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                  >
                    <option value="all">All Analyses</option>
                    <option value="safe">Safe Datasets</option>
                    <option value="poisoned">Poisoned Datasets</option>
                    <option value="failed">Failed Analyses</option>
                  </select>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search analyses..."
                      value={pastSearch}
                      onChange={(e) => setPastSearch(e.target.value)}
                      className="pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md text-sm focus:ring-primary-500 focus:border-primary-500 bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
              </div>

              {pastAnalyses.length === 0 ? (
                <div className="text-center py-12">
                  <Database className="mx-auto h-12 w-12 text-gray-400 dark:text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">No past analyses</h3>
                  <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                    Your completed analyses will appear here
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {pastAnalyses.map(analysis => (
                    <div key={analysis.id} className="border border-gray-200 dark:border-gray-700 rounded-lg hover:border-primary-300 dark:hover:border-primary-700 transition-colors">
                      <div className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex-1 space-y-2">
                            {/* Row 1: Scan Name + Status Badge */}
                            <div className="flex items-center gap-3">
                              <div className={getStatusColor(analysis.status)}>
                                {getStatusIcon(analysis.status)}
                              </div>
                              <h4 className="text-base font-semibold text-gray-900 dark:text-white">
                                {analysis.scanName || analysis.fileName}
                              </h4>
                              {analysis.status === 'completed' && analysis.isPoisoned !== null && (
                                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                  analysis.isPoisoned 
                                    ? 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-400' 
                                    : 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-400'
                                }`}>
                                  {analysis.isPoisoned ? '⚠ Potentially Poisoned' : '✓ Safe'}
                                </span>
                              )}
                              {analysis.status === 'completed' && analysis.securityScore !== null && (
                                <span className="text-xs font-medium text-gray-500 dark:text-gray-400">
                                  Score: {analysis.securityScore}/100
                                </span>
                              )}
                            </div>

                            {/* Row 2: Created By + Metadata */}
                            <div className="flex items-center text-xs text-gray-500 dark:text-gray-400">
                              <span className="font-medium">Created by {analysis.createdBy}</span>
                              <span className="mx-2">•</span>
                              <span>{formatDate(analysis.completedAt || analysis.timestamp)}</span>
                              <span className="mx-2">•</span>
                              <span>Size: {formatBytes(analysis.fileSize)}</span>
                              {analysis.suspiciousEntries > 0 && (
                                <>
                                  <span className="mx-2">•</span>
                                  <span className="text-red-600 dark:text-red-400 font-medium">
                                    {analysis.suspiciousEntries} suspicious entries
                                  </span>
                                </>
                              )}
                            </div>
                          </div>

                          {/* Action Button */}
                          {analysis.status === 'completed' && analysis.results && (
                            <LockedOverlay locked={!hasPermission('triksha.scan.view-past-results') || !canAccessScan(analysis.createdBy)} message="You do not have permission to view details of this analysis">
                              <button
                                onClick={() => openResultsModal(analysis)}
                                className="px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-md transition-colors"
                                title="View Details"
                              >
                                View Details
                              </button>
                            </LockedOverlay>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Results Modal */}
      {showResultsModal && modalAnalysis && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Background overlay */}
          <div 
            className="fixed inset-0 bg-black bg-opacity-50 dark:bg-opacity-70"
            onClick={closeResultsModal}
          ></div>

          {/* Modal panel */}
          <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
              {/* Header */}
              <div className="bg-white dark:bg-gray-800 px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                      Dataset Poisoning Analysis Results
                    </h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{modalAnalysis.fileName}</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => exportReport('json')}
                      className="px-3 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors flex items-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export JSON</span>
                    </button>
                    <button
                      onClick={() => exportReport('pdf')}
                      className="px-3 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 rounded-md transition-colors flex items-center space-x-2"
                    >
                      <Download className="h-4 w-4" />
                      <span>Export PDF</span>
                    </button>
                    <button
                      onClick={closeResultsModal}
                      className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                    >
                      <X className="h-6 w-6" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Content */}
              <div className="bg-gray-50 dark:bg-gray-900 px-6 py-6 overflow-y-auto flex-1">
                {/* Summary Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  {/* Security Score Card */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Security Score</span>
                      <Shield className={`h-5 w-5 ${
                        modalAnalysis.securityScore >= 80 ? 'text-green-500' :
                        modalAnalysis.securityScore >= 60 ? 'text-yellow-500' :
                        'text-red-500'
                      }`} />
                    </div>
                    <div className={`text-3xl font-bold ${
                      modalAnalysis.securityScore >= 80 ? 'text-green-600 dark:text-green-400' :
                      modalAnalysis.securityScore >= 60 ? 'text-yellow-600 dark:text-yellow-400' :
                      'text-red-600 dark:text-red-400'
                    }`}>
                      {modalAnalysis.securityScore}
                      <span className="text-lg text-gray-500 dark:text-gray-400">/100</span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-3">
                      <div
                        className={`h-2 rounded-full ${
                          modalAnalysis.securityScore >= 80 ? 'bg-green-600' :
                          modalAnalysis.securityScore >= 60 ? 'bg-yellow-600' :
                          'bg-red-600'
                        }`}
                        style={{ width: `${modalAnalysis.securityScore}%` }}
                      />
                    </div>
                  </div>

                  {/* Status Card */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Status</span>
                      {modalAnalysis.isPoisoned ? (
                        <AlertCircle className="h-5 w-5 text-red-500" />
                      ) : (
                        <CheckCircle className="h-5 w-5 text-green-500" />
                      )}
                    </div>
                    <div className={`text-lg font-bold ${
                      modalAnalysis.isPoisoned ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'
                    }`}>
                      {modalAnalysis.isPoisoned ? 'Potentially Poisoned' : 'Safe'}
                    </div>
                  </div>

                  {/* Total Entries Card */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Total Entries</span>
                      <Database className="h-5 w-5 text-blue-500" />
                    </div>
                    <div className="text-3xl font-bold text-gray-900 dark:text-white">
                      {modalAnalysis.totalEntries?.toLocaleString() || 0}
                    </div>
                  </div>

                  {/* Suspicious Entries Card */}
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-4 border border-gray-200 dark:border-gray-700">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Suspicious</span>
                      {modalAnalysis.suspiciousEntries > 0 ? (
                        <TrendingUp className="h-5 w-5 text-red-500" />
                      ) : (
                        <TrendingDown className="h-5 w-5 text-green-500" />
                      )}
                    </div>
                    <div className={`text-3xl font-bold ${
                      modalAnalysis.suspiciousEntries > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'
                    }`}>
                      {modalAnalysis.suspiciousEntries || 0}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      {modalAnalysis.totalEntries > 0 ? 
                        `${((modalAnalysis.suspiciousEntries / modalAnalysis.totalEntries) * 100).toFixed(1)}% of total` : 
                        '0% of total'
                      }
                    </div>
                  </div>
                </div>

                {/* Visualization - Distribution Chart */}
                {modalAnalysis.totalEntries > 0 && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 mb-6">
                    <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-6 flex items-center">
                      <Activity className="h-5 w-5 mr-2 text-primary-600" />
                      Entry Distribution
                    </h4>
                    <div className="flex items-end justify-center space-x-8 h-64 mb-4">
                      {/* Safe entries bar */}
                      <div className="flex flex-col items-center w-32">
                        <div className="w-full flex flex-col justify-end h-48 mb-4 relative">
                          {(() => {
                            const safePercentage = ((modalAnalysis.totalEntries - modalAnalysis.suspiciousEntries) / modalAnalysis.totalEntries) * 100;
                            const barHeight = Math.max(safePercentage, 5);
                            
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
                            {(((modalAnalysis.totalEntries - modalAnalysis.suspiciousEntries) / modalAnalysis.totalEntries) * 100).toFixed(1)}%
                          </div>
                          <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mt-1">Safe Entries</div>
                        </div>
                      </div>
                      
                      {/* Suspicious entries bar */}
                      <div className="flex flex-col items-center w-32">
                        <div className="w-full flex flex-col justify-end h-48 mb-4 relative">
                          {(() => {
                            const suspiciousPercentage = (modalAnalysis.suspiciousEntries / modalAnalysis.totalEntries) * 100;
                            const barHeight = Math.max(suspiciousPercentage, 5);
                            
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
                            {((modalAnalysis.suspiciousEntries / modalAnalysis.totalEntries) * 100).toFixed(1)}%
                          </div>
                          <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mt-1">Suspicious</div>
                        </div>
                      </div>
                    </div>
                    {/* Baseline */}
                    <div className="border-t-2 border-gray-300 dark:border-gray-600"></div>
                  </div>
                )}

                {/* Analysis Details Table */}
                <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 mb-6">
                  <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                    <h4 className="text-md font-semibold text-gray-900 dark:text-white">Analysis Details</h4>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                      <thead className="bg-gray-50 dark:bg-gray-900">
                        <tr>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Metric
                          </th>
                          <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                            Value
                          </th>
                        </tr>
                      </thead>
                      <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                        <tr>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            File Name
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {modalAnalysis.fileName}
                          </td>
                        </tr>
                        <tr>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            File Size
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {formatBytes(modalAnalysis.fileSize)}
                          </td>
                        </tr>
                        <tr>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            Analysis Date
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {formatDate(modalAnalysis.timestamp)}
                          </td>
                        </tr>
                        <tr>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            Completed At
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            {formatDate(modalAnalysis.completedAt)}
                          </td>
                        </tr>
                        <tr>
                          <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                            Detection Method
                          </td>
                          <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                            Isolation Forest + Gemini 2.5 Flash
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Enhanced Detection Breakdown */}
                {modalAnalysis.results?.detection_breakdown && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 mb-6">
                    <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                      <h4 className="text-md font-semibold text-gray-900 dark:text-white">Detection Breakdown</h4>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Results from {modalAnalysis.results.analysis_metadata?.detectors_count || '7'} detection methods
                      </p>
                    </div>
                    <div className="p-6 space-y-4">
                      {/* Ensemble Detection */}
                      {modalAnalysis.results.detection_breakdown.ensemble && (
                        <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4 border border-blue-200 dark:border-blue-800">
                          <div className="flex items-center justify-between mb-3">
                            <h5 className="text-sm font-semibold text-blue-900 dark:text-blue-300">
                              🎯 Ensemble Detection
                            </h5>
                            <span className="text-xs font-medium px-2 py-1 bg-blue-200 dark:bg-blue-800 text-blue-900 dark:text-blue-200 rounded">
                              {modalAnalysis.results.detection_breakdown.ensemble.suspicious_count} flagged
                            </span>
                          </div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                            {modalAnalysis.results.detection_breakdown.ensemble.per_detector?.map((detector, idx) => (
                              <div key={idx} className="bg-white dark:bg-gray-800 rounded p-2">
                                <div className="text-xs font-medium text-gray-600 dark:text-gray-400">{detector.name}</div>
                                <div className="text-lg font-bold text-blue-600 dark:text-blue-400">{detector.n_suspicious}</div>
                              </div>
                            ))}
                          </div>
                          <p className="text-xs text-blue-800 dark:text-blue-300">
                            Using {modalAnalysis.results.detection_breakdown.ensemble.detectors_used?.join(', ')}
                          </p>
                        </div>
                      )}

                      {/* Label Flipping */}
                      {modalAnalysis.results.detection_breakdown.label_flipping && 
                       modalAnalysis.results.detection_breakdown.label_flipping.risk_level !== 'LOW' && (
                        <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-4 border border-yellow-200 dark:border-yellow-800">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-sm font-semibold text-yellow-900 dark:text-yellow-300">
                              🔄 Label Flipping Detection
                            </h5>
                            <span className={`text-xs font-medium px-2 py-1 rounded ${
                              modalAnalysis.results.detection_breakdown.label_flipping.risk_level === 'HIGH' 
                                ? 'bg-red-200 dark:bg-red-800 text-red-900 dark:text-red-200'
                                : 'bg-yellow-200 dark:bg-yellow-800 text-yellow-900 dark:text-yellow-200'
                            }`}>
                              {modalAnalysis.results.detection_breakdown.label_flipping.risk_level} RISK
                            </span>
                          </div>
                          <p className="text-sm text-yellow-800 dark:text-yellow-300">
                            {modalAnalysis.results.detection_breakdown.label_flipping.summary}
                          </p>
                          {modalAnalysis.results.detection_breakdown.label_flipping.suspicious_pairs_count > 0 && (
                            <div className="mt-2 text-xs text-yellow-700 dark:text-yellow-400">
                              Found {modalAnalysis.results.detection_breakdown.label_flipping.suspicious_pairs_count} suspicious pairs 
                              and {modalAnalysis.results.detection_breakdown.label_flipping.duplicate_groups_count} duplicate groups
                            </div>
                          )}
                        </div>
                      )}

                      {/* Backdoor Triggers */}
                      {modalAnalysis.results.detection_breakdown.backdoor_triggers && 
                       modalAnalysis.results.detection_breakdown.backdoor_triggers.total_triggers_found > 0 && (
                        <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-4 border border-red-200 dark:border-red-800">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-sm font-semibold text-red-900 dark:text-red-300">
                              🚨 Backdoor Trigger Detection
                            </h5>
                            <span className={`text-xs font-medium px-2 py-1 rounded ${
                              modalAnalysis.results.detection_breakdown.backdoor_triggers.risk_level === 'HIGH'
                                ? 'bg-red-200 dark:bg-red-800 text-red-900 dark:text-red-200'
                                : modalAnalysis.results.detection_breakdown.backdoor_triggers.risk_level === 'MEDIUM'
                                ? 'bg-orange-200 dark:bg-orange-800 text-orange-900 dark:text-orange-200'
                                : 'bg-yellow-200 dark:bg-yellow-800 text-yellow-900 dark:text-yellow-200'
                            }`}>
                              {modalAnalysis.results.detection_breakdown.backdoor_triggers.risk_level} RISK
                            </span>
                          </div>
                          <p className="text-sm text-red-800 dark:text-red-300 mb-3">
                            {modalAnalysis.results.detection_breakdown.backdoor_triggers.summary}
                          </p>
                          {modalAnalysis.results.detection_breakdown.backdoor_triggers.ngram_triggers?.length > 0 && (
                            <div className="space-y-1">
                              <div className="text-xs font-medium text-red-700 dark:text-red-400 mb-1">
                                Detected Triggers:
                              </div>
                              {modalAnalysis.results.detection_breakdown.backdoor_triggers.ngram_triggers.slice(0, 5).map((trigger, idx) => (
                                <div key={idx} className="bg-white dark:bg-gray-800 rounded px-2 py-1 text-xs flex items-center justify-between">
                                  <span className="font-mono text-red-600 dark:text-red-400">{trigger.trigger}</span>
                                  <span className="text-gray-500 dark:text-gray-400">
                                    {(trigger.frequency * 100).toFixed(1)}% frequency
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Data Corruption */}
                      {modalAnalysis.results.detection_breakdown.data_corruption && 
                       modalAnalysis.results.detection_breakdown.data_corruption.corrupted_samples_count > 0 && (
                        <div className="bg-purple-50 dark:bg-purple-900/20 rounded-lg p-4 border border-purple-200 dark:border-purple-800">
                          <div className="flex items-center justify-between mb-2">
                            <h5 className="text-sm font-semibold text-purple-900 dark:text-purple-300">
                              💥 Data Corruption Detection
                            </h5>
                            <span className={`text-xs font-medium px-2 py-1 rounded ${
                              modalAnalysis.results.detection_breakdown.data_corruption.risk_level === 'HIGH'
                                ? 'bg-red-200 dark:bg-red-800 text-red-900 dark:text-red-200'
                                : modalAnalysis.results.detection_breakdown.data_corruption.risk_level === 'MEDIUM'
                                ? 'bg-orange-200 dark:bg-orange-800 text-orange-900 dark:text-orange-200'
                                : 'bg-yellow-200 dark:bg-yellow-800 text-yellow-900 dark:text-yellow-200'
                            }`}>
                              {modalAnalysis.results.detection_breakdown.data_corruption.risk_level} RISK
                            </span>
                          </div>
                          <p className="text-sm text-purple-800 dark:text-purple-300">
                            {modalAnalysis.results.detection_breakdown.data_corruption.summary}
                          </p>
                          {modalAnalysis.results.detection_breakdown.data_corruption.issue_types && (
                            <div className="mt-2 flex flex-wrap gap-2">
                              {Object.entries(modalAnalysis.results.detection_breakdown.data_corruption.issue_types).map(([type, count]) => (
                                <span key={type} className="text-xs px-2 py-1 bg-purple-200 dark:bg-purple-800 text-purple-900 dark:text-purple-200 rounded">
                                  {type.replace(/_/g, ' ')}: {count}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Multi-Source Confidence */}
                      {modalAnalysis.results.confidence_level && (
                        <div className="bg-green-50 dark:bg-green-900/20 rounded-lg p-4 border border-green-200 dark:border-green-800">
                          <div className="flex items-center justify-between">
                            <div>
                              <h5 className="text-sm font-semibold text-green-900 dark:text-green-300">
                                ✅ Confidence Level
                              </h5>
                              <p className="text-xs text-green-700 dark:text-green-400 mt-1">
                                {modalAnalysis.results.suspicious_count > 0 && 
                                  `${Math.round((modalAnalysis.results.suspicious_entries?.filter(e => e.detection_sources?.length > 1).length / modalAnalysis.results.suspicious_count) * 100)}% of suspicious samples were flagged by multiple detectors`
                                }
                              </p>
                            </div>
                            <span className="text-lg font-bold text-green-600 dark:text-green-400 uppercase">
                              {modalAnalysis.results.confidence_level}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* AI Semantic Analysis */}
                {modalAnalysis.results?.semantic_analysis && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 mb-6">
                    <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-3">AI Analysis Summary</h4>
                    <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
                      <p className="text-sm text-gray-700 dark:text-gray-300">
                        {modalAnalysis.results.semantic_analysis.summary || 'No detailed analysis available.'}
                      </p>
                    </div>
                  </div>
                )}

                {/* Summary from Enhanced Analyzer */}
                {modalAnalysis.results?.summary && (
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-4 border border-gray-300 dark:border-gray-700">
                    <h4 className="text-md font-semibold text-gray-900 dark:text-white mb-2">Analysis Summary</h4>
                    <pre className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap font-mono">
                      {modalAnalysis.results.summary}
                    </pre>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="bg-gray-50 dark:bg-gray-800 px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex-shrink-0">
                <div className="flex justify-end">
                  <button
                    onClick={closeResultsModal}
                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
                  >
                    Close
                  </button>
                </div>
              </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dataset;
