import React, { useState, useMemo } from 'react';
import {
  X, Shield, AlertTriangle, CheckCircle, ChevronDown, ChevronUp, ChevronRight,
  FileText, Database, Wrench, ThumbsUp, ThumbsDown, RefreshCw, BarChart3,
  Target, Zap
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { SecbugForm } from './SecbugModal';

// ── Technique → Category mapping ──────────────────────────────────────
const TECHNIQUE_TO_CATEGORY = {
  // Visual prompt injection
  'VISUAL_PROMPT_INJECTION': 'Visual',
  // RAG techniques
  'RAG_POISONING': 'RAG', 'RAG_ATTACK': 'RAG', 'RETRIEVAL_MANIPULATION': 'RAG',
  'KB_EXTRACTION': 'RAG', 'CITATION_ATTACK': 'RAG', 'RANKING_MANIPULATION': 'RAG',
  'EMBEDDING_ATTACK': 'RAG', 'CONTEXT_OVERFLOW': 'RAG',
  // PII techniques
  'PII_ATTACK': 'PII', 'DIRECT_PII_EXTRACTION': 'PII', 'PII_INFERENCE': 'PII',
  'BIOMETRIC_EXTRACTION': 'PII', 'RE_IDENTIFICATION': 'PII', 'HEALTH_DATA_LEAK': 'PII',
  'AGGREGATE_DISCLOSURE': 'PII', 'PII_EXTRACTION': 'PII', 'DATA_EXFILTRATION': 'PII',
  'IDENTITY_PROBING': 'PII',
  // Agentic techniques
  'AGENTIC_ATTACK': 'Agentic', 'AGENTIC_INFO_LEAKAGE': 'Agentic', 'AGENTIC_SCRIPT_GEN': 'Agentic',
  'TOOL_MCP_ATTACK': 'Agentic', 'FULL_ATTACK_CHAIN': 'Agentic', 'ZERO_CLICK_ATTACK': 'Agentic',
  'TOOL_MANIPULATION': 'Agentic', 'AGENT_HIJACKING': 'Agentic', 'CHAIN_BREAKING': 'Agentic',
  'TOOL_INJECTION': 'Agentic', 'AGENTIC_ENCODING': 'Agentic',
  'OUTPUT_MANIPULATION': 'Agentic', 'MEMORY_POISONING': 'Agentic', 'CROSS_SESSION_LEAK': 'Agentic',
};

const getCategoryForTechnique = (technique) => {
  const upper = (technique || '').toUpperCase();
  return TECHNIQUE_TO_CATEGORY[upper] || 'Normal';
};

const CATEGORY_META = {
  'Visual':  { label: 'Visual',  badgeClass: 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' },
  'Agentic': { label: 'Agentic', badgeClass: 'bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300' },
  'RAG':     { label: 'RAG',     badgeClass: 'bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300' },
  'PII':     { label: 'PII',     badgeClass: 'bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300' },
  'Normal':  { label: 'Normal',  badgeClass: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300' },
};

// Helper function to format model name for display
const formatModelNameForDisplay = (modelId) => {
  if (!modelId) return null;
  let formatted = modelId;
  // Remove "Unknown:" prefix
  formatted = formatted.replace(/^Unknown:/i, '');
  // Strip "custom-api:" prefix
  formatted = formatted.replace(/^custom-api:/i, '');
  // Remove "-usecase" suffix
  formatted = formatted.replace(/-usecase$/i, '');
  // Handle generic "proxy-target" placeholder
  if (formatted === 'proxy-target') {
    return 'Custom Proxy';
  }
  return formatted;
};

// Technique Card component for expandable results
const TechniqueResultCard = ({ result, index, scanName, onRaiseSecbug }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [feedback, setFeedback] = useState(null);
  
  const handleFeedback = (type) => {
    setFeedback(feedback === type ? null : type);
    console.log('Feedback:', type, 'for result:', result.technique);
  };
  
  const promptText = result.prompt || result.input || result.attack_prompt || result.text || '';
  const responseText = result.response || result.output || result.answer || result.model_response || '';
  const bypassed = Boolean(result.bypassed || result.bypass_successful);
  
  // Only show Raise SECBUG for successful bypasses
  const showSecbugButton = bypassed;
  
  return (
    <div className={`rounded-lg border overflow-hidden ${
      bypassed 
        ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800' 
        : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
    }`}>
      {/* Collapsed Header */}
      <div className="px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center space-x-3 flex-1 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          {bypassed ? (
            <AlertTriangle className="h-5 w-5 text-red-600 flex-shrink-0" />
          ) : (
            <CheckCircle className="h-5 w-5 text-green-600 flex-shrink-0" />
          )}
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 dark:text-white text-sm">
              {result.technique || 'Unknown Technique'}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate mt-0.5">
              {promptText.substring(0, 80)}{promptText.length > 80 ? '...' : ''}
            </div>
          </div>
        </button>
        <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            bypassed 
              ? 'bg-red-600 text-white' 
              : 'bg-green-600 text-white'
          }`}>
            {bypassed ? 'BYPASSED' : 'BLOCKED'}
          </span>
          {showSecbugButton && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                onRaiseSecbug({
                  vulnerability_type: `Guardrail Bypass - ${result.technique || 'Unknown'}`,
                  severity: 'high',
                  attack_type: result.technique,
                  payload: promptText,
                  response: responseText,
                  details: `This prompt successfully bypassed the guardrails using the ${result.technique} technique. Model: ${result.model || 'Unknown'}`,
                  recommendation: 'Review and strengthen guardrails against this attack technique. Consider adding specific filters for this type of bypass.'
                }, scanName, result.technique || 'Unknown Technique');
              }}
              className="px-3 py-1 text-xs font-medium text-primary-700 dark:text-primary-300 bg-primary-100 dark:bg-primary-900/40 hover:bg-primary-200 dark:hover:bg-primary-900/60 rounded-md transition-colors"
            >
              Raise Ticket
            </button>
          )}
          {/* Feedback buttons */}
          <div className="flex items-center space-x-0.5 ml-1 border-l border-gray-200 dark:border-gray-700 pl-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleFeedback('up');
              }}
              className={`p-1 rounded transition-colors ${
                feedback === 'up' 
                  ? 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30' 
                  : 'text-gray-400 hover:text-green-500 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="Helpful result"
            >
              <ThumbsUp className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleFeedback('down');
              }}
              className={`p-1 rounded transition-colors ${
                feedback === 'down' 
                  ? 'text-red-500 dark:text-red-400 bg-red-100 dark:bg-red-900/30' 
                  : 'text-gray-400 hover:text-red-500 hover:bg-gray-100 dark:hover:bg-gray-700'
              }`}
              title="False positive"
            >
              <ThumbsDown className="h-3.5 w-3.5" />
            </button>
          </div>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 hover:bg-gray-200 dark:hover:bg-gray-700 rounded transition-colors"
          >
            {isExpanded ? (
              <ChevronUp className="h-4 w-4 text-gray-400" />
            ) : (
              <ChevronDown className="h-4 w-4 text-gray-400" />
            )}
          </button>
        </div>
      </div>
      
      {/* Expanded Content */}
      {isExpanded && (
        <div className={`px-4 pb-4 space-y-3 border-t ${
          bypassed ? 'border-red-200 dark:border-red-800' : 'border-green-200 dark:border-green-800'
        }`}>
          {/* Full Prompt */}
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Prompt:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-40">
              {promptText || 'No prompt available'}
            </div>
          </div>
          
          {/* Response */}
          <div>
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Response:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
              <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300">
                {responseText || 'No response available'}
              </pre>
            </div>
          </div>
          
          {/* LLM Verdict */}
          {result.verdict_reason && (
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium text-gray-600 dark:text-gray-400">Verdict:</span>
                {result.verdict_confidence != null && (
                  <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${
                    Math.round(result.verdict_confidence * 100) >= 80
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300'
                      : Math.round(result.verdict_confidence * 100) >= 50
                        ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300'
                        : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                  }`}>
                    {Math.round(result.verdict_confidence * 100)}% confidence
                  </span>
                )}
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                {result.verdict_reason}
              </div>
            </div>
          )}
          
          {/* Metadata */}
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div className="bg-gray-50 dark:bg-gray-900 p-2 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-gray-500 dark:text-gray-400">Model</div>
              <div className="font-medium text-gray-900 dark:text-white">{result.model || '—'}</div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-900 p-2 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-gray-500 dark:text-gray-400">Provider</div>
              <div className="font-medium text-gray-900 dark:text-white">{result.provider || '—'}</div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-900 p-2 rounded border border-gray-200 dark:border-gray-700">
              <div className="text-gray-500 dark:text-gray-400">Confidence</div>
              <div className="font-medium text-gray-900 dark:text-white">
                {result.verdict_confidence != null ? `${Math.round(result.verdict_confidence * 100)}%` : (result.confidence || '—')}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const ScanResultsModal = ({
  scanId,
  scanName,
  referenceId,
  isOpen,
  onClose,
  scanResults,
  loadingScanResults = false,
  attackConfig = null  // Attack config with scan type flags
}) => {
  // State for selected technique, category expansion, and SECBUG view
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [expandedCategories, setExpandedCategories] = useState({});
  const [secbugView, setSecbugView] = useState(null);

  // Toggle a category open/closed
  const toggleCategory = (catName) => {
    setExpandedCategories(prev => ({ ...prev, [catName]: !prev[catName] }));
  };

  // Select a category (show all its results in right panel)
  const handleCategoryClick = (catName) => {
    setSelectedTechnique(null);
    setSelectedCategory(selectedCategory === catName ? null : catName);
  };
  
  // Process scan results to calculate statistics and group by technique
  const processedData = useMemo(() => {
    if (!scanResults) return null;

    let totalPrompts = 0;
    let successfulBypasses = 0;
    let failedBypasses = 0;
    let detailedResults = [];

    // Extract results from different possible data structures
    if (scanResults.attack_results && Array.isArray(scanResults.attack_results)) {
      detailedResults = scanResults.attack_results;
    } else if (scanResults.results && Array.isArray(scanResults.results)) {
      detailedResults = scanResults.results;
    } else if (scanResults.data && Array.isArray(scanResults.data)) {
      detailedResults = scanResults.data;
    }

    // Merge visual prompt injection results into the same flow so they render
    // in the main two-panel layout (technique grouping + per-prompt cards)
    // instead of falling through to the "No Results Available" empty state.
    if (Array.isArray(scanResults.visual_attack_results) && scanResults.visual_attack_results.length > 0) {
      const visualNormalized = scanResults.visual_attack_results.map(r => ({
        ...r,
        technique: r.technique || 'VISUAL_PROMPT_INJECTION',
      }));
      detailedResults = [...detailedResults, ...visualNormalized];
    }

    totalPrompts = detailedResults.length;
    
    // Group by technique
    const techniqueMap = {};
    
    detailedResults.forEach(result => {
      const technique = result.technique || 'Unknown';
      const bypassed = Boolean(result.bypassed || result.bypass_successful);
      
      if (bypassed) {
          successfulBypasses++;
        } else {
          failedBypasses++;
        }
      
      if (!techniqueMap[technique]) {
        techniqueMap[technique] = {
          name: technique,
          results: [],
          bypasses: 0,
          blocked: 0
        };
      }
      
      techniqueMap[technique].results.push(result);
      if (bypassed) {
        techniqueMap[technique].bypasses++;
        } else {
        techniqueMap[technique].blocked++;
        }
      });

    // Group techniques into categories (Agentic, RAG, PII, Normal)
    const techniques = Object.values(techniqueMap);
    const categoryMap = {};
    techniques.forEach(tech => {
      const cat = getCategoryForTechnique(tech.name);
      if (!categoryMap[cat]) {
        categoryMap[cat] = {
          name: cat,
          techniques: [],
          totalPrompts: 0,
          totalBypasses: 0,
          totalBlocked: 0,
        };
      }
      categoryMap[cat].techniques.push(tech);
      categoryMap[cat].totalPrompts += tech.results.length;
      categoryMap[cat].totalBypasses += tech.bypasses;
      categoryMap[cat].totalBlocked += tech.blocked;
    });

    // Order categories: Visual first (so image-based scans surface clearly), then text categories.
    const categoryOrder = ['Visual', 'Agentic', 'RAG', 'PII', 'Normal'];
    const categories = categoryOrder
      .filter(c => categoryMap[c])
      .map(c => categoryMap[c]);

    return {
      totalPrompts,
      successfulBypasses,
      failedBypasses,
      bypassRate: totalPrompts > 0 ? (successfulBypasses / totalPrompts) * 100 : 0,
      techniques,
      categories,
      allResults: detailedResults
    };
  }, [scanResults]);

  // Extract target model info from scan results
  const modelInfo = useMemo(() => {
    if (!scanResults) return null;
    
    // Try to get model info from various possible locations
    const models = scanResults.metadata?.models || 
                   scanResults.models || 
                   scanResults.original_request?.models ||
                   scanResults.metadata?.original_request?.models || [];
    
    if (models.length > 0) {
      const model = models[0];
      // For custom-api, the actual model name is in custom_config.model_id
      const actualModelId = model.custom_config?.model_id || model.model_id || 'Unknown';
      return {
        provider: model.provider || model.custom_config?.type || 'Unknown',
        modelId: actualModelId,
        type: model.custom_config?.type || model.provider || 'custom-api'
      };
    }
    
    // Try to extract from model_results keys - but also check metadata for actual model name
    if (scanResults.model_results) {
      const modelKey = Object.keys(scanResults.model_results)[0];
      if (modelKey) {
        const [provider] = modelKey.split(':');
        // Try to get actual model name from metadata
        const actualModel = scanResults.metadata?.models?.[0]?.custom_config?.model_id ||
                           scanResults.metadata?.original_request?.models?.[0]?.custom_config?.model_id ||
                           modelKey.split(':')[1];
        return { provider, modelId: actualModel, type: provider };
      }
    }
    
    // Fallback: try to get from first result (text or visual)
    const firstResult = scanResults.attack_results?.[0] ||
                        scanResults.results?.[0] ||
                        scanResults.data?.[0] ||
                        scanResults.visual_attack_results?.[0];
    if (firstResult) {
      return {
        provider: firstResult.provider || firstResult.model_provider || 'custom-api',
        modelId: firstResult.model || firstResult.model_id || 'Unknown',
        type: firstResult.provider || 'custom-api'
      };
    }

    return null;
  }, [scanResults]);

  // Handle raise SECBUG
  const handleRaiseSecbug = (finding, serverName, toolName) => {
    setSecbugView({ finding, serverName, toolName });
  };

  // Handle back from SECBUG
  const handleSecbugBack = () => {
    setSecbugView(null);
  };

  // Helper function to properly escape CSV fields
  const escapeCsvField = (value) => {
    if (!value) return '';
    let stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
    let cleaned = stringValue
      .replace(/\r\n/g, ' ')
      .replace(/\n/g, ' ')
      .replace(/\r/g, ' ')
      .replace(/\t/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    cleaned = cleaned.replace(/"/g, '""');
    return cleaned;
  };

  // Export to CSV
  const exportToCSV = () => {
    if (!processedData || processedData.allResults.length === 0) {
      toast.error('No results to export');
      return;
    }

    let csvRows = [];
    csvRows.push("Prompt Number,Prompt,Response,Bypass Status,Model,Provider,Technique,Confidence,Timestamp");
    
    processedData.allResults.forEach((result, index) => {
        const prompt = escapeCsvField(result.prompt || result.input || result.attack_prompt || result.text);
      const response = escapeCsvField(result.response || result.output || result.answer || result.model_response);
      const bypassStatus = Boolean(result.bypassed || result.bypass_successful) ? 'Bypassed' : 'Not Bypassed';
        const model = escapeCsvField(result.model || result.model_id);
        const provider = escapeCsvField(result.provider);
      const technique = escapeCsvField(result.technique);
      const confidence = escapeCsvField(result.confidence);
        const timestamp = escapeCsvField(result.timestamp || result.created_at);
        
        csvRows.push(`"${index + 1}","${prompt}","${response}","${bypassStatus}","${model}","${provider}","${technique}","${confidence}","${timestamp}"`);
    });
    
    const csvContent = csvRows.join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `scan_results_${scanId}_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success(`${processedData.allResults.length} rows exported to CSV successfully!`);
  };

  // Export to JSON
  const exportToJSON = () => {
    if (!scanResults) return;
    
    const dataStr = JSON.stringify(scanResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement("a");
    link.href = url;
    link.download = `scan_results_${scanId}_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    toast.success('Results exported to JSON successfully!');
  };

  // Generate Report (similar to MCP)
  const generateReport = () => {
    if (!processedData) return;

    const reportHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>GenAI Red Teaming Report - ${scanName || scanId}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #1f2937; background: #fff; padding: 40px; max-width: 900px; margin: 0 auto; }
    .header { text-align: center; padding-bottom: 30px; border-bottom: 3px solid #2563eb; margin-bottom: 30px; }
    .header h1 { font-size: 28px; color: #1e40af; margin-bottom: 8px; }
    .header .subtitle { color: #6b7280; font-size: 14px; }
    .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0 30px 0; }
    .metric-card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 15px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .metric-card .value { font-size: 28px; font-weight: 700; }
    .metric-card .label { font-size: 11px; color: #6b7280; text-transform: uppercase; }
    .metric-bypassed { color: #dc2626; }
    .metric-blocked { color: #059669; }
    .metric-total { color: #2563eb; }
    .metric-rate { color: #dc2626; }
    .section { margin-bottom: 30px; }
    .section h2 { font-size: 18px; color: #1e40af; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 15px; }
    .technique-card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 15px; margin-bottom: 12px; background: #fff; }
    .technique-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .technique-name { font-weight: 600; font-size: 14px; color: #1f2937; }
    .technique-stats { display: flex; gap: 10px; }
    .stat-badge { padding: 3px 10px; border-radius: 15px; font-size: 11px; font-weight: 600; }
    .stat-bypassed { background: #fee2e2; color: #dc2626; }
    .stat-blocked { background: #d1fae5; color: #059669; }
    .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; font-size: 11px; color: #9ca3af; }
  </style>
</head>
<body>
  <div class="header">
    <h1>GenAI Red Teaming Report</h1>
    <div class="subtitle">Adversarial Prompt Testing Results</div>
    <div style="margin-top: 15px; font-size: 13px; color: #4b5563;">
      <strong>Target:</strong> ${scanName || scanId} | 
      <strong>Date:</strong> ${new Date().toLocaleString()}
    </div>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <div class="value metric-total">${processedData.totalPrompts}</div>
      <div class="label">Total Prompts</div>
    </div>
    <div class="metric-card">
      <div class="value metric-bypassed">${processedData.successfulBypasses}</div>
      <div class="label">Successful Bypasses</div>
    </div>
    <div class="metric-card">
      <div class="value metric-blocked">${processedData.failedBypasses}</div>
      <div class="label">Blocked</div>
    </div>
    <div class="metric-card">
      <div class="value metric-rate">${Math.round(processedData.bypassRate)}%</div>
      <div class="label">Bypass Rate</div>
    </div>
  </div>

  <div class="section">
    <h2>Techniques Summary</h2>
    ${processedData.techniques.map(tech => `
      <div class="technique-card">
        <div class="technique-header">
          <span class="technique-name">${tech.name}</span>
          <div class="technique-stats">
            <span class="stat-badge stat-bypassed">${tech.bypasses} Bypassed</span>
            <span class="stat-badge stat-blocked">${tech.blocked} Blocked</span>
          </div>
        </div>
      </div>
    `).join('')}
  </div>

  <div class="footer">
    <p>Generated by Triksha - AI Security Platform</p>
    <p>Report generated on ${new Date().toLocaleString()}</p>
  </div>
</body>
</html>`;

    const reportWindow = window.open('', '_blank');
    reportWindow.document.write(reportHtml);
    reportWindow.document.close();
    reportWindow.onload = () => {
      setTimeout(() => {
        reportWindow.print();
      }, 500);
    };
  };

  // Get results for selected technique or all if none selected
  const displayResults = useMemo(() => {
    if (selectedTechnique) {
      return processedData?.techniques.find(t => t.name === selectedTechnique)?.results || [];
    }
    if (selectedCategory) {
      const cat = processedData?.categories?.find(c => c.name === selectedCategory);
      return cat ? cat.techniques.flatMap(t => t.results) : [];
    }
    return processedData?.allResults || [];
  }, [selectedTechnique, selectedCategory, processedData]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="fixed inset-0 transition-opacity bg-gray-500 dark:bg-gray-900 bg-opacity-75" onClick={onClose} />
      
      {/* Modal - Fixed height to match MCP modal */}
      <div className="relative bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl w-full max-w-7xl flex flex-col" style={{ height: '90vh', maxHeight: '900px' }}>
        {/* Header */}
        <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 flex-shrink-0">
          <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Target className="h-6 w-6 text-white" />
                <div>
                  <h3 className="text-lg font-semibold text-white">{scanName || scanId}</h3>
                  <p className="text-sm text-white/70">Contextual GenAI Red Teaming Results</p>
                </div>
              </div>
            <div className="flex items-center space-x-3">
              {referenceId && (
                <button
                  onClick={() => window.open(`${(process.env.REACT_APP_JIRA_URL || '').replace(/\/$/, '')}/browse/${referenceId}`, '_blank')}
                    className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                  >
                    <Shield className="w-4 h-4 mr-2" />
                    Ticket
                  </button>
                )}
                <button
                  onClick={generateReport}
                  className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                >
                  <FileText className="w-4 h-4 mr-2" />
                  Report
                </button>
                  <button
                    onClick={exportToCSV}
                  className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                  >
                  <FileText className="w-4 h-4 mr-2" />
                  CSV
                  </button>
                  <button
                    onClick={exportToJSON}
                  className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                  >
                  <Database className="w-4 h-4 mr-2" />
                  JSON
                  </button>
                <button onClick={onClose} className="text-white hover:text-gray-200">
                  <X className="h-6 w-6" />
              </button>
            </div>
          </div>
        </div>
        
        {/* Target Model Info Bar - matches MCP's view toggle area */}
        <div className="bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-3 flex-shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <Wrench className="h-4 w-4 text-gray-500 dark:text-gray-400" />
                <span className="text-sm text-gray-600 dark:text-gray-400">Target Model:</span>
              {modelInfo ? (
                  <span className="px-2.5 py-1 bg-primary-100 dark:bg-primary-900/40 text-primary-700 dark:text-primary-300 text-sm font-medium rounded-md">
                    {formatModelNameForDisplay(
                      modelInfo.provider === 'custom-api' || modelInfo.provider === 'proxy'
                        ? modelInfo.modelId 
                        : `${modelInfo.provider}:${modelInfo.modelId}`
                    )}
                  </span>
                ) : (
                  <span className="text-sm text-gray-500 dark:text-gray-400 italic">Model info not available</span>
                )}
              </div>
              
              {/* Scan Types */}
              {attackConfig && (
                <div className="flex items-center space-x-2">
                  <Zap className="h-4 w-4 text-gray-500 dark:text-gray-400" />
                  <span className="text-sm text-gray-600 dark:text-gray-400">Scan Type:</span>
                  <div className="flex items-center space-x-1.5">
                    {attackConfig.is_rag_based && (
                      <span className="px-2 py-0.5 bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 text-xs font-medium rounded">
                        RAG
                      </span>
                    )}
                    {attackConfig.is_agentic && (
                      <span className="px-2 py-0.5 bg-blue-100 dark:bg-blue-900/40 text-blue-700 dark:text-blue-300 text-xs font-medium rounded">
                        Agentic
                      </span>
                    )}
                    {attackConfig.handles_pii && (
                      <span className="px-2 py-0.5 bg-orange-100 dark:bg-orange-900/40 text-orange-700 dark:text-orange-300 text-xs font-medium rounded">
                        PII
                      </span>
                    )}
                    {attackConfig.is_normal && (
                      <span className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs font-medium rounded">
                        Normal
                      </span>
                    )}
                    {attackConfig.is_guardrail_scan && (
                      <span className="px-2 py-0.5 bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 text-xs font-medium rounded">
                        Guardrail
                      </span>
                    )}
                    {!attackConfig.is_rag_based && !attackConfig.is_agentic && !attackConfig.handles_pii && !attackConfig.is_normal && !attackConfig.is_guardrail_scan && (
                      <span className="text-sm text-gray-500 dark:text-gray-400 italic">Standard</span>
                    )}
                  </div>
                </div>
              )}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400">
              Contextual GenAI red teaming results
            </div>
          </div>
                  </div>

          {/* Content - fills remaining space */}
          <div className="flex relative overflow-hidden flex-1">
            {loadingScanResults ? (
              <div className="flex items-center justify-center w-full">
                <div className="text-center">
                  <RefreshCw className="h-8 w-8 text-primary-600 animate-spin mx-auto mb-4" />
                  <p className="text-gray-600 dark:text-gray-400">Loading scan results...</p>
                </div>
              </div>
            ) : processedData && processedData.totalPrompts > 0 ? (
              <>
                {/* LEFT Panel - Techniques List OR Results (when SECBUG is open) */}
                <div 
                  className={`border-r border-gray-200 dark:border-gray-700 overflow-y-auto bg-gray-50 dark:bg-gray-900 transition-all duration-300 ease-in-out ${
                    secbugView ? 'w-3/5' : 'w-2/5'
                  }`}
                >
                  {secbugView ? (
                    /* Show Results when SECBUG form is open */
                    <div className="p-6">
                      <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                        <Zap className="h-5 w-5 mr-2 text-primary-600" />
                        {secbugView.toolName}
                      </h4>
                      
                      <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        Bypassed Prompts ({displayResults.filter(r => Boolean(r.bypassed || r.bypass_successful)).length})
                      </h5>
                      
                      <div className="space-y-3">
                        {displayResults.filter(r => Boolean(r.bypassed || r.bypass_successful)).map((result, idx) => (
                          <TechniqueResultCard 
                            key={idx} 
                            result={result}
                            index={idx}
                            scanName={scanName || scanId}
                            onRaiseSecbug={handleRaiseSecbug}
                          />
                        ))}
                      </div>
                    </div>
                  ) : (
                    /* Normal Techniques List View */
                    <div className="p-6">
                      {/* Summary Stats */}
                      <div className="grid grid-cols-2 gap-3 mb-6">
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 border border-gray-200 dark:border-gray-700 text-center">
                          <div className="text-xl font-bold text-blue-600">{processedData.totalPrompts}</div>
                          <div className="text-xs text-gray-500">Total Prompts</div>
                  </div>
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 border border-gray-200 dark:border-gray-700 text-center">
                          <div className={`text-xl font-bold ${processedData.bypassRate > 0 ? 'text-red-600' : 'text-green-600'}`}>
                            {Math.round(processedData.bypassRate)}%
                </div>
                          <div className="text-xs text-gray-500">Bypass Rate</div>
                  </div>
                </div>
                      
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                        <Zap className="h-4 w-4 mr-2" />
                        Techniques Tested ({processedData.techniques.length})
                      </h4>
                      
                      {/* All option */}
                      <div 
                        className={`mb-3 bg-white dark:bg-gray-800 border-2 rounded-lg p-3 cursor-pointer transition-all ${
                          selectedTechnique === null && selectedCategory === null
                            ? 'border-primary-500 shadow-md'
                            : 'border-gray-200 dark:border-gray-700 hover:border-primary-300 hover:shadow-sm'
                        }`}
                        onClick={() => { setSelectedTechnique(null); setSelectedCategory(null); }}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-medium text-gray-900 dark:text-white">All Techniques</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-xs text-gray-500">{processedData.totalPrompts} prompts</span>
                            {processedData.successfulBypasses > 0 && (
                              <span className="flex items-center space-x-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full text-xs">
                                <AlertTriangle className="h-3 w-3" />
                                <span>{processedData.successfulBypasses}</span>
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      {/* Category sections with nested technique cards */}
                      {processedData.categories.map((category) => {
                        const meta = CATEGORY_META[category.name] || CATEGORY_META['Normal'];
                        const isExpanded = expandedCategories[category.name] !== false; // default open
                        const isCatSelected = selectedCategory === category.name && !selectedTechnique;
                        
                        return (
                          <div key={category.name} className="mb-3">
                            {/* Category header */}
                            <div 
                              className={`bg-white dark:bg-gray-800 border-2 rounded-lg overflow-hidden transition-all ${
                                isCatSelected
                                  ? 'border-primary-500 shadow-md'
                                  : 'border-gray-200 dark:border-gray-700 hover:border-primary-300'
                              }`}
                            >
                              <div className="flex items-center justify-between p-3 cursor-pointer"
                                onClick={() => { handleCategoryClick(category.name); toggleCategory(category.name); }}
                              >
                                <div className="flex items-center space-x-2">
                                  {isExpanded 
                                    ? <ChevronDown className="h-4 w-4 text-gray-400" /> 
                                    : <ChevronRight className="h-4 w-4 text-gray-400" />
                                  }
                                  <span className={`px-2 py-0.5 text-xs font-semibold rounded ${meta.badgeClass}`}>
                                    {meta.label}
                                  </span>
                                  <span className="font-medium text-gray-900 dark:text-white text-sm">
                                    {category.techniques.length} technique{category.techniques.length !== 1 ? 's' : ''}
                                  </span>
                                </div>
                                <div className="flex items-center space-x-2">
                                  <span className="text-xs text-gray-500">{category.totalPrompts} prompts</span>
                                  {category.totalBypasses > 0 && (
                                    <span className="flex items-center space-x-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full text-xs">
                                      <AlertTriangle className="h-3 w-3" />
                                      <span>{category.totalBypasses}</span>
                                    </span>
                                  )}
                                  {category.totalBypasses === 0 && (
                                    <CheckCircle className="h-4 w-4 text-green-500" />
                                  )}
                                </div>
                              </div>
                              
                              {/* Nested technique cards */}
                              {isExpanded && (
                                <div className="border-t border-gray-100 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/50 px-3 pb-3 pt-2 space-y-2">
                                  {category.techniques.map((technique) => (
                                    <div 
                                      key={technique.name}
                                      className={`bg-white dark:bg-gray-800 border rounded-md p-2.5 cursor-pointer transition-all ${
                                        selectedTechnique === technique.name
                                          ? 'border-primary-500 shadow-sm bg-primary-50 dark:bg-primary-900/20'
                                          : 'border-gray-200 dark:border-gray-700 hover:border-primary-300 hover:shadow-sm'
                                      }`}
                                      onClick={(e) => { 
                                        e.stopPropagation(); 
                                        setSelectedTechnique(technique.name); 
                                        setSelectedCategory(null); 
                                      }}
                                    >
                                      <div className="flex items-center justify-between">
                                        <span className="font-medium text-gray-900 dark:text-white text-xs">{technique.name}</span>
                                        <div className="flex items-center space-x-2">
                                          <span className="text-xs text-gray-500">{technique.results.length} prompts</span>
                                          {technique.bypasses > 0 && (
                                            <span className="flex items-center space-x-1 px-1.5 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full text-xs">
                                              <AlertTriangle className="h-3 w-3" />
                                              <span>{technique.bypasses}</span>
                                            </span>
                                          )}
                                          {technique.bypasses === 0 && (
                                            <CheckCircle className="h-3.5 w-3.5 text-green-500" />
                                          )}
                                        </div>
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                    </div>
                    
                {/* RIGHT Panel - Results OR SECBUG Form */}
                <div 
                  className={`overflow-y-auto bg-white dark:bg-gray-800 transition-all duration-300 ease-in-out ${
                    secbugView ? 'w-2/5' : 'w-3/5'
                  }`}
                >
                  {secbugView ? (
                    /* SECBUG Form - slides in from right */
                    <div 
                      className="h-full"
                      style={{
                        animation: 'slideInRight 0.3s ease-out forwards'
                      }}
                    >
                      <style>{`
                        @keyframes slideInRight {
                          from {
                            opacity: 0;
                            transform: translateX(50px);
                          }
                          to {
                            opacity: 1;
                            transform: translateX(0);
                          }
                        }
                      `}</style>
                      <SecbugForm
                        finding={secbugView.finding}
                        serverName={secbugView.serverName}
                        toolName={secbugView.toolName}
                        onBack={handleSecbugBack}
                        onSuccess={(ticketKey, ticketUrl) => {
                          // Optionally do something on success
                        }}
                      />
                    </div>
                  ) : (
                    /* Normal Results View */
                    <div className="p-6">
                      <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                        <Wrench className="h-5 w-5 mr-2 text-primary-600" />
                        {selectedTechnique || (selectedCategory ? `${selectedCategory} Results` : 'All Results')}
                      </h4>
                      
                      {/* Stats for selected technique */}
                      <div className="grid grid-cols-2 gap-3 mb-6">
                        <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border border-gray-200 dark:border-gray-700">
                          <div className="text-lg font-bold text-gray-900 dark:text-white">{displayResults.length}</div>
                          <div className="text-xs text-gray-500">Total Prompts</div>
                        </div>
                        <div className={`rounded-lg p-3 border ${
                          displayResults.filter(r => Boolean(r.bypassed || r.bypass_successful)).length > 0 
                            ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800' 
                            : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                        }`}>
                          <div className={`text-lg font-bold ${
                            displayResults.filter(r => Boolean(r.bypassed || r.bypass_successful)).length > 0 ? 'text-red-600' : 'text-green-600'
                          }`}>
                            {displayResults.filter(r => Boolean(r.bypassed || r.bypass_successful)).length}
                          </div>
                          <div className="text-xs text-gray-500">Bypasses</div>
                        </div>
                      </div>
                      
                      {/* Results List */}
                      <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                        Results ({displayResults.length})
                      </h5>
                      
                      {displayResults.length === 0 ? (
                        <div className="text-center py-8 bg-gray-50 dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700">
                          <BarChart3 className="h-10 w-10 mx-auto mb-3 text-gray-400" />
                          <p className="text-gray-500 dark:text-gray-400">No results to display</p>
                  </div>
                      ) : (
                        <div className="space-y-3">
                          {displayResults.map((result, idx) => (
                            <TechniqueResultCard 
                              key={idx} 
                              result={result}
                              index={idx}
                              scanName={scanName || scanId}
                              onRaiseSecbug={handleRaiseSecbug}
                            />
                ))}
              </div>
                      )}
                    </div>
                  )}
              </div>
              </>
            ) : (
              <div className="flex flex-col items-center justify-center w-full text-center p-8">
                <BarChart3 className="h-12 w-12 text-gray-400 mb-4" />
                <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No Results Available</h4>
                <p className="text-gray-500 dark:text-gray-400 max-w-md">
                  No scan results are available for this scan.
                </p>
              </div>
            )}

          </div>

          {/* Footer */}
          <div className="px-6 py-3 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 flex-shrink-0">
            <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
              <span>Scan ID: {scanId}</span>
              <span>Generated by Triksha</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanResultsModal;
