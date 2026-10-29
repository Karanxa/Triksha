import React, { useState, useEffect } from 'react';
import {
  X, Shield, AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp,
  AlertOctagon, Info, Server, ArrowRight, GitBranch, Wrench, MessageSquare, FileCode,
  ThumbsUp, ThumbsDown, RefreshCw
} from 'lucide-react';
import { SecbugForm } from './SecbugModal';

// Smart description formatter - makes long descriptions digestible
const SmartDescription = ({ text, maxLength = 150 }) => {
  if (!text) return <span className="text-gray-500 dark:text-gray-400 italic text-xs">No description</span>;
  
  // Extract first sentence or up to maxLength
  const firstSentence = text.match(/^[^.!?]+[.!?]/)?.[0] || text.substring(0, maxLength);
  const preview = firstSentence.length > maxLength ? firstSentence.substring(0, maxLength) + '...' : firstSentence;
  
  return (
    <div className="text-xs text-gray-600 dark:text-gray-400 leading-relaxed">
      {preview}
    </div>
  );
};
  
// Collapsible section component
const CollapsibleSection = ({ title, children, defaultOpen = false }) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  
  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-3 py-2 bg-gray-50 dark:bg-gray-900 hover:bg-gray-100 dark:hover:bg-gray-800 flex items-center justify-between text-left transition-colors"
      >
        <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">{title}</span>
        {isOpen ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
      </button>
      {isOpen && (
        <div className="px-3 py-2 bg-white dark:bg-gray-800 text-xs text-gray-600 dark:text-gray-400 border-t border-gray-200 dark:border-gray-700">
          {children}
        </div>
      )}
    </div>
  );
};
  
// Issue Card component for active scan findings
const IssueCard = ({ finding, serverName, toolName, onRaiseSecbug }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [feedback, setFeedback] = useState(null); // null | 'up' | 'down'
  
  const handleFeedback = (type) => {
    setFeedback(feedback === type ? null : type);
    // TODO: Backend logic to store feedback will be implemented later
    console.log('Feedback:', type, 'for finding:', finding.vulnerability_type || finding.attack_type);
  };
  
  const payloadPreview = (() => {
    try {
      const parsed = JSON.parse(finding.payload || '{}');
      const value = Object.values(parsed)[0];
      return typeof value === 'string' ? value.substring(0, 50) + (value.length > 50 ? '...' : '') : JSON.stringify(parsed).substring(0, 50);
    } catch {
      return (finding.payload || '').substring(0, 50);
    }
  })();
  
  const fullPayload = (() => {
    try {
      const parsed = JSON.parse(finding.payload || '{}');
      const first = Object.values(parsed)[0];
      // Stringify non-primitive values so React can render them — without this
      // a nested-object payload like {"req": {"userContext": {...}}} would
      // return an object and crash the modal with "Objects are not valid as a
      // React child" → blank white screen.
      if (first === undefined || first === null) return JSON.stringify(parsed, null, 2);
      if (typeof first === 'string' || typeof first === 'number' || typeof first === 'boolean') {
        return String(first);
      }
      return JSON.stringify(first, null, 2);
    } catch {
      return typeof finding.payload === 'string' ? finding.payload : JSON.stringify(finding.payload);
    }
  })();
  
  // Dynamic colors based on severity
  const severityColors = {
    critical: {
      bg: 'bg-red-50 dark:bg-red-900/20',
      border: 'border-red-200 dark:border-red-800',
      icon: 'text-red-600',
      expandBorder: 'border-red-200 dark:border-red-800'
    },
    high: {
      bg: 'bg-orange-50 dark:bg-orange-900/20',
      border: 'border-orange-200 dark:border-orange-800',
      icon: 'text-orange-600',
      expandBorder: 'border-orange-200 dark:border-orange-800'
    },
    medium: {
      bg: 'bg-yellow-50 dark:bg-yellow-900/20',
      border: 'border-yellow-200 dark:border-yellow-800',
      icon: 'text-yellow-600',
      expandBorder: 'border-yellow-200 dark:border-yellow-800'
    },
    low: {
      bg: 'bg-blue-50 dark:bg-blue-900/20',
      border: 'border-blue-200 dark:border-blue-800',
      icon: 'text-blue-600',
      expandBorder: 'border-blue-200 dark:border-blue-800'
    }
  };
  
  const colors = severityColors[finding.severity] || severityColors.medium;
  
  return (
    <div className={`rounded-lg border ${colors.bg} ${colors.border} overflow-hidden`}>
      {/* Collapsed Header */}
      <div className="px-4 py-3 flex items-center justify-between">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center space-x-3 flex-1 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          <AlertTriangle className={`h-5 w-5 ${colors.icon} flex-shrink-0`} />
          <div className="flex-1 min-w-0">
            <div className="font-medium text-gray-900 dark:text-white text-sm">
              {finding.vulnerability_type || finding.attack_type}
            </div>
            <div className="text-xs text-gray-500 dark:text-gray-400 font-mono truncate mt-0.5">
              {payloadPreview}
            </div>
          </div>
        </button>
        <div className="flex items-center space-x-2 flex-shrink-0 ml-2">
          {finding.severity && (
            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
              finding.severity === 'critical' ? 'bg-red-600 text-white' :
              finding.severity === 'high' ? 'bg-orange-500 text-white' :
              finding.severity === 'medium' ? 'bg-yellow-500 text-black' :
              'bg-blue-500 text-white'
            }`}>
              {finding.severity.toUpperCase()}
            </span>
          )}
          <button
            onClick={(e) => {
              e.stopPropagation();
              if (onRaiseSecbug) {
                onRaiseSecbug(finding, serverName, toolName);
              }
            }}
            className="px-3 py-1 text-xs font-medium text-primary-700 dark:text-primary-300 bg-primary-100 dark:bg-primary-900/40 hover:bg-primary-200 dark:hover:bg-primary-900/60 rounded-md transition-colors"
          >
            Raise Ticket
          </button>
          {/* Subtle feedback buttons */}
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
              title="Helpful finding"
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
        <div className={`px-4 pb-4 space-y-3 border-t ${colors.expandBorder}`}>
          {/* Full Payload */}
          <div className="pt-3">
            <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Payload:</div>
            <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded overflow-x-auto border border-gray-200 dark:border-gray-700 max-h-32">
              {fullPayload}
            </div>
          </div>
          
          {/* Response */}
          {finding.response && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Response:</div>
              <div className="text-sm font-mono bg-white dark:bg-gray-800 p-2 rounded overflow-auto border border-gray-200 dark:border-gray-700 max-h-48">
                <pre className="whitespace-pre-wrap text-xs text-gray-700 dark:text-gray-300">
                  {(() => {
                    try {
                      const parsed = JSON.parse(finding.response);
                      if (parsed.content && Array.isArray(parsed.content)) {
                        return parsed.content.map(c => c.text || JSON.stringify(c)).join('\n');
                      }
                      return JSON.stringify(parsed, null, 2);
                    } catch {
                      // Defend against non-string finding.response values.
                      return typeof finding.response === 'string'
                        ? finding.response
                        : JSON.stringify(finding.response);
                    }
                  })()}
                </pre>
              </div>
            </div>
          )}
          
          {/* Details */}
          {finding.details && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Details:</div>
              <div className="text-sm text-gray-700 dark:text-gray-300">
                {typeof finding.details === 'string' ? finding.details : JSON.stringify(finding.details)}
              </div>
            </div>
          )}

          {/* Recommendation */}
          {finding.recommendation && (
            <div>
              <div className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">Recommendation:</div>
              <div className="text-sm text-gray-700 dark:text-gray-300">
                {typeof finding.recommendation === 'string' ? finding.recommendation : JSON.stringify(finding.recommendation)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
  };
  
// Full description for detail view - parses into structured sections
const FullDescription = ({ text }) => {
  if (!text) return <span className="text-gray-500 dark:text-gray-400 italic">No description available</span>;
  
  const sections = [];
  const lines = text.split('\n');
  let currentSection = null;
  let mainDescription = [];
  
  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    
    // Detect section headers (ends with colon or all caps followed by colon)
    const sectionMatch = trimmed.match(/^((?:Supported operations|Use cases|Args|Arguments|Returns?|Examples?|Possible return types|Format|Parameters|Options)[^:]*):?\s*$/i);
      
    if (sectionMatch) {
      // Save previous section
      if (currentSection) {
        sections.push(currentSection);
      }
      currentSection = {
        title: sectionMatch[1],
        content: []
      };
    } else if (currentSection) {
      // Add to current section
      currentSection.content.push(trimmed);
      } else {
      // Main description (before any sections)
      mainDescription.push(trimmed);
      }
  });
  
  // Save last section
  if (currentSection) {
    sections.push(currentSection);
  }
  
  return (
    <div className="space-y-3">
      {/* Main description */}
      {mainDescription.length > 0 && (
        <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
          {mainDescription.join(' ')}
        </p>
      )}
      
      {/* Collapsible sections */}
      {sections.map((section, idx) => (
        <CollapsibleSection key={idx} title={section.title} defaultOpen={idx === 0}>
          <div className="space-y-1 leading-relaxed">
            {section.content.map((item, iidx) => {
              // If it looks like a list item (starts with -, •, or word:)
              if (/^[-•*]\s/.test(item) || /^\w+:\s/.test(item)) {
                const cleanItem = item.replace(/^[-•*]\s*/, '');
                return (
                  <div key={iidx} className="flex items-start">
                    <span className="text-primary-600 dark:text-primary-400 mr-2">•</span>
                    <span>{cleanItem}</span>
                  </div>
                );
    }
              // Regular text
              return <p key={iidx}>{item}</p>;
            })}
          </div>
        </CollapsibleSection>
      ))}
    </div>
  );
};

const MCPSecurityModal = ({ scan, onClose }) => {
  // Extract data before hooks
  const { servers = [], summary = {} } = scan?.data || {};
  const securitySummary = summary.security_summary || {};
  
  // Default to first server selected
  const [selectedEntity, setSelectedEntity] = useState(
    servers.length > 0 ? { type: 'server', data: servers[0], index: 0 } : null
  );
  
  // Passive/Active scan toggle
  const [scanView, setScanView] = useState('passive'); // 'passive' | 'active'
  const [activeResults, setActiveResults] = useState(null);
  const [loadingActive, setLoadingActive] = useState(false);
  
  // SECBUG sliding panel state
  const [secbugView, setSecbugView] = useState(null); // null or { finding, serverName, toolName }
  
  // Handle raise SECBUG - transitions to SECBUG form view
  const handleRaiseSecbug = (finding, serverName, toolName) => {
    setSecbugView({ finding, serverName, toolName });
  };
  
  // Handle back from SECBUG - returns to normal view
  const handleSecbugBack = () => {
    setSecbugView(null);
  };
  
  // Fetch active scan results when toggled. Active testing runs in the
  // background after the passive scan, so keep allowing re-fetch while empty.
  const fetchActiveResults = async (silent = false) => {
    if (activeResults && activeResults.findings && activeResults.findings.length > 0) return activeResults;
    if (!silent) setLoadingActive(true);
    try {
      const response = await fetch(`/mcp/scan/${scan.scan_id || scan.id}/active-results`, {
        credentials: 'include'
      });
      const data = await response.json();
      if (data.status === 'ok') {
        setActiveResults(data);
        // Auto-select first tool if available
        if (data.findings && data.findings.length > 0) {
          const toolMap = {};
          data.findings.forEach(f => {
            if (!toolMap[f.tool_name]) {
              toolMap[f.tool_name] = { tests: [], vulnerabilities: 0 };
            }
            toolMap[f.tool_name].tests.push(f);
            if (f.vulnerability_found) {
              toolMap[f.tool_name].vulnerabilities++;
            }
          });
          const firstTool = Object.keys(toolMap)[0];
          if (firstTool) {
            setSelectedEntity({ type: 'active-tool', data: { name: firstTool, ...toolMap[firstTool] } });
          }
        }
        return data;
      }
    } catch (err) {
      console.error('Failed to fetch active scan results:', err);
    } finally {
      if (!silent) setLoadingActive(false);
    }
    return null;
  };

  // While viewing the Active tab, poll until findings arrive or the active
  // phase reaches a terminal status. Active testing runs in the background
  // after the passive scan and can take a few minutes.
  useEffect(() => {
    if (scanView !== 'active') return;
    let stop = false;
    let tries = 0;
    const tick = async () => {
      if (stop) return;
      const data = await fetchActiveResults(true);
      const findings = (data && data.findings) || [];
      const st = data && data.active_status;
      // 'running' keeps polling; 'unknown' gets a few retries (covers the brief
      // race on a fresh scan) then stops; any other status is terminal.
      const terminal = st && st !== 'running' && !(st === 'unknown' && tries < 5);
      if (findings.length > 0 || terminal || tries >= 40) return; // stop polling
      tries += 1;
      if (!stop) setTimeout(tick, 6000);
    };
    tick();
    return () => { stop = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanView]);

  if (!scan || !scan.data) return null;
  
  // Aggregate risk_breakdown from all servers
  const aggregateRisks = servers.reduce((acc, server) => {
    if (server.risk_breakdown) {
      acc.critical += server.risk_breakdown.critical || 0;
      acc.high += server.risk_breakdown.high || 0;
      acc.medium += server.risk_breakdown.medium || 0;
      acc.low += server.risk_breakdown.low || 0;
    }
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
  
  const highRiskCount = (securitySummary.high || 0) + aggregateRisks.high + aggregateRisks.critical;
  const mediumRiskCount = (securitySummary.medium || 0) + aggregateRisks.medium;
  const lowRiskCount = (securitySummary.low || 0) + aggregateRisks.low;
  const avgScore = securitySummary.average_score || 100;
  
  const getScoreColor = (score) => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    return 'text-red-600';
  };
  
  const generateReport = () => {
    // Get active scan results if available
    const activeFindings = activeResults?.findings || [];
    const vulnerableFindings = activeFindings.filter(f => f.vulnerability_found);
    
    // Calculate passive scan risk counts
    const passiveHighCount = servers.reduce((acc, s) => 
      acc + (s.security_findings?.filter(f => f.severity === 'high')?.length || 0), 0);
    const passiveMediumCount = servers.reduce((acc, s) => 
      acc + (s.security_findings?.filter(f => f.severity === 'medium')?.length || 0), 0);
    const passiveLowCount = servers.reduce((acc, s) => 
      acc + (s.security_findings?.filter(f => f.severity === 'low')?.length || 0), 0);
    
    // Calculate active scan risk counts
    const activeHighCount = vulnerableFindings.filter(f => 
      f.severity?.toLowerCase() === 'high' || f.severity?.toLowerCase() === 'critical').length;
    const activeMediumCount = vulnerableFindings.filter(f => 
      f.severity?.toLowerCase() === 'medium').length;
    const activeLowCount = vulnerableFindings.filter(f => 
      f.severity?.toLowerCase() === 'low').length;
    
    // Combined counts
    const highRiskCount = passiveHighCount + activeHighCount;
    const mediumRiskCount = passiveMediumCount + activeMediumCount;
    const lowRiskCount = passiveLowCount + activeLowCount;
    const totalFindings = highRiskCount + mediumRiskCount + lowRiskCount;
    
    // Calculate totals
    const totalTools = servers.reduce((acc, s) => acc + (s.tools?.length || 0), 0);
    const totalPrompts = servers.reduce((acc, s) => acc + (s.prompts?.length || 0), 0);
    const totalResources = servers.reduce((acc, s) => acc + (s.resources?.length || 0), 0);
    
    // Get all unique findings grouped by severity
  const allFindings = servers.flatMap(server => 
    (server.security_findings || []).map(f => ({
      ...f,
        serverName: server.server_name
    }))
  );
  
    const reportHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Assessment Report - ${scan.scanName || scan.fileName}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
      line-height: 1.6; 
      color: #1f2937; 
      background: #fff;
      padding: 40px;
      max-width: 900px;
      margin: 0 auto;
    }
    .header { 
      text-align: center; 
      padding-bottom: 30px; 
      border-bottom: 3px solid #2563eb; 
      margin-bottom: 30px;
    }
    .header h1 { font-size: 28px; color: #1e40af; margin-bottom: 8px; }
    .header .subtitle { color: #6b7280; font-size: 14px; }
    .header .scan-info { margin-top: 15px; font-size: 13px; color: #4b5563; }
    
    .executive-summary { 
      background: linear-gradient(135deg, #eff6ff 0%, #dbeafe 100%); 
      padding: 25px; 
      border-radius: 12px; 
      margin-bottom: 30px;
      border-left: 5px solid #2563eb;
    }
    .executive-summary h2 { color: #1e40af; margin-bottom: 15px; font-size: 18px; }
    .executive-summary p { color: #374151; font-size: 14px; }
    
    .metrics-grid { 
      display: grid; 
      grid-template-columns: repeat(4, 1fr); 
      gap: 15px; 
      margin: 20px 0 30px 0;
    }
    .metric-card { 
      background: #fff; 
      border: 1px solid #e5e7eb; 
      border-radius: 10px; 
      padding: 15px; 
      text-align: center;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .metric-card .value { font-size: 28px; font-weight: 700; }
    .metric-card .label { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; }
    .metric-high { color: #dc2626; }
    .metric-medium { color: #f59e0b; }
    .metric-low { color: #3b82f6; }
    .metric-score { color: #059669; }
    
    .section { margin-bottom: 30px; }
    .section h2 { 
      font-size: 18px; 
      color: #1e40af; 
      border-bottom: 2px solid #e5e7eb; 
      padding-bottom: 8px; 
      margin-bottom: 15px;
    }
    .section h3 { font-size: 15px; color: #374151; margin: 15px 0 10px 0; }
    
    .methodology { 
      background: #f9fafb; 
      padding: 20px; 
      border-radius: 10px; 
      margin-bottom: 30px;
    }
    .methodology h2 { color: #374151; margin-bottom: 12px; font-size: 16px; }
    .methodology p { font-size: 13px; color: #4b5563; margin-bottom: 10px; }
    .methodology ul { margin-left: 20px; font-size: 13px; color: #4b5563; }
    .methodology li { margin-bottom: 5px; }
    
    .finding-card {
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 15px;
      margin-bottom: 12px;
      background: #fff;
    }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-title { font-weight: 600; font-size: 14px; color: #1f2937; }
    .severity-badge { 
      padding: 3px 10px; 
      border-radius: 15px; 
      font-size: 11px; 
      font-weight: 600;
      text-transform: uppercase;
    }
    .severity-high { background: #fee2e2; color: #dc2626; }
    .severity-medium { background: #fef3c7; color: #d97706; }
    .severity-low { background: #dbeafe; color: #2563eb; }
    .finding-details { font-size: 13px; color: #4b5563; }
    .finding-server { font-size: 11px; color: #9ca3af; margin-top: 8px; }
    
    .server-section { 
      background: #f9fafb; 
      border-radius: 10px; 
      padding: 15px; 
      margin-bottom: 15px;
    }
    .server-name { font-weight: 600; font-size: 15px; color: #1f2937; margin-bottom: 8px; }
    .server-url { font-size: 12px; color: #6b7280; font-family: monospace; }
    .server-stats { display: flex; gap: 20px; margin-top: 10px; font-size: 12px; color: #4b5563; }
    
    .entity-list { margin-top: 12px; }
    .entity-item { 
      background: #fff; 
      border: 1px solid #e5e7eb; 
      border-radius: 6px; 
      padding: 10px 12px; 
      margin-bottom: 8px;
    }
    .entity-name { font-weight: 500; font-size: 13px; color: #1f2937; }
    .entity-desc { font-size: 12px; color: #6b7280; margin-top: 4px; }
    
    .recommendation-box {
      background: #ecfdf5;
      border-left: 4px solid #059669;
      padding: 15px;
      border-radius: 0 8px 8px 0;
      margin-top: 20px;
    }
    .recommendation-box h3 { color: #065f46; font-size: 14px; margin-bottom: 8px; }
    .recommendation-box ul { margin-left: 18px; font-size: 13px; color: #047857; }
    .recommendation-box li { margin-bottom: 5px; }
    
    .active-scan-section { margin-top: 30px; }
    .vuln-card {
      border-radius: 8px;
      margin-bottom: 20px;
      overflow: hidden;
      page-break-inside: avoid;
    }
    .vuln-card.high { background: #fff7ed; border: 1px solid #fed7aa; }
    .vuln-card.medium { background: #fefce8; border: 1px solid #fef08a; }
    .vuln-card.low { background: #eff6ff; border: 1px solid #bfdbfe; }
    .vuln-card.critical { background: #fef2f2; border: 1px solid #fecaca; }
    .vuln-header {
      padding: 15px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .vuln-icon { font-size: 20px; flex-shrink: 0; }
    .vuln-header-content { flex: 1; }
    .vuln-title { font-weight: 600; font-size: 15px; color: #1f2937; margin-bottom: 2px; }
    .vuln-payload-preview { font-size: 12px; color: #6b7280; font-family: monospace; }
    .vuln-badges { display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
    .severity-tag { 
      padding: 4px 12px; 
      border-radius: 4px; 
      font-size: 12px; 
      font-weight: 600; 
      text-transform: uppercase;
    }
    .severity-tag.high { background: #f97316; color: white; }
    .severity-tag.medium { background: #eab308; color: white; }
    .severity-tag.low { background: #3b82f6; color: white; }
    .severity-tag.critical { background: #dc2626; color: white; }
    .vuln-body { padding: 0 15px 15px 15px; }
    .vuln-section { margin-bottom: 15px; }
    .vuln-section:last-child { margin-bottom: 0; }
    .vuln-label { font-size: 13px; font-weight: 400; color: #374151; margin-bottom: 6px; }
    .vuln-box { 
      background: #fff; 
      border: 1px solid #e5e7eb; 
      border-radius: 6px; 
      padding: 12px; 
      font-family: 'Courier New', monospace; 
      font-size: 13px; 
      color: #1f2937;
      word-break: break-word;
      white-space: pre-wrap;
    }
    .vuln-details { font-size: 14px; color: #374151; line-height: 1.6; }
    .vuln-recommendation { font-size: 14px; color: #374151; line-height: 1.6; }
    
    .footer { 
      margin-top: 40px; 
      padding-top: 20px; 
      border-top: 1px solid #e5e7eb; 
      text-align: center;
      font-size: 11px;
      color: #9ca3af;
    }
    
    @media print {
      body { padding: 20px; }
      .finding-card, .server-section { break-inside: avoid; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>MCP Security Assessment Report</h1>
    <div class="subtitle">Model Context Protocol Server Security Analysis</div>
    <div class="scan-info">
      <strong>Target:</strong> ${scan.scanName || scan.fileName} | 
      <strong>Date:</strong> ${new Date(scan.timestamp).toLocaleString()} | 
      <strong>Scan ID:</strong> ${scan.id?.substring(0, 8)}...
    </div>
  </div>

  <div class="executive-summary">
    <h2>Executive Summary</h2>
    <p>
      This security assessment analyzed <strong>${servers.length} MCP server(s)</strong> containing 
      <strong>${totalTools} tool(s)</strong>${totalPrompts > 0 ? `, <strong>${totalPrompts} prompt(s)</strong>` : ''}${totalResources > 0 ? `${totalPrompts > 0 ? ',' : ''} and <strong>${totalResources} resource(s)</strong>` : ''}. 
      ${totalFindings > 0 
        ? `The assessment identified <strong>${totalFindings} security finding(s)</strong> in total — 
           <strong>${highRiskCount}</strong> high-severity, <strong>${mediumRiskCount}</strong> medium-severity, and <strong>${lowRiskCount}</strong> low-severity issues${vulnerableFindings.length > 0 ? ` (including ${vulnerableFindings.length} confirmed through active testing)` : ''}.`
        : vulnerableFindings.length > 0 
          ? `Active security testing discovered <strong>${vulnerableFindings.length} vulnerability(ies)</strong> through dynamic analysis.`
          : 'No significant security findings were identified.'
      }
    </p>
  </div>

  <div class="metrics-grid" style="grid-template-columns: repeat(3, 1fr);">
    <div class="metric-card">
      <div class="value metric-high">${highRiskCount}</div>
      <div class="label">High Risk</div>
    </div>
    <div class="metric-card">
      <div class="value metric-medium">${mediumRiskCount}</div>
      <div class="label">Medium Risk</div>
    </div>
    <div class="metric-card">
      <div class="value metric-low">${lowRiskCount}</div>
      <div class="label">Low Risk</div>
    </div>
  </div>

  <div class="methodology">
    <h2>Assessment Methodology</h2>
    <p>This security assessment was conducted using Triksha's automated MCP security scanner, which employs a two-phase approach:</p>
    <ul>
      <li><strong>Passive Analysis:</strong> Static examination of server configurations, tool definitions, prompt templates, and resource declarations to identify potential security misconfigurations, overly permissive access patterns, and risky capability exposures.</li>
      <li><strong>Active Testing:</strong> Dynamic security testing using an AI-powered agent that simulates realistic attack scenarios including prompt injection, tool abuse, data exfiltration attempts, and authorization bypass techniques.</li>
    </ul>
    <p style="margin-top: 10px;">The agent leverages contextual understanding of each tool's purpose to generate targeted security tests, ensuring comprehensive coverage of potential attack vectors specific to MCP implementations.</p>
  </div>

  ${totalFindings > 0 ? `
  <div class="section">
    <h2>Security Findings</h2>
    ${allFindings.filter(f => f.severity === 'high').length > 0 ? `
      <h3>High Severity Issues</h3>
      ${allFindings.filter(f => f.severity === 'high').map(f => `
        <div class="finding-card">
          <div class="finding-header">
            <span class="finding-title">${f.detector || f.type || 'Security Issue'}</span>
            <span class="severity-badge severity-high">High</span>
          </div>
          <div class="finding-details">${f.details || f.message || 'Potential security risk identified.'}</div>
          <div class="finding-server">Server: ${f.serverName} | Entity: ${f.entity_name || 'N/A'}</div>
        </div>
      `).join('')}
    ` : ''}
    
    ${allFindings.filter(f => f.severity === 'medium').length > 0 ? `
      <h3>Medium Severity Issues</h3>
      ${allFindings.filter(f => f.severity === 'medium').map(f => `
        <div class="finding-card">
          <div class="finding-header">
            <span class="finding-title">${f.detector || f.type || 'Security Issue'}</span>
            <span class="severity-badge severity-medium">Medium</span>
          </div>
          <div class="finding-details">${f.details || f.message || 'Potential security risk identified.'}</div>
          <div class="finding-server">Server: ${f.serverName} | Entity: ${f.entity_name || 'N/A'}</div>
        </div>
      `).join('')}
    ` : ''}
    
    ${allFindings.filter(f => f.severity === 'low').length > 0 ? `
      <h3>Low Severity Issues</h3>
      ${allFindings.filter(f => f.severity === 'low').map(f => `
        <div class="finding-card">
          <div class="finding-header">
            <span class="finding-title">${f.detector || f.type || 'Security Issue'}</span>
            <span class="severity-badge severity-low">Low</span>
          </div>
          <div class="finding-details">${f.details || f.message || 'Minor security consideration.'}</div>
          <div class="finding-server">Server: ${f.serverName} | Entity: ${f.entity_name || 'N/A'}</div>
        </div>
      `).join('')}
    ` : ''}
  </div>
  ` : ''}

  ${vulnerableFindings.length > 0 ? `
  <div class="section active-scan-section">
    <h2>Active Scan Vulnerabilities</h2>
    <p style="font-size: 13px; color: #4b5563; margin-bottom: 15px;">
      The following vulnerabilities were discovered through dynamic testing by the Triksha security agent:
    </p>
    ${vulnerableFindings.map(f => {
      // Parse payload for display
      let payloadDisplay = '';
      let payloadPreview = '';
      try {
        const parsed = JSON.parse(f.payload || '{}');
        const value = Object.values(parsed)[0];
        payloadDisplay = typeof value === 'string' ? value : JSON.stringify(parsed, null, 2);
        payloadPreview = typeof value === 'string' ? value.substring(0, 50) : JSON.stringify(parsed).substring(0, 50);
      } catch {
        payloadDisplay = f.payload || 'N/A';
        payloadPreview = (f.payload || '').substring(0, 50);
      }
      
      // Parse response for display
      let responseDisplay = '';
      try {
        const parsed = JSON.parse(f.response || '{}');
        responseDisplay = typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
      } catch {
        responseDisplay = f.response || '';
      }
      
      const severity = (f.severity || 'medium').toLowerCase();
      
      return `
      <div class="vuln-card ${severity}">
        <div class="vuln-header">
          <div class="vuln-icon">⚠️</div>
          <div class="vuln-header-content">
            <div class="vuln-title">${f.vulnerability_type || f.attack_type || 'Vulnerability Detected'}</div>
            <div class="vuln-payload-preview">${payloadPreview}</div>
          </div>
          <div class="vuln-badges">
            <span class="severity-tag ${severity}">${severity.toUpperCase()}</span>
          </div>
        </div>
        <div class="vuln-body">
          <div class="vuln-section">
            <div class="vuln-label">Payload:</div>
            <div class="vuln-box">${payloadDisplay}</div>
          </div>
          ${responseDisplay ? `
          <div class="vuln-section">
            <div class="vuln-label">Response:</div>
            <div class="vuln-box">${responseDisplay.substring(0, 800)}${responseDisplay.length > 800 ? '...' : ''}</div>
          </div>
          ` : ''}
          ${f.details ? `
          <div class="vuln-section">
            <div class="vuln-label">Details:</div>
            <div class="vuln-details">${f.details}</div>
          </div>
          ` : ''}
          ${f.recommendation ? `
          <div class="vuln-section">
            <div class="vuln-label">Recommendation:</div>
            <div class="vuln-recommendation">${f.recommendation}</div>
          </div>
          ` : ''}
        </div>
      </div>
    `}).join('')}
  </div>
  ` : ''}

  <div class="section">
    <h2>Server Inventory</h2>
    ${servers.map(server => `
      <div class="server-section">
        <div class="server-name">${server.server_name || 'MCP Server'}</div>
        <div class="server-url">${server.server_url || ''}</div>
        <div class="server-stats">
          <span>Tools: ${server.tools?.length || 0}</span>
          ${server.prompts?.length > 0 ? `<span>Prompts: ${server.prompts.length}</span>` : ''}
          ${server.resources?.length > 0 ? `<span>Resources: ${server.resources.length}</span>` : ''}
        </div>
        ${server.tools?.length > 0 ? `
          <div class="entity-list">
            <h4 style="font-size: 12px; color: #6b7280; margin-bottom: 8px;">Tools:</h4>
            ${server.tools.slice(0, 5).map(t => `
              <div class="entity-item">
                <div class="entity-name">${t.name}</div>
                ${t.description ? `<div class="entity-desc">${t.description.substring(0, 100)}${t.description.length > 100 ? '...' : ''}</div>` : ''}
              </div>
            `).join('')}
            ${server.tools.length > 5 ? `<div style="font-size: 11px; color: #9ca3af; margin-top: 5px;">+ ${server.tools.length - 5} more tools</div>` : ''}
          </div>
        ` : ''}
      </div>
    `).join('')}
  </div>

  <div class="recommendation-box">
    <h3>Key Recommendations</h3>
    <ul>
      ${highRiskCount > 0 ? '<li>Address all high-severity findings immediately as they may expose critical security risks.</li>' : ''}
      ${mediumRiskCount > 0 ? '<li>Review and remediate medium-severity issues in the next security sprint.</li>' : ''}
      <li>Implement proper input validation for all MCP tools to prevent injection attacks.</li>
      <li>Apply principle of least privilege when configuring tool permissions.</li>
      <li>Regularly audit tool descriptions and capabilities for sensitive information exposure.</li>
      <li>Consider implementing rate limiting and monitoring for tool invocations.</li>
    </ul>
  </div>

  <div class="footer">
    <p>Generated by Triksha - AI Security Platform</p>
    <p>Report generated on ${new Date().toLocaleString()}</p>
  </div>
</body>
</html>`;

    // Open report in new window for printing/saving as PDF
    const reportWindow = window.open('', '_blank');
    reportWindow.document.write(reportHtml);
    reportWindow.document.close();
    
    // Trigger print dialog after content loads
    reportWindow.onload = () => {
      setTimeout(() => {
        reportWindow.print();
      }, 500);
    };
  };
  
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Backdrop */}
        <div className="fixed inset-0 transition-opacity bg-gray-500 dark:bg-gray-900 bg-opacity-75" onClick={onClose} />
        
      {/* Modal - Fixed height for consistency */}
      <div className="relative bg-white dark:bg-gray-800 rounded-lg text-left overflow-hidden shadow-xl w-full max-w-7xl flex flex-col" style={{ height: '90vh', maxHeight: '900px' }}>
          {/* Header */}
          <div className="bg-gradient-to-r from-primary-600 to-primary-700 px-6 py-4 flex-shrink-0">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Shield className="h-6 w-6 text-white" />
                <div>
                  <h3 className="text-lg font-semibold text-white">{scan.scanName || scan.fileName}</h3>
                </div>
              </div>
              <div className="flex items-center space-x-3">
                <button
                  onClick={generateReport}
                  className="inline-flex items-center px-3 py-1.5 bg-white/20 hover:bg-white/30 text-white text-sm rounded-lg transition-colors"
                >
                  <FileCode className="w-4 h-4 mr-2" />
                  Report
                </button>
                <button onClick={onClose} className="text-white hover:text-gray-200">
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>
          </div>
          
          {/* View Toggle */}
          <div className="bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 px-6 py-3 flex-shrink-0">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600 dark:text-gray-400">View:</span>
                <div className="flex bg-gray-200 dark:bg-gray-700 rounded-lg p-1">
                <button
                    onClick={() => {
                      setScanView('passive');
                      // Select first server when switching to passive view
                      if (servers.length > 0) {
                        setSelectedEntity({ type: 'server', data: servers[0], index: 0 });
                      }
                    }}
                    className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
                      scanView === 'passive' 
                        ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow-sm' 
                        : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                    }`}
                >
                    Passive Scan
                </button>
                  <button
                    onClick={() => {
                      setScanView('active');
                      if (activeResults && activeResults.findings && activeResults.findings.length > 0) {
                        // If results already cached, select first tool
                        const toolMap = {};
                        activeResults.findings.forEach(f => {
                          if (!toolMap[f.tool_name]) {
                            toolMap[f.tool_name] = { tests: [], vulnerabilities: 0 };
                          }
                          toolMap[f.tool_name].tests.push(f);
                          if (f.vulnerability_found) {
                            toolMap[f.tool_name].vulnerabilities++;
                          }
                        });
                        const firstTool = Object.keys(toolMap)[0];
                        if (firstTool) {
                          setSelectedEntity({ type: 'active-tool', data: { name: firstTool, ...toolMap[firstTool] } });
                        }
                      } else {
                        fetchActiveResults();
                      }
                    }}
                    className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
                      scanView === 'active' 
                        ? 'bg-white dark:bg-gray-600 text-gray-900 dark:text-white shadow-sm' 
                        : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                    }`}
                  >
                    Active Scan
                  </button>
          </div>
                    </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {scanView === 'passive' ? 'Static analysis results' : 'Active scan results'}
                    </div>
                  </div>
                </div>
                
          {/* Content based on view */}
          {scanView === 'active' ? (
            /* ACTIVE SCAN VIEW - Split Layout with SECBUG sliding panel */
            <div className="flex relative overflow-hidden flex-1">
              {loadingActive ? (
                <div className="flex items-center justify-center w-full">
                  <div className="animate-spin h-8 w-8 border-4 border-primary-500 border-t-transparent rounded-full"></div>
                      </div>
              ) : activeResults && activeResults.findings && activeResults.findings.length > 0 ? (
                <>
                  {/* LEFT Panel - Tools List OR Tool Issues (when SECBUG is open) */}
                  <div 
                    className={`border-r border-gray-200 dark:border-gray-700 overflow-y-auto bg-gray-50 dark:bg-gray-900 transition-all duration-300 ease-in-out ${
                      secbugView ? 'w-3/5' : 'w-2/5'
                    }`}
                  >
                    {secbugView ? (
                      /* Show Tool and its Issues when SECBUG form is open */
                      <div className="p-6">
                        <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                          <Wrench className="h-5 w-5 mr-2 text-primary-600" />
                          {secbugView.toolName}
                        </h4>
                        
                        {/* Issues List for this specific tool */}
                        <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                          Issues ({selectedEntity?.data?.vulnerabilities || 0})
                        </h5>
                        
                        <div className="space-y-3">
                          {selectedEntity?.data?.tests?.filter(f => f.vulnerability_found).map((finding, idx) => (
                            <IssueCard 
                              key={idx} 
                              finding={finding}
                              serverName={scan?.server_name || scan?.data?.servers?.[0]?.server_name || 'Unknown Server'}
                              toolName={selectedEntity.data.name}
                              onRaiseSecbug={handleRaiseSecbug}
                            />
                          ))}
                        </div>
                      </div>
                    ) : (
                      /* Normal Tools List View */
                    <div className="p-6">
                      {/* Summary Stats */}
                      <div className="grid grid-cols-2 gap-3 mb-6">
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 border border-gray-200 dark:border-gray-700 text-center">
                          <div className={`text-xl font-bold ${activeResults.summary.vulnerabilities_found > 0 ? 'text-red-600' : 'text-green-600'}`}>
                            {activeResults.summary.vulnerabilities_found}
                          </div>
                          <div className="text-xs text-gray-500">Issues</div>
                        </div>
                        <div className="bg-white dark:bg-gray-800 rounded-lg p-3 border border-gray-200 dark:border-gray-700 text-center">
                          <div className="text-xl font-bold text-blue-600">{activeResults.summary.tools_tested}</div>
                          <div className="text-xs text-gray-500">Tools</div>
                    </div>
                  </div>
                  
                      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                        <Wrench className="h-4 w-4 mr-2" />
                        Tools Tested
                      </h4>
                      
                      {/* Group findings by tool */}
                      {(() => {
                        const toolMap = {};
                        activeResults.findings.forEach(f => {
                          if (!toolMap[f.tool_name]) {
                            toolMap[f.tool_name] = { tests: [], vulnerabilities: 0 };
                          }
                          toolMap[f.tool_name].tests.push(f);
                          if (f.vulnerability_found) {
                            toolMap[f.tool_name].vulnerabilities++;
                          }
                        });
                        
                        return Object.entries(toolMap).map(([toolName, data]) => (
                          <div 
                            key={toolName}
                            className={`mb-3 bg-white dark:bg-gray-800 border-2 rounded-lg p-3 cursor-pointer transition-all ${
                              selectedEntity?.type === 'active-tool' && selectedEntity?.data?.name === toolName
                                ? 'border-primary-500 shadow-md'
                                : 'border-gray-200 dark:border-gray-700 hover:border-primary-300 hover:shadow-sm'
                            }`}
                            onClick={() => setSelectedEntity({ type: 'active-tool', data: { name: toolName, ...data } })}
                          >
                    <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                <span className="font-medium text-gray-900 dark:text-white">{toolName}</span>
                      </div>
                              <div className="flex items-center space-x-2">
                                <span className="text-xs text-gray-500">{data.tests.length} tests</span>
                                {data.vulnerabilities > 0 && (
                                  <span className="flex items-center space-x-1 px-2 py-0.5 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-full text-xs">
                                    <AlertTriangle className="h-3 w-3" />
                                    <span>{data.vulnerabilities}</span>
                                  </span>
                                )}
                                {data.vulnerabilities === 0 && (
                                  <CheckCircle className="h-4 w-4 text-green-500" />
                                )}
                    </div>
                  </div>
                      </div>
                        ));
                      })()}
                    </div>
                    )}
                  </div>
                  
                  {/* RIGHT Panel - Tool Details OR SECBUG Form (slides in from right) */}
                  <div 
                    className={`overflow-y-auto bg-white dark:bg-gray-800 transition-all duration-300 ease-in-out ${
                      secbugView ? 'w-2/5' : 'w-3/5'
                    }`}
                  >
                    {secbugView ? (
                      /* SECBUG Form - with slide-in animation */
                      <div 
                        className="h-full animate-slide-in-right"
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
                      /* Normal Tool Details View */
                    <div className="p-6">
                      {selectedEntity?.type === 'active-tool' ? (
                      <div>
                          <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                            <Wrench className="h-5 w-5 mr-2 text-primary-600" />
                            {selectedEntity.data.name}
                          </h4>
                          
                          {/* Tool Stats */}
                          <div className="grid grid-cols-2 gap-3 mb-6">
                            <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 border border-gray-200 dark:border-gray-700">
                              <div className="text-lg font-bold text-gray-900 dark:text-white">{selectedEntity.data.tests.length}</div>
                              <div className="text-xs text-gray-500">Testcases Performed</div>
                      </div>
                            <div className={`rounded-lg p-3 border ${
                              selectedEntity.data.vulnerabilities > 0 
                                ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800' 
                                : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                            }`}>
                              <div className={`text-lg font-bold ${selectedEntity.data.vulnerabilities > 0 ? 'text-red-600' : 'text-green-600'}`}>
                                {selectedEntity.data.vulnerabilities}
                    </div>
                              <div className="text-xs text-gray-500">Vulnerabilities</div>
                  </div>
                </div>
                
                          {/* Issues for this tool */}
                          <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
                            Issues ({selectedEntity.data.vulnerabilities})
                          </h5>
                          
                          {selectedEntity.data.vulnerabilities === 0 ? (
                            <div className="text-center py-8 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
                              <CheckCircle className="h-10 w-10 mx-auto mb-3 text-green-500" />
                              <p className="text-green-700 dark:text-green-300 font-medium">No vulnerabilities found</p>
                              <p className="text-sm text-gray-500 mt-1">{selectedEntity.data.tests.length} tests passed</p>
                    </div>
                          ) : (
                            <div className="space-y-3">
                              {selectedEntity.data.tests.filter(f => f.vulnerability_found).map((finding, idx) => (
                                  <IssueCard 
                                    key={idx} 
                                    finding={finding}
                                    serverName={scan?.server_name || scan?.data?.servers?.[0]?.server_name || 'Unknown Server'}
                                    toolName={selectedEntity.data.name}
                                    onRaiseSecbug={handleRaiseSecbug}
                                  />
                              ))}
                      </div>
                )}
                    </div>
                      ) : (
                        <div className="flex flex-col items-center justify-center h-full text-center text-gray-500 dark:text-gray-400">
                          <Wrench className="h-12 w-12 mb-4 opacity-50" />
                          <p>Select a tool from the left to view its test results</p>
                  </div>
                )}
                      </div>
                    )}
                    </div>
                </>
              ) : (() => {
                const st = activeResults?.active_status;
                if (st === 'skipped_no_key') {
                  return (
                    <div className="flex flex-col items-center justify-center w-full text-center p-8">
                      <AlertTriangle className="h-12 w-12 text-amber-500 mb-4" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">LLM API key required</h4>
                      <p className="text-gray-500 dark:text-gray-400 max-w-md">
                        Active security testing is LLM-powered. Add a provider API key in Settings (your name → Settings),
                        then re-run the scan to perform active testing.
                      </p>
                    </div>
                  );
                }
                if (st === 'no_targets') {
                  return (
                    <div className="flex flex-col items-center justify-center w-full text-center p-8">
                      <AlertTriangle className="h-12 w-12 text-gray-400 mb-4" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Nothing to actively test</h4>
                      <p className="text-gray-500 dark:text-gray-400 max-w-md">
                        The MCP server wasn’t reachable or exposed no tools, so there was nothing to actively probe.
                        Check the server URL / connectivity and re-run.
                      </p>
                    </div>
                  );
                }
                if (st === 'done') {
                  return (
                    <div className="flex flex-col items-center justify-center w-full text-center p-8">
                      <CheckCircle className="h-12 w-12 text-green-500 mb-4" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Active testing complete</h4>
                      <p className="text-gray-500 dark:text-gray-400 max-w-md">
                        The autonomous agent probed the tools and found no exploitable issues in this run.
                      </p>
                    </div>
                  );
                }
                if (st === 'running' || !st || st === 'unknown') {
                  // 'unknown' (older scans / brief race) still shows a gentle message;
                  // 'running' shows live progress.
                  return st === 'running' || !st ? (
                    <div className="flex flex-col items-center justify-center w-full text-center p-8">
                      <RefreshCw className="h-10 w-10 text-primary-500 mb-4 animate-spin" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Active testing in progress…</h4>
                      <p className="text-gray-500 dark:text-gray-400 max-w-md">
                        Active security testing runs automatically after the passive scan — the autonomous agent probes each
                        tool over multiple turns, which can take a few minutes. Results appear here automatically.
                      </p>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center w-full text-center p-8">
                      <AlertTriangle className="h-12 w-12 text-gray-400 mb-4" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No active-scan results</h4>
                      <p className="text-gray-500 dark:text-gray-400 max-w-md">
                        This scan has no stored active-test results. Re-run the scan to run active testing
                        (requires an LLM API key in Settings).
                      </p>
                    </div>
                  );
                }
                return (
                  <div className="flex flex-col items-center justify-center w-full text-center p-8">
                    <AlertTriangle className="h-12 w-12 text-gray-400 mb-4" />
                    <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No active-scan results</h4>
                    <p className="text-gray-500 dark:text-gray-400 max-w-md">Re-run the scan to run active testing.</p>
                  </div>
                );
              })()}
                                </div>
          ) : (
          /* PASSIVE SCAN VIEW (existing content) */
          <div className="flex flex-1 overflow-hidden">
            {/* LEFT: Discovery Graph */}
            <div className="w-1/2 border-r border-gray-200 dark:border-gray-700 overflow-y-auto bg-gray-50 dark:bg-gray-900">
              <div className="p-6">
                <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-4 flex items-center">
                  <GitBranch className="h-4 w-4 mr-2" />
                  Discovery Graph
                      </h4>
                
                {servers.map((server, sidx) => {
                  // Calculate unique issue types (not repetitions across tools)
                  const uniqueDetectors = new Set((server.security_findings || []).map(f => f.detector));
                  const uniquePatternIssues = uniqueDetectors.size;
                  const uniqueCapabilityIssues = (server.capability_concerns || []).length;
                  const totalRisks = uniquePatternIssues + uniqueCapabilityIssues;
                  
                          return (
                    <div key={sidx} className="mb-6">
                      {/* Server Node */}
                      <div className="flex items-start mb-3">
                        <div className="flex-shrink-0 mt-1">
                          {server.status === 'success' ? (
                            <CheckCircle className="h-5 w-5 text-green-600" />
                          ) : (
                            <XCircle className="h-5 w-5 text-red-600" />
                              )}
                    </div>
                        <div className="ml-3 flex-1">
                          <div
                            className={`bg-white dark:bg-gray-800 border-2 rounded-lg p-3 shadow-sm cursor-pointer hover:shadow-md transition-all ${
                              server.status !== 'success'
                                ? 'border-red-300 dark:border-red-700 hover:border-red-500'
                                : 'border-gray-300 dark:border-gray-600 hover:border-primary-500'
                            }`}
                            onClick={() => setSelectedEntity({ type: 'server', data: server, index: sidx })}
                          >
                            <div className="flex items-center justify-between">
                            <div className="flex-1">
                                <div className="font-semibold text-gray-900 dark:text-white">{server.server_name}</div>
                                <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                  {server.server_type} • {server.protocol_version || 'unknown protocol'}
                            </div>
                    </div>
                              {totalRisks > 0 && (
                                <div className="flex items-center space-x-1">
                                  <div className={`h-3 w-3 rounded-full ${
                                    totalRisks >= 10 ? 'bg-red-600 animate-pulse' :
                                    totalRisks >= 5 ? 'bg-red-500' :
                                    totalRisks >= 3 ? 'bg-orange-500' :
                                    'bg-yellow-500'
                                  }`} />
                                  <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                                    {totalRisks}
                            </span>
                          </div>
                )}
                        </div>
                            {server.error_message && (
                              <div className="mt-2 flex items-start gap-1.5 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded text-xs text-red-700 dark:text-red-300">
                                <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
                                <span className="font-mono">{server.error_message}</span>
                              </div>
                            )}
                    </div>
                      </div>
                  </div>
                
                    {/* Connection Lines & Child Nodes */}
                    {server.status === 'success' && (
                      <div className="ml-8 pl-4 border-l-2 border-gray-300 dark:border-gray-600 space-y-3">
                        {/* Tools */}
                        {server.tools && server.tools.length > 0 && (
                      <div>
                            <div className="flex items-center text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
                              <Wrench className="h-3 w-3 mr-1" />
                              Tools ({server.tools.length})
                    </div>
                            <div className="space-y-2">
                              {server.tools.map((tool, tidx) => {
                                // Count security findings for this specific tool (pattern-based only)
                                const toolFindings = (server.security_findings || []).filter(f => 
                                  f.entity_name === tool.name && f.entity_type === 'tool'
                                );
                                const toolRiskCount = toolFindings.length;
                      
                      return (
                                  <div key={tidx} className="flex items-start">
                                    <ArrowRight className="h-4 w-4 text-gray-400 mr-2 mt-0.5 flex-shrink-0" />
                                    <div 
                                      className="flex-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded p-2 text-xs cursor-pointer hover:border-primary-500 hover:shadow-sm transition-all"
                                      onClick={() => setSelectedEntity({ type: 'tool', data: tool, server: server.server_name, serverData: server })}
                                    >
                            <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                          <div className="font-medium text-gray-900 dark:text-white">{tool.name}</div>
                                          {toolRiskCount > 0 && (
                                            <div className={`h-2 w-2 rounded-full ${
                                              toolRiskCount >= 3 ? 'bg-red-600 animate-pulse' : 
                                              toolRiskCount >= 2 ? 'bg-orange-500' : 
                                              'bg-yellow-500'
                                            }`} title={`${toolRiskCount} security issue${toolRiskCount > 1 ? 's' : ''}`} />
                                          )}
                            </div>
                          </div>
                                      {tool.description && (
                                        <div className="mt-1">
                                          <SmartDescription text={tool.description} maxLength={80} />
                                </div>
                              )}
                            </div>
                          </div>
                          );
                        })}
                    </div>
                  </div>
                )}
                
                        {/* Prompts */}
                        {server.prompts && server.prompts.length > 0 && (
                      <div>
                            <div className="flex items-center text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
                              <MessageSquare className="h-3 w-3 mr-1" />
                              Prompts ({server.prompts.length})
                  </div>
                            <div className="space-y-2">
                              {server.prompts.map((prompt, pidx) => {
                                // Count security findings for this specific prompt
                                const promptFindings = (server.security_findings || []).filter(f => 
                                  f.entity_name === prompt.name && f.entity_type === 'prompt'
                                );
                                const promptRiskCount = promptFindings.length;
                      
                      return (
                                  <div key={pidx} className="flex items-start">
                                    <ArrowRight className="h-4 w-4 text-gray-400 mr-2 mt-0.5 flex-shrink-0" />
                                    <div 
                                      className="flex-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded p-2 text-xs cursor-pointer hover:border-primary-500 hover:shadow-sm transition-all"
                                      onClick={() => setSelectedEntity({ type: 'prompt', data: prompt, server: server.server_name })}
                          >
                            <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                          <div className="font-medium text-gray-900 dark:text-white">{prompt.name}</div>
                                          {promptRiskCount > 0 && (
                                            <div className={`h-2 w-2 rounded-full ${
                                              promptRiskCount >= 3 ? 'bg-red-600 animate-pulse' : 
                                              promptRiskCount >= 2 ? 'bg-orange-500' : 
                                              'bg-yellow-500'
                                            }`} title={`${promptRiskCount} security issue${promptRiskCount > 1 ? 's' : ''}`} />
                                      )}
                            </div>
                          </div>
                                      {prompt.description && (
                                        <div className="mt-1">
                                          <SmartDescription text={prompt.description} maxLength={80} />
                                      </div>
                          )}
                                            </div>
                        </div>
                      );
                    })}
                  </div>
              </div>
            )}
            
                        {/* Resources */}
                        {server.resources && server.resources.length > 0 && (
                          <div>
                            <div className="flex items-center text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">
                              <FileCode className="h-3 w-3 mr-1" />
                              Resources ({server.resources.length})
                                        </div>
                            <div className="space-y-2">
                              {server.resources.map((resource, ridx) => {
                                // Count security findings for this specific resource
                                const resourceFindings = (server.security_findings || []).filter(f => 
                                  f.entity_name === resource.name && f.entity_type === 'resource'
                                );
                                const resourceRiskCount = resourceFindings.length;
                      
                      return (
                                  <div key={ridx} className="flex items-start">
                                    <ArrowRight className="h-4 w-4 text-gray-400 mr-2 mt-0.5 flex-shrink-0" />
                                    <div 
                                      className="flex-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded p-2 text-xs cursor-pointer hover:border-primary-500 hover:shadow-sm transition-all"
                                      onClick={() => setSelectedEntity({ type: 'resource', data: resource, server: server.server_name })}
                          >
                            <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                                          <div className="font-medium text-gray-900 dark:text-white">{resource.name}</div>
                                          {resourceRiskCount > 0 && (
                                            <div className={`h-2 w-2 rounded-full ${
                                              resourceRiskCount >= 3 ? 'bg-red-600 animate-pulse' : 
                                              resourceRiskCount >= 2 ? 'bg-orange-500' : 
                                              'bg-yellow-500'
                                            }`} title={`${resourceRiskCount} security issue${resourceRiskCount > 1 ? 's' : ''}`} />
                                      )}
                                    </div>
                                  </div>
                                      {resource.description && (
                                        <div className="mt-1">
                                          <SmartDescription text={resource.description} maxLength={80} />
                            </div>
                          )}
                      </div>
                        </div>
                      );
                    })}
                  </div>
              </div>
            )}
                        </div>
                        )}
                      </div>
                      );
                    })}
                  </div>
                    </div>
                    
            {/* RIGHT: Security Analysis */}
            <div className="w-1/2 overflow-y-auto bg-white dark:bg-gray-800">
              <div className="p-6">
                {selectedEntity ? (
                  <>
                    {/* Selected Entity Details */}
                        {selectedEntity.type === 'server' && (
                          <div>
                        <div className="mb-4">
                          <h4 className="text-lg font-semibold text-gray-900 dark:text-white">
                            {selectedEntity.data.server_name}
                          </h4>
                          <p className="text-sm text-gray-500 dark:text-gray-400">
                            MCP Server • {selectedEntity.data.server_type}
                          </p>
                          </div>
                    
                        {/* Server Purpose */}
                        {selectedEntity.data.server_info && (
                          <div className="mb-4 p-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                            <div className="flex items-start space-x-2">
                              <Info className="h-4 w-4 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                          <div>
                                <div className="text-xs font-semibold text-blue-900 dark:text-blue-200 mb-1">Purpose</div>
                                <div className="text-sm text-blue-800 dark:text-blue-300 leading-relaxed">
                                  {selectedEntity.data.server_summary || `${selectedEntity.data.server_info.name || 'MCP Server'} provides ${selectedEntity.data.tools?.length || 0} tools, ${selectedEntity.data.prompts?.length || 0} prompts, and ${selectedEntity.data.resources?.length || 0} resources for AI agents.`}
                          </div>
                          </div>
                          </div>
                        </div>
            )}
            
                    
                        {/* Potential Issues */}
                        <div className="mb-4">
                          {(() => {
                            // Group security findings by detector type
                            const findingsByDetector = {};
                            (selectedEntity.data.security_findings || []).forEach(finding => {
                              const detector = finding.detector;
                              if (!findingsByDetector[detector]) {
                                findingsByDetector[detector] = {
                                  name: detector.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
                                  entities: [],
                                  severity: finding.severity
                                };
                              }
                              if (!findingsByDetector[detector].entities.includes(finding.entity_name)) {
                                findingsByDetector[detector].entities.push(finding.entity_name);
                              }
                            });
                            
                            const detectorEntries = Object.entries(findingsByDetector);
                            const hasCapabilityConcerns = selectedEntity.data.capability_concerns && selectedEntity.data.capability_concerns.length > 0;
                            const hasPatternIssues = detectorEntries.length > 0;
                            const totalIssues = detectorEntries.length + (hasCapabilityConcerns ? selectedEntity.data.capability_concerns.length : 0);
                            
                            if (!hasCapabilityConcerns && !hasPatternIssues) {
                              return (
                                <div className="flex items-center space-x-2 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg">
                                  <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
                                  <span className="text-sm text-green-800 dark:text-green-300">No security issues detected</span>
                          </div>
                              );
                            }
                            
                            return (
                              <CollapsibleSection title={`Potential Issues (${totalIssues})`} defaultOpen={true}>
                            <div className="space-y-2">
                                  {/* Pattern-based findings grouped by type */}
                                  {detectorEntries.map(([detector, info]) => (
                                    <div key={detector} className="p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
                                      <div className="flex items-start space-x-2">
                                        <XCircle className="h-3.5 w-3.5 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0" />
                                    <div className="flex-1">
                                          <div className="text-xs font-semibold text-red-900 dark:text-red-200 mb-1">
                                            {info.name}
                                    </div>
                                          <div className="flex flex-wrap gap-1">
                                            {info.entities.map((entity, idx) => (
                                              <span key={idx} className="text-[10px] bg-red-200 dark:bg-red-900/40 text-red-800 dark:text-red-300 px-1.5 py-0.5 rounded font-medium">
                                                {entity}
                                      </span>
                                            ))}
                                  </div>
                                        </div>
                                      </div>
                                          </div>
                                        ))}
                                  
                                  {/* Capability concerns */}
                                  {hasCapabilityConcerns && selectedEntity.data.capability_concerns.map((concern, idx) => (
                                    <div key={`cap-${idx}`} className="p-2 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded">
                                      <div className="flex items-start space-x-2">
                                        <AlertOctagon className="h-3.5 w-3.5 text-orange-600 dark:text-orange-400 mt-0.5 flex-shrink-0" />
                                        <div className="flex-1">
                                          <div className="text-xs font-semibold text-orange-900 dark:text-orange-200 mb-1">
                                            {concern}
                                      </div>
                                          <div className="text-[10px] text-orange-700 dark:text-orange-400">
                                            Server-level capability risk
                                    </div>
                                        </div>
                                    </div>
                                </div>
                              ))}
                                </div>
                              </CollapsibleSection>
                            );
                          })()}
                        </div>
                        
                        {/* Detected Capabilities */}
                        {selectedEntity.data.detected_capabilities && selectedEntity.data.detected_capabilities.length > 0 && (
                          <div className="mb-4">
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">Detected Capabilities</h5>
                            <div className="flex flex-wrap gap-2">
                              {selectedEntity.data.detected_capabilities.map((cap, idx) => {
                                const isHighRisk = ['code_execution', 'handles_credentials', 'database_access'].includes(cap);
                                const isMediumRisk = ['file_system_access', 'network_access', 'handles_pii'].includes(cap);
                                return (
                                  <span 
                                    key={idx} 
                                    className={`px-2 py-1 rounded text-xs font-medium ${
                                      isHighRisk 
                                        ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' 
                                        : isMediumRisk 
                                        ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300'
                                        : 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                    }`}
                                  >
                                    {cap.replace(/_/g, ' ')}
                                  </span>
                                );
                              })}
                            </div>
                          </div>
                        )}
                        
                        {/* Recommendations */}
                        <div>
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
                            <Shield className="h-4 w-4 mr-2 text-green-600" />
                            Recommendations
                            </h5>
                          <div className="space-y-2 text-sm text-gray-700 dark:text-gray-300">
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600 font-bold">•</span>
                              <span>Implement strict input validation for all tool parameters</span>
                                          </div>
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600 font-bold">•</span>
                              <span>Apply rate limiting to prevent abuse of external service calls</span>
                                      </div>
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600 font-bold">•</span>
                              <span>Monitor and log all tool invocations for audit trails</span>
                                    </div>
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600 font-bold">•</span>
                              <span>Use least-privilege principle for tool permissions</span>
                                </div>
                                    </div>
                            </div>
                          </div>
                        )}
                        
                    {selectedEntity.type === 'tool' && (
                                    <div>
                        <div className="mb-4">
                          <div className="flex items-center space-x-2 text-xs text-gray-500 dark:text-gray-400 mb-2">
                            <Server className="h-3 w-3" />
                            <span>{selectedEntity.server}</span>
                                </div>
                          <h4 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
                            <Wrench className="h-5 w-5 mr-2" />
                            {selectedEntity.data.name}
                          </h4>
                          <div className="mt-3">
                            <FullDescription text={selectedEntity.data.description} />
                                  </div>
                                </div>
                        
                        {/* Input Schema */}
                        {selectedEntity.data.input_schema && (
                          <div className="mb-4">
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Input Parameters</h5>
                            <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <pre className="text-xs text-gray-700 dark:text-gray-300 overflow-x-auto">
                                {JSON.stringify(selectedEntity.data.input_schema.properties || {}, null, 2)}
                              </pre>
                            </div>
                          </div>
                        )}
                        
                        {/* Potential Issues */}
                        <div className="mb-4">
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-3 flex items-center">
                            <AlertTriangle className="h-4 w-4 mr-2 text-orange-600" />
                            Potential Issues
                            </h5>
                          
                          {selectedEntity.serverData?.capability_concerns && selectedEntity.serverData.capability_concerns.length > 0 ? (
                            <div className="space-y-2">
                              {selectedEntity.serverData.capability_concerns.map((concern, idx) => (
                                <div key={idx} className="flex items-start space-x-2 p-2 bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded text-xs">
                                  <span className="text-orange-600">•</span>
                                  <span className="text-orange-900 dark:text-orange-200">{concern}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="flex items-center space-x-2 p-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded text-xs">
                              <CheckCircle className="h-4 w-4 text-green-600" />
                              <span className="text-green-800 dark:text-green-300">No issues detected</span>
                          </div>
                        )}
                        </div>
                        
                        {/* Recommendations */}
                                    <div>
                          <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Recommendations</h5>
                          <div className="space-y-1 text-xs text-gray-700 dark:text-gray-300">
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600">•</span>
                              <span>Validate all input parameters against schema</span>
                                    </div>
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600">•</span>
                              <span>Implement timeout controls for tool execution</span>
                                  </div>
                            <div className="flex items-start space-x-2">
                              <span className="text-green-600">•</span>
                              <span>Log tool invocations with context and results</span>
                                </div>
                            </div>
                          </div>
                      </div>
                    )}
                        
                    {(selectedEntity.type === 'prompt' || selectedEntity.type === 'resource') && (
                      <div>
                        <div className="mb-4">
                          <div className="flex items-center space-x-2 text-xs text-gray-500 dark:text-gray-400 mb-2">
                            <Server className="h-3 w-3" />
                            <span>{selectedEntity.server}</span>
                  </div>
                          <h4 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
                            {selectedEntity.type === 'prompt' ? <MessageSquare className="h-5 w-5 mr-2" /> : <FileCode className="h-5 w-5 mr-2" />}
                            {selectedEntity.data.name}
                          </h4>
                          <div className="mt-3">
                            <FullDescription text={selectedEntity.data.description} />
              </div>
                          {selectedEntity.data.uri && (
                            <p className="text-xs text-gray-500 dark:text-gray-500 mt-2 font-mono">
                              {selectedEntity.data.uri}
                            </p>
                      )}
                  </div>
                        
                        {selectedEntity.data.arguments && (
                          <div className="mb-4">
                            <h5 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">Arguments</h5>
                            <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                              <pre className="text-xs text-gray-700 dark:text-gray-300 overflow-x-auto">
                                {JSON.stringify(selectedEntity.data.arguments, null, 2)}
                              </pre>
                            </div>
                          </div>
                        )}
                          </div>
                        )}
                      </>
                    ) : (
                  <div className="flex items-center justify-center h-full text-center">
                    <div>
                      <GitBranch className="h-12 w-12 text-gray-400 mx-auto mb-3" />
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-1">Select an entity</h4>
                      <p className="text-xs text-gray-500 dark:text-gray-400">
                        Click on a server, tool, prompt, or resource in the discovery graph to view details
                      </p>
                      </div>
                  </div>
                )}
              </div>
          </div>
          </div>
          )}
          
          {/* Footer */}
          <div className="px-6 py-3 bg-gray-50 dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700 flex-shrink-0">
            <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
              <span>Scanned at {new Date(scan.timestamp).toLocaleString()}</span>
              {scan.createdBy && <span>by {scan.createdBy}</span>}
          </div>
        </div>
      </div>
    </div>
  );
};

export default MCPSecurityModal;
