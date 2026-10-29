import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Shield } from 'lucide-react';
import TrikshaAnimation from '../components/TrikshaAnimation';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tokenExpiry, setTokenExpiry] = useState(null);
  const [showExpiryModal, setShowExpiryModal] = useState(false);
  const [showTrikshaAnimation, setShowTrikshaAnimation] = useState(false);
  const [timeUntilExpiry, setTimeUntilExpiry] = useState(null);

  // Preloaded data state - loaded in background when user authenticates
  const [preloadedData, setPreloadedData] = useState({
    modelScans: null,
    mcpScans: null,
    datasetAnalyses: null,
    isLoading: false,
    isLoaded: false,
  });

  // Token expiry check with 5-minute buffer
  const isTokenExpired = useCallback(() => {
    if (!tokenExpiry) return false;
    const now = Date.now();
    const fiveMinutesInMs = 5 * 60 * 1000; // 5 minutes in milliseconds
    return tokenExpiry <= (now + fiveMinutesInMs);
  }, [tokenExpiry]);

  // Extract expiration time from JWT token
  const extractTokenExpiry = useCallback((token) => {
    try {
      if (!token) return null;
      const payload = JSON.parse(atob(token.split('.')[1]));
      return payload.exp ? payload.exp * 1000 : null; // Convert to milliseconds
    } catch (error) {
      console.error('Failed to parse JWT token:', error);
      return null;
    }
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      console.log('[AuthContext] Checking local session...');
      const res = await fetch('/auth/me', {
        credentials: 'include',
        headers: { 'Accept': 'application/json' },
      });
      if (res.status === 401) {
        setIsAuthenticated(false);
        setUser(null);
        return;
      }
      if (!res.ok) {
        throw new Error(`status ${res.status}`);
      }
      const info = await res.json();
      console.log('[AuthContext] Session info:', info);
      
      // token_exp provided by proxy (epoch seconds). If not, fall back to client-side parse if a raw token is ever returned in future.
      if (info?.token_exp) {
        const expiry = Number(info.token_exp) * 1000;
        setTokenExpiry(expiry);
        
        // Check if token is expired or will expire within 5 minutes
        if (expiry && expiry <= (Date.now() + 5 * 60 * 1000)) {
          console.log('[AuthContext] Token expired or expiring soon, expiry:', new Date(expiry), 'now:', new Date());
          setIsAuthenticated(false);
          setUser(null);
          setShowExpiryModal(true);
          return;
        }
      }
      
      const newAuthenticated = Boolean(info?.user);
      console.log('[AuthContext] Setting authenticated state:', newAuthenticated, 'User:', info?.user);
      setIsAuthenticated(newAuthenticated);
      setUser(info?.user || null);
      
      // Show animation when user first authenticates
      if (newAuthenticated) {
        setShowTrikshaAnimation(true);
      }
    } catch (error) {
      console.log('[AuthContext] Session check error:', error);
      setIsAuthenticated(false);
      setUser(null);
      setTokenExpiry(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  // Preload all data in background when user authenticates
  useEffect(() => {
    if (!isAuthenticated || !user) return;
    if (preloadedData.isLoaded || preloadedData.isLoading) return; // Already loaded or loading

    const preloadData = async () => {
      console.log('[AuthContext] Starting background data preload...');
      setPreloadedData(prev => ({ ...prev, isLoading: true }));
      
      const fetchWithTimeout = async (url, timeout = 10000) => {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        try {
          const res = await fetch(url, {
            credentials: 'include',
            headers: {
              'Accept': 'application/json',
              'Content-Type': 'application/json'
            },
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (res.ok) {
            return await res.json();
          }
          return null;
        } catch (error) {
          clearTimeout(timeoutId);
          console.warn(`[Preload] Error fetching ${url}:`, error.message);
          return null;
        }
      };

      // Fetch all data in parallel
      const [modelScans, mcpScans, datasetAnalyses] = await Promise.all([
        fetchWithTimeout('/scans'),
        fetchWithTimeout('/mcp/scans?limit=50'),
        fetchWithTimeout('/dataset/analyses?limit=50'),
      ]);

      console.log('[AuthContext] Background data preload complete:', {
        modelScans: modelScans ? '✓' : '✗',
        mcpScans: mcpScans ? '✓' : '✗',
        datasetAnalyses: datasetAnalyses ? '✓' : '✗',
      });

      setPreloadedData({
        modelScans: modelScans?.scans || [],
        mcpScans: mcpScans?.scans || [],
        datasetAnalyses: datasetAnalyses?.analyses || [],
        isLoading: false,
        isLoaded: true,
      });
    };

    // Run preload in background after a small delay to not block initial render
    const timeoutId = setTimeout(preloadData, 300);
    
    return () => clearTimeout(timeoutId);
  }, [isAuthenticated, user, preloadedData.isLoaded, preloadedData.isLoading]);

  // Periodic token validation with 5-minute buffer
  useEffect(() => {
    if (!isAuthenticated || !tokenExpiry) return;
    
    const checkTokenExpiry = () => {
      const now = Date.now();
      const timeLeft = tokenExpiry - now;
      
      // Update countdown timer
      setTimeUntilExpiry(timeLeft);
      
      if (isTokenExpired()) {
        console.log('[AuthContext] Token expired during periodic check');
        setIsAuthenticated(false);
        setUser(null);
        setShowExpiryModal(true);
      }
    };
    
    // Check every 30 seconds for more accurate countdown
    const interval = setInterval(checkTokenExpiry, 30 * 1000);
    
    // Also check immediately
    checkTokenExpiry();
    
    return () => clearInterval(interval);
  }, [isAuthenticated, tokenExpiry, isTokenExpired]);

  const login = useCallback(async (username, password) => {
    const res = await fetch('/auth/login', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed');
    }
    await refreshSession();
    return true;
  }, [refreshSession]);

  const signup = useCallback(async (username, password) => {
    const res = await fetch('/auth/signup', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Sign up failed');
    }
    await refreshSession();
    return true;
  }, [refreshSession]);

  const logout = useCallback(async () => {
    try {
      await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    } catch (_) { /* ignore */ }
    setIsAuthenticated(false);
    setUser(null);
    window.location.href = '/';
  }, []);

  const checkSetupStatus = useCallback(async () => {
    try {
      const res = await fetch('/setup/status', { credentials: 'include' });
      if (!res.ok) return false;
      const data = await res.json();
      return Boolean(data.needs_setup);
    } catch (_) { return false; }
  }, []);

  const completeSetup = useCallback(async (payload) => {
    const res = await fetch('/setup', {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Setup failed');
    }
    return true;
  }, []);

  const handleTokenExpiry = useCallback(() => {
    setShowExpiryModal(false);
    login();
  }, [login]);

  const handleTrikshaAnimationComplete = useCallback(() => {
    setShowTrikshaAnimation(false);
  }, []);


  const isAdmin = isAuthenticated;
  const canViewAllScans = isAuthenticated;
  const hasPermission = useCallback(() => isAuthenticated, [isAuthenticated]);
  const canAccessScan = useCallback(() => true, []);

  const value = {
    isAuthenticated,
    user,
    loading,
    login,
    signup,
    logout,
    refreshSession,
    checkSetupStatus,
    completeSetup,
    isTokenExpired,
    showExpiryModal,
    handleTokenExpiry,
    isAdmin,
    canViewAllScans,
    hasPermission,
    canAccessScan,
    preloadedData,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
      
      {/* Triksha Animation */}
      {showTrikshaAnimation && (
        <TrikshaAnimation onComplete={handleTrikshaAnimationComplete} />
      )}
      
      {/* Token Expiry Modal */}
      {showExpiryModal && (
        <div className="fixed inset-0 bg-black bg-opacity-20 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md mx-4 shadow-2xl border border-gray-200">
            <div className="flex items-center mb-4">
              <Shield className="h-8 w-8 text-red-500 mr-3" />
              <h3 className="text-lg font-semibold text-gray-900">Session Expired</h3>
            </div>
            <p className="text-gray-600 mb-4">
              Please sign in again to continue using the application without interruption.
            </p>
            {timeUntilExpiry && (
              <div className="bg-yellow-50 border border-yellow-200 rounded-md p-3 mb-6">
                <p className="text-sm text-yellow-800">
                  <strong>Time remaining:</strong> {Math.max(0, Math.floor(timeUntilExpiry / 1000 / 60))} minutes {Math.max(0, Math.floor((timeUntilExpiry / 1000) % 60))} seconds
                </p>
              </div>
            )}
            <div className="flex justify-end space-x-3">
              <button
                onClick={handleTokenExpiry}
                className="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 transition-colors"
              >
                Sign In Again
              </button>
            </div>
          </div>
        </div>
      )}
    </AuthContext.Provider>
  );
};

export const createApiClient = () => {
  // Use relative base URL so requests go through CRA dev server proxy/middleware
  const baseURL = '';
  const handleAuthExpiry = (status) => {
    // Handle auth errors by showing expiry modal
    if (status === 401 || status === 403) {
      console.log('[AuthContext] Auth error detected, status:', status);
      // Don't redirect immediately, let the AuthContext handle it
      // The periodic check will catch this and show the modal
      return true;
    }
    return false;
  };
  
  const client = {
    get: async (endpoint, options = {}) => {
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        credentials: 'include',
        ...options,
      });
      
      if (!response.ok) {
        if (handleAuthExpiry(response.status)) {
          throw new Error('Unauthorized');
        }
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      return response.json();
    },

    post: async (endpoint, data = {}, options = {}) => {
      // Special handling for FormData (file uploads)
      const isFormData = data instanceof FormData;
      
      // Avoid double-encoding: if caller passed a JSON string, do not stringify again
      const bodyPayload = isFormData ? data : (typeof data === 'string' ? data : JSON.stringify(data));
      
      // Don't set Content-Type for FormData - let browser set it with boundary
      const headers = isFormData ? {} : { 'Content-Type': 'application/json' };
      
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: 'POST',
        headers: {
          ...headers,
          ...options.headers,
        },
        body: bodyPayload,
        credentials: 'include',
        ...options,
      });
      
      if (!response.ok) {
        if (handleAuthExpiry(response.status)) {
          throw new Error('Unauthorized');
        }
        
        // Try to extract detailed error message from response
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorData = null;
        
        try {
          errorData = await response.json();
          errorMessage = errorData.detail || errorData.message || errorMessage;
        } catch (jsonError) {
          // If JSON parsing fails, use default message
          console.warn('[API] Could not parse error response as JSON');
        }
        
        const error = new Error(errorMessage);
        error.status = response.status;
        error.response = { status: response.status, data: errorData || { detail: errorMessage } };
        throw error;
      }
      
      return response.json();
    },

    put: async (endpoint, data = {}, options = {}) => {
      const bodyPayload = typeof data === 'string' ? data : JSON.stringify(data);
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        body: bodyPayload,
        credentials: 'include',
        ...options,
      });
      
      if (!response.ok) {
        if (handleAuthExpiry(response.status)) {
          throw new Error('Unauthorized');
        }
        
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorData = null;
        try {
          errorData = await response.json();
          errorMessage = errorData.detail || errorData.message || errorMessage;
        } catch (jsonError) {
          console.warn('[API] Could not parse error response as JSON');
        }
        
        const error = new Error(errorMessage);
        error.status = response.status;
        error.response = { status: response.status, data: errorData || { detail: errorMessage } };
        throw error;
      }
      
      return response.json();
    },

    delete: async (endpoint, options = {}) => {
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        credentials: 'include',
        ...options,
      });
      
      if (!response.ok) {
        if (handleAuthExpiry(response.status)) {
          throw new Error('Unauthorized');
        }
        
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorData = null;
        try {
          errorData = await response.json();
          errorMessage = errorData.detail || errorData.message || errorMessage;
        } catch (jsonError) {
          console.warn('[API] Could not parse error response as JSON');
        }
        
        const error = new Error(errorMessage);
        error.status = response.status;
        error.response = { status: response.status, data: errorData || { detail: errorMessage } };
        throw error;
      }
      
      return response.json();
    },

    patch: async (endpoint, data = {}, options = {}) => {
      const bodyPayload = typeof data === 'string' ? data : JSON.stringify(data);
      const response = await fetch(`${baseURL}${endpoint}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        body: bodyPayload,
        credentials: 'include',
        ...options,
      });
      
      if (!response.ok) {
        if (handleAuthExpiry(response.status)) {
          throw new Error('Unauthorized');
        }
        
        let errorMessage = `HTTP error! status: ${response.status}`;
        let errorData = null;
        try {
          errorData = await response.json();
          errorMessage = errorData.detail || errorData.message || errorMessage;
        } catch (jsonError) {
          console.warn('[API] Could not parse error response as JSON');
        }
        
        const error = new Error(errorMessage);
        error.status = response.status;
        error.response = { status: response.status, data: errorData || { detail: errorMessage } };
        throw error;
      }
      
      return response.json();
    },
  };

  return client;
};
