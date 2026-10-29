import React, { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Menu } from 'lucide-react';
import Sidebar from './Sidebar';
import { FULL_BLEED_ROUTES } from '../navConfig';

const Layout = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  // Loading state while validating token
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
        <div className="text-gray-600 dark:text-gray-300">Loading…</div>
      </div>
    );
  }

  // If not authenticated, show login modal only
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 p-4">
        <div className="w-full max-w-md">
          <div className="card">
            <div className="card-header">
              <div className="flex items-center justify-center">
                <div className="h-12 w-12 flex items-center justify-center">
                  <svg className="h-12 w-12" viewBox="0 0 24 24" fill="none">
                    <path d="M12 2L8 4V10C8 14 12 18 12 18S16 14 16 10V4L12 2Z" fill="#2874F0" />
                    <text x="12" y="16" textAnchor="middle" fontSize="7" fill="white" fontWeight="bold" fontFamily="Arial, sans-serif">T</text>
                  </svg>
                </div>
              </div>
              <h3 className="card-title text-center">Welcome to Triksha</h3>
              <p className="card-description text-center">
                Please sign in to access the platform
              </p>
            </div>

            <div className="card-content space-y-4">
              <button
                onClick={() => window.location.href = "/login"}
                className="btn-primary w-full"
              >
                Sign In
              </button>
            </div>

            <div className="card-footer">
              <div className="flex justify-center w-full">
                <p className="text-sm text-gray-600 text-center">Sign in to continue</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const fullBleed = FULL_BLEED_ROUTES.includes(location.pathname);

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 dark:bg-gray-900">
      <Sidebar mobileOpen={mobileOpen} onCloseMobile={() => setMobileOpen(false)} />

      <div className="flex flex-1 flex-col min-w-0">
        {/* Mobile top bar (hamburger) — sidebar is the primary nav on desktop */}
        <div className="md:hidden sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 px-4">
          <button
            onClick={() => setMobileOpen(true)}
            className="p-2 -ml-2 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="text-lg font-bold text-blue-600 dark:text-blue-400">Triksha</span>
        </div>

        {/* Page content */}
        <main className="flex flex-1 flex-col overflow-hidden">
          {fullBleed ? (
            <div className="flex-1 min-h-0">{children}</div>
          ) : (
            <div className="flex-1 overflow-y-auto">
              <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">{children}</div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Layout;
