import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';
import Layout from './components/Layout';
import Scan from './pages/Scan';
import MCPScanner from './pages/MCPScanner';
import Dataset from './pages/Dataset';
import Home from './pages/Home';
import Agents from './pages/Agents';
import { Navigate } from 'react-router-dom';
import Sandbox from './pages/Sandbox';
import Connectors from './pages/Connectors';
import PRDReviewer from './pages/PRDReviewer';
import PromptHardener from './pages/PromptHardener';
import SkillHardener from './pages/SkillHardener';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { CopilotNavProvider } from './contexts/CopilotNavContext';
import AuthGate from './pages/AuthGate';
import Settings from './pages/Settings';
import { ThemeProvider } from './contexts/ThemeContext';
import Demo from './pages/Demo';
import './index.css';

// Create a client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// authenticated we render the setup/login screen instead of the Layout+Routes.
function GatedApp() {
  const { isAuthenticated, loading } = useAuth();
  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center',
        justifyContent: 'center', background: '#0f172a', color: '#94a3b8' }}>
        Loading…
      </div>
    );
  }
  if (!isAuthenticated) {
    return <AuthGate />;
  }
  return (
    <Layout>
      <Routes>
                <Route path="/" element={<Home />} />
                <Route path="/scan" element={<Scan />} />
                <Route path="/models" element={<Scan />} />
                <Route path="/datasets" element={<Dataset />} />
                <Route path="/agents" element={<Agents />} />
                <Route path="/mcps" element={<MCPScanner />} />
                <Route path="/prd" element={<PRDReviewer />} />
                <Route path="/sandbox" element={<Sandbox />} />
                <Route path="/connectors" element={<Connectors />} />
                <Route path="/settings" element={<Settings />} />
                {/* Legacy redirects */}
                <Route path="/utils/prd-reviewer" element={<Navigate to="/prd" replace />} />
                <Route path="/reviews" element={<Navigate to="/prd" replace />} />
                <Route path="/utils" element={<Navigate to="/" replace />} />
                <Route path="/harden" element={<PromptHardener />} />
                <Route path="/skills-harden" element={<SkillHardener />} />
                <Route path="/utils/prompt-hardener" element={<Navigate to="/harden" replace />} />

              </Routes>
    </Layout>
  );
}

function App() {
  if (process.env.REACT_APP_DEMO_MODE === 'true') {
    return (
      <Router>
        <Demo />
        <Toaster position="top-center" />
      </Router>
    );
  }
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <CopilotNavProvider>
          <Router>
            <div className="App">
              <GatedApp />
            <Toaster
              position="top-left"
              toastOptions={{
                duration: 4000,
                style: {
                  background: '#363636',
                  color: '#fff',
                },
                success: {
                  duration: 3000,
                  iconTheme: {
                    primary: '#22c55e',
                    secondary: '#fff',
                  },
                },
                error: {
                  duration: 5000,
                  iconTheme: {
                    primary: '#ef4444',
                    secondary: '#fff',
                  },
                },
              }}
            />
          </div>
        </Router>
          </CopilotNavProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
