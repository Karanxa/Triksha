require('events').EventEmitter.defaultMaxListeners = 30;

const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function (app) {
  const targetApi = process.env.REACT_APP_API_URL || 'http://localhost:8000';

  const apiPaths = ['/scan', '/scans', '/models', '/templates', '/auth', '/health', '/dataset', '/generate-system-prompt', '/harden-system-prompt', '/harden/', '/skills/harden', '/mcp', '/swagger', '/triksha', '/manual-test', '/jira', '/sandbox', '/agents', '/security-review', '/dashboard', '/connectors', '/copilot', '/setup', '/redoc'];
  const streamingPaths = ['/scan', '/mcp', '/agents'];

  apiPaths.forEach((p) => {
    const contextFunction = (pathname, req) => {
      if (!pathname.startsWith(p)) {
        return false;
      }

      const acceptHeader = req.headers.accept || '';
      const isHtmlRequest = acceptHeader.includes('text/html');
      const isDocPath = pathname.startsWith('/swagger') || pathname.startsWith('/redoc');

      if (isHtmlRequest && !isDocPath) {
        return false;
      }

      return true;
    };

    app.use(createProxyMiddleware(contextFunction, {
      target: targetApi,
      changeOrigin: true,
      ws: streamingPaths.includes(p),
      logLevel: 'warn',
      onError: (err, req, res) => {
        console.error(`[PROXY ERROR] ${req.method} ${req.url}:`, err.message);
        if (res && typeof res.status === 'function') {
          res.status(500).json({ error: 'Proxy error', details: err.message });
        } else if (res && res.end) {
          res.end();
        }
      }
    }));
  });
};
