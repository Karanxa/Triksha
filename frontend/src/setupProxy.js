const { createProxyMiddleware } = require('http-proxy-middleware');

// Dev only: forward /demo/* to the local demo API.
module.exports = function (app) {
  app.use('/demo', createProxyMiddleware({
    target: process.env.REACT_APP_API_URL || 'http://localhost:8001',
    changeOrigin: true,
    pathRewrite: (path) => `/demo${path}`,
    logLevel: 'warn',
  }));
};
