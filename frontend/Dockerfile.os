# Triksha frontend image — ships the OSS nginx config (proxies API paths
# to the `api` service).
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
COPY .npmrc ./
# npm install (not ci) — lockfile may reconcile on first OSS build.
RUN npm install --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.os.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:80/health || exit 1
CMD ["nginx", "-g", "daemon off;"]
