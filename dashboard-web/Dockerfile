# Multi-stage Dockerfile for Dashboard
# Stage 1: Build React frontend
FROM node:20-alpine as frontend-build

WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --legacy-peer-deps || npm install --legacy-peer-deps

# Copy source code
COPY . .

# Set API URL to relative path (works when served from same origin)
ENV VITE_API_URL=/api

# Build frontend (use docker-specific build without TypeScript checking)
RUN npm run build:docker

# Stage 2: API and serve frontend with nginx
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install nginx and curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy API requirements and install
COPY api/requirements.txt ./api/
RUN pip install --no-cache-dir -r api/requirements.txt

# Copy API code
COPY api/ ./api/

# Copy built frontend from previous stage
COPY --from=frontend-build /app/dist /var/www/html

# Create nginx configuration
RUN echo 'server {\n\
    listen 3000;\n\
    server_name _;\n\
    root /var/www/html;\n\
    index index.html;\n\
\n\
    # Frontend - serve React app\n\
    location / {\n\
        try_files $uri $uri/ /index.html;\n\
    }\n\
\n\
    # API - proxy to FastAPI backend\n\
    location /api/ {\n\
        proxy_pass http://127.0.0.1:8000;\n\
        proxy_http_version 1.1;\n\
        proxy_set_header Upgrade $http_upgrade;\n\
        proxy_set_header Connection "upgrade";\n\
        proxy_set_header Host $host;\n\
        proxy_set_header X-Real-IP $remote_addr;\n\
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
        proxy_set_header X-Forwarded-Proto $scheme;\n\
    }\n\
}\n\
' > /etc/nginx/sites-available/default

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
echo "Starting RAG Wazuh Dashboard..."\n\
\n\
# Start API server in background\n\
echo "Starting API server on port 8000..."\n\
cd /app/api && python main.py &\n\
API_PID=$!\n\
\n\
# Wait for API to be ready\n\
sleep 3\n\
\n\
# Start nginx\n\
echo "Starting nginx on port 3000..."\n\
nginx -g "daemon off;" &\n\
NGINX_PID=$!\n\
\n\
echo "Dashboard started successfully!"\n\
echo "  - Dashboard (with API proxy): http://localhost:3000"\n\
echo "  - API direct access: http://localhost:8000"\n\
\n\
# Wait for any process to exit\n\
wait -n\n\
\n\
# Exit with status of process that exited first\n\
exit $?\n\
' > /app/start.sh && chmod +x /app/start.sh

EXPOSE 3000 8000

CMD ["/app/start.sh"]
