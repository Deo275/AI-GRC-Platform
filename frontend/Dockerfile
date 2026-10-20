# =============================================================================
# Stage 14B: AI-GRC Platform Frontend Production Dockerfile
# =============================================================================

# Stage 1: Build production static bundle
FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build-time API base URL for client-side browser requests
# Browser requests originate from the host browser, reaching backend on host port
ARG VITE_API_BASE_URL=http://localhost:8000
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL

ARG VITE_IS_DOCKER=true
ENV VITE_IS_DOCKER=$VITE_IS_DOCKER

RUN npm run build

# Stage 2: Production static web server (Nginx)
FROM nginx:alpine

# Copy built static assets
COPY --from=build /app/dist /usr/share/nginx/html

# SPA fallback configuration for client-side routing
RUN printf 'server {\n    listen 80;\n    server_name _;\n    root /usr/share/nginx/html;\n    index index.html;\n    location / {\n        try_files $uri $uri/ /index.html;\n    }\n}\n' > /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
