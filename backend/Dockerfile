# =============================================================================
# Stage 14B: AI-GRC Platform Backend Dockerfile
# =============================================================================
FROM python:3.11-slim

# Prevent Python from buffering stdout/stderr and writing bytecode
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app/backend:/app

WORKDIR /app

# Install system dependencies
# Nmap is required by the continuous network scanner
# libcap2-bin provides setcap so unprivileged appuser can use raw socket capabilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create unprivileged user (uid 1000) for least-privilege runtime security
RUN useradd -m -u 1000 -s /bin/bash appuser

# Copy application, scanner, and management scripts source code
COPY backend/ ./backend/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/

# Grant Nmap raw socket capabilities for unprivileged execution
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

# Set ownership to unprivileged user
RUN chown -R appuser:appuser /app

# Switch to unprivileged user
USER appuser

WORKDIR /app/backend

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
