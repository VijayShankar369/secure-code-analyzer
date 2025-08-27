FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy source code
COPY src/ src/
COPY rules/ rules/

# Create non-root user for security
RUN groupadd -r sca && useradd -r -g sca sca
RUN chown -R sca:sca /app
USER sca

# Set environment variables
ENV PYTHONPATH=/app/src
ENV SCA_RULES_DIR=/app/rules

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD sca version || exit 1

# Default command
ENTRYPOINT ["sca"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="Secure Code Analyzer"
LABEL org.opencontainers.image.description="Static security analysis for PHP and JavaScript"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.vendor="Security Team"
LABEL org.opencontainers.image.licenses="MIT"