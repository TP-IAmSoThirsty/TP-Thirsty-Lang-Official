# Multi-stage Dockerfile for Thirsty-Lang
# Stage 1: Test & Build
FROM python:3.11-slim as builder

WORKDIR /build

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install in development mode with test dependencies
RUN pip install --no-cache-dir -e ".[test]"

# Run full test suite - only proceed to next stage if all tests pass
RUN pytest tests/ -q --tb=short && echo "✓ All 1212 tests passed"

# Build distribution
RUN python -m pip install --no-cache-dir build && \
    python -m build && \
    echo "✓ Build distribution created"


# Stage 2: Runtime Image
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (runtime only - minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libffi8 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 thirsty && \
    mkdir -p /app && \
    chown -R thirsty:thirsty /app

# Copy built distribution from builder
COPY --from=builder /build/dist /tmp/dist

# Install thirsty-lang from built wheel
RUN pip install --no-cache-dir /tmp/dist/*.whl && \
    rm -rf /tmp/dist

# Copy project source for reference/examples
COPY --chown=thirsty:thirsty src /app/src
COPY --chown=thirsty:thirsty docs /app/docs
COPY --chown=thirsty:thirsty README.md /app/README.md

# Switch to non-root user
USER thirsty

# Set up environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/thirsty/.local/bin:$PATH"

# Default command: show version and available commands
ENTRYPOINT ["thirsty"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="Thirsty-Lang" \
      org.opencontainers.image.description="A governance-first programming language family" \
      org.opencontainers.image.version="0.8.2" \
      org.opencontainers.image.source="https://github.com/TP-IAmSoThirsty/TP-Thirsty-Lang-Official"
