# Thirsty-Lang Docker Guide

The image is published to two public registries (multi-arch: `linux/amd64` +
`linux/arm64`):

- **Docker Hub:** `thirstyoftp/thirsty-lang`
- **GHCR:** `ghcr.io/tp-iamsothirsty/thirsty-lang`

Use whichever you prefer; the examples below use GHCR.

## Quick Start

### Run the Demo

```bash
# Docker Hub
docker run --rm thirstyoftp/thirsty-lang:latest run --demo
# …or GHCR
docker run --rm ghcr.io/tp-iamsothirsty/thirsty-lang:latest run --demo
```

### Interactive REPL

```bash
docker run -it --rm ghcr.io/tp-iamsothirsty/thirsty-lang:latest repl
```

### Run a Script

```bash
docker run --rm -v $(pwd):/scripts ghcr.io/tp-iamsothirsty/thirsty-lang:latest run /scripts/myfile.thirsty
```

---

## Local Development

### Build Locally

```bash
docker build -t thirsty-lang:dev .
```

### Run Full Test Suite

```bash
docker compose run --rm test
```

### Development Shell (with hot-reload)

```bash
docker compose run --rm dev
```

Changes in `./src` are immediately reflected in the container.

### Format Code

```bash
docker compose run --rm fmt
```

### Project Health Check

```bash
docker compose run --rm doctor
```

---

## Docker Compose Services

**docker-compose.yml** includes:

- **`thirsty`** — Runtime container for executing .thirsty files
- **`dev`** — Development environment with hot-reload mounted volumes
- **`test`** — Full test suite runner (1212 tests)
- **`repl`** — Interactive REPL
- **`lsp`** — Language Server Protocol server (port 9898)
- **`build-js`** — Compile to JavaScript
- **`fmt`** — Code formatter
- **`doctor`** — Project health check

Run any service:

```bash
docker compose run --rm <service>
```

---

## Publishing Releases

### Automatic: GitHub Actions

On every tag push, GitHub Actions automatically:

1. ✓ Builds the Docker image
2. ✓ Runs all 1212 tests *inside* the build
3. ✓ Pushes to GitHub Container Registry (GHCR)

**Trigger a release:**

```bash
git tag v0.9.0
git push tp v0.9.0
```

The image will be available at:
```
ghcr.io/tp-iamsothirsty/thirsty-lang:0.9.0
ghcr.io/tp-iamsothirsty/thirsty-lang:latest
```

### Manual Build & Push

```bash
# Build locally
docker build -t thirsty-lang:0.9.0 .

# Tag for registry
docker tag thirsty-lang:0.9.0 ghcr.io/tp-iamsothirsty/thirsty-lang:0.9.0
docker tag thirsty-lang:0.9.0 ghcr.io/tp-iamsothirsty/thirsty-lang:latest

# Log in (first time only)
docker login ghcr.io

# Push
docker push ghcr.io/tp-iamsothirsty/thirsty-lang:0.9.0
docker push ghcr.io/tp-iamsothirsty/thirsty-lang:latest
```

---

## Image Details

**Base:** `python:3.11-slim`  
**Size:** 255MB (production runtime)  
**User:** Non-root (`thirsty:1000`)  
**Entrypoint:** `thirsty` CLI  

All 7 CLI commands included:
- `thirsty` — Execute .thirsty files
- `thirst-of-gods` — Divine contract validation
- `tarl` — Policy-as-code engine
- `tscg` — Symbolic constraint grammar
- `tscg-b` — Binary frame protocol
- `shadow-thirst` — Mutation analysis
- `tarl-lsp` — Language Server Protocol

---

## CLI Helpers

### macOS/Linux

```bash
bash docker-quick.sh build        # Build image
bash docker-quick.sh run --demo   # Run demo
bash docker-quick.sh repl         # Start REPL
bash docker-quick.sh test         # Run tests
bash docker-quick.sh dev          # Dev shell
bash docker-quick.sh fmt          # Format code
bash docker-quick.sh doctor       # Health check
bash docker-quick.sh version      # Show version
bash docker-quick.sh clean        # Clean up
```

### Windows

```bash
docker-quick.bat build            # Build image
docker-quick.bat run --demo       # Run demo
docker-quick.bat repl             # Start REPL
docker-quick.bat test             # Run tests
docker-quick.bat dev              # Dev shell
docker-quick.bat fmt              # Format code
docker-quick.bat doctor           # Health check
docker-quick.bat version          # Show version
docker-quick.bat clean            # Clean up
```

---

## Governance & Security Features

The Docker image preserves all 6 tiers of Thirsty-Lang:

1. **Core Language** — Full lexer, parser, type checker, interpreter
2. **Thirst of Gods** — Divine contract validation for OOP/async/error handling
3. **T.A.R.L.** — Policy-as-code engine with ALLOW/DENY/ESCALATE verdicts
4. **Shadow Thirst** — Mutation analysis with 6 analyzers (determinism, plane isolation, etc.)
5. **TSCG** — Symbolic constraint grammar with SHA-256 canonicalization
6. **TSCG-B** — Binary frame protocol with CRC32 + SHA-256 integrity

Run with governance flags:

```bash
docker run --rm -v $(pwd):/app \
  ghcr.io/tp-iamsothirsty/thirsty-lang:latest \
  run /app/program.thirsty \
  --thirst-level governed \
  --policy /app/policy.tarl \
  --authority myapp
```

---

## Troubleshooting

### "Image not found" error

Ensure you're pulling from GHCR:

```bash
docker pull ghcr.io/tp-iamsothirsty/thirsty-lang:latest
```

### Tests fail during build

The Dockerfile includes a test gate: if any test fails, the build fails. This is intentional — only working images ship.

### Permission denied on volumes

The container runs as non-root user `thirsty:1000`. Mount volumes with proper permissions:

```bash
docker run --rm -v $(pwd)/src:/app/src:rw ghcr.io/tp-iamsothirsty/thirsty-lang:latest fmt
```

---

## Next Steps

- **Publish to Docker Hub** — Make it available via `docker pull thirsty-lang:latest`
- **Multi-arch builds** — Add `linux/arm64` support for M1/M2 Macs
- **Alpine base** — Reduce image size to ~150MB with `python:3.11-alpine`
- **CI/CD integration** — Pre-built images in your deployment pipeline
