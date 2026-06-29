#!/bin/bash
# Thirsty-Lang Docker quick-start
# Usage: bash docker-quick.sh [command]

set -e

COMMAND="${1:-help}"
IMAGE_NAME="thirsty-lang:0.8.0"
PROJECT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$COMMAND" in
  build)
    echo "🏗️  Building Thirsty-Lang Docker image..."
    docker build -t "$IMAGE_NAME" -f Dockerfile "$PROJECT_PATH"
    echo "✓ Image built: $IMAGE_NAME"
    ;;

  run)
    echo "▶️  Running Thirsty-Lang..."
    SCRIPT="${2:---demo}"
    docker run --rm "$IMAGE_NAME" run "$SCRIPT"
    ;;

  repl)
    echo "💬 Starting Thirsty-Lang REPL..."
    docker run -it --rm "$IMAGE_NAME" repl
    ;;

  test)
    echo "🧪 Running full test suite..."
    docker compose -f "$PROJECT_PATH/docker-compose.yml" run --rm test
    ;;

  dev)
    echo "🔧 Starting development environment..."
    docker compose -f "$PROJECT_PATH/docker-compose.yml" run --rm dev
    ;;

  fmt)
    echo "✨ Formatting source files..."
    docker compose -f "$PROJECT_PATH/docker-compose.yml" run --rm fmt
    ;;

  doctor)
    echo "🏥 Running project health check..."
    docker compose -f "$PROJECT_PATH/docker-compose.yml" run --rm doctor
    ;;

  version)
    echo "📦 Checking version..."
    docker run --rm "$IMAGE_NAME" --version
    ;;

  clean)
    echo "🧹 Cleaning up containers and images..."
    docker compose -f "$PROJECT_PATH/docker-compose.yml" down -v
    docker rmi "$IMAGE_NAME" 2>/dev/null || true
    echo "✓ Cleanup complete"
    ;;

  help|*)
    echo "🌊 Thirsty-Lang Docker CLI"
    echo ""
    echo "Usage: bash docker-quick.sh [command] [args...]"
    echo ""
    echo "Commands:"
    echo "  build           Build Docker image"
    echo "  run [script]    Run a .thirsty script (default: --demo)"
    echo "  repl            Start interactive REPL"
    echo "  test            Run full test suite"
    echo "  dev             Start development shell"
    echo "  fmt             Format source files"
    echo "  doctor          Project health check"
    echo "  version         Show Thirsty-Lang version"
    echo "  clean           Clean up containers/images"
    echo "  help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  bash docker-quick.sh build"
    echo "  bash docker-quick.sh run --demo"
    echo "  bash docker-quick.sh repl"
    echo "  bash docker-quick.sh test"
    ;;
esac
