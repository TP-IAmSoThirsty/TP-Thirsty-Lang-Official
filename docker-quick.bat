@echo off
REM Thirsty-Lang Docker quick-start for Windows
REM Usage: docker-quick.bat [command]

setlocal enabledelayedexpansion

set "IMAGE_NAME=thirsty-lang:0.8.0"
set "PROJECT_PATH=%~dp0"
set "COMMAND=%1"

if "%COMMAND%"=="" set "COMMAND=help"

if "%COMMAND%"=="build" (
    echo 🏗️  Building Thirsty-Lang Docker image...
    docker build -t %IMAGE_NAME% -f Dockerfile "%PROJECT_PATH%"
    echo ✓ Image built: %IMAGE_NAME%
    goto :end
)

if "%COMMAND%"=="run" (
    set "SCRIPT=%2"
    if "!SCRIPT!"=="" set "SCRIPT=--demo"
    echo ▶️  Running Thirsty-Lang...
    docker run --rm %IMAGE_NAME% run !SCRIPT!
    goto :end
)

if "%COMMAND%"=="repl" (
    echo 💬 Starting Thirsty-Lang REPL...
    docker run -it --rm %IMAGE_NAME% repl
    goto :end
)

if "%COMMAND%"=="test" (
    echo 🧪 Running full test suite...
    docker compose -f "%PROJECT_PATH%docker-compose.yml" run --rm test
    goto :end
)

if "%COMMAND%"=="dev" (
    echo 🔧 Starting development environment...
    docker compose -f "%PROJECT_PATH%docker-compose.yml" run --rm dev
    goto :end
)

if "%COMMAND%"=="fmt" (
    echo ✨ Formatting source files...
    docker compose -f "%PROJECT_PATH%docker-compose.yml" run --rm fmt
    goto :end
)

if "%COMMAND%"=="doctor" (
    echo 🏥 Running project health check...
    docker compose -f "%PROJECT_PATH%docker-compose.yml" run --rm doctor
    goto :end
)

if "%COMMAND%"=="version" (
    echo 📦 Checking version...
    docker run --rm %IMAGE_NAME% --version
    goto :end
)

if "%COMMAND%"=="clean" (
    echo 🧹 Cleaning up containers and images...
    docker compose -f "%PROJECT_PATH%docker-compose.yml" down -v
    docker rmi %IMAGE_NAME% 2>nul || true
    echo ✓ Cleanup complete
    goto :end
)

echo 🌊 Thirsty-Lang Docker CLI
echo.
echo Usage: docker-quick.bat [command] [args...]
echo.
echo Commands:
echo   build           Build Docker image
echo   run [script]    Run a .thirsty script (default: --demo)
echo   repl            Start interactive REPL
echo   test            Run full test suite
echo   dev             Start development shell
echo   fmt             Format source files
echo   doctor          Project health check
echo   version         Show Thirsty-Lang version
echo   clean           Clean up containers/images
echo   help            Show this help message
echo.
echo Examples:
echo   docker-quick.bat build
echo   docker-quick.bat run --demo
echo   docker-quick.bat repl
echo   docker-quick.bat test

:end
endlocal
