@echo off
REM ============================================================================
REM  PhishNet - one-command launcher (Windows)
REM  Ensures the BERT weights are pulled via Git LFS, creates a local .env with
REM  a dev API key on first run, then brings the stack up with Docker Compose.
REM ============================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- Preflight: Docker must be installed and running ------------------------
where docker >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker was not found on PATH. Install Docker Desktop, then re-run.
  exit /b 1
)
docker info >nul 2>&1
if errorlevel 1 (
  echo [ERROR] Docker is installed but not running. Start Docker Desktop, then re-run.
  exit /b 1
)

REM --- Materialize the BERT model via Git LFS (else detection returns bert:false)
where git >nul 2>&1
if errorlevel 1 (
  echo [WARN] git not found on PATH - skipping 'git lfs pull'. If detection
  echo        reports "bert: false", install Git + Git LFS and run: git lfs pull
) else (
  echo Pulling BERT weights via Git LFS ^(~268 MB, first run only^)...
  git lfs install >nul 2>&1
  git lfs pull
)

REM --- First run: generate a local .env with a dev API key --------------------
if not exist ".env" (
  echo Creating .env with a local-dev API key...
  (
    echo DATABASE_URL=sqlite:///data/phishnet.db
    echo OLLAMA_BASE_URL=http://ollama:11434
    echo PHISHNET_API_KEYS=dev-key-local:web
    echo PHISHNET_RETENTION_DAYS=30
  ) > .env
  echo .env created. API key: dev-key-local  ^(send as header  X-API-Key: dev-key-local^)
) else (
  echo Using existing .env
)

echo.
echo Starting PhishNet  ^(docker compose up -d --build^) ...
echo First run also downloads the Llama 3.2 1B model ^(~1.3 GB^) - this can take a while.
docker compose up -d --build
if errorlevel 1 (
  echo [ERROR] docker compose failed. See the output above.
  exit /b 1
)

echo.
echo ============================================================
echo  PhishNet is starting up.
echo    Frontend : http://localhost:3002
echo    API docs : http://localhost:8002/docs
echo    Verify   : curl http://localhost:8002/detect/methods
echo  API key (X-API-Key): dev-key-local
echo  Logs : docker compose logs -f      Stop : docker compose down
echo ============================================================
endlocal
