# PhishNet — Local MVP Runbook

## Prereqs
- Docker Desktop (Linux containers)

## Start
From `C:\Users\K\.openclaw\workspace`:

```powershell
# Use Docker Desktop's docker.exe
$docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'

# Ensure credential helper can be found
[Environment]::SetEnvironmentVariable('Path', 'C:\Program Files\Docker\Docker\resources\bin;' + [Environment]::GetEnvironmentVariable('Path','Process'), 'Process')

& $docker compose build
& $docker compose up -d
& $docker ps
```

## URLs
- Web: http://localhost:3000
- API: http://localhost:8000
- API health: http://localhost:8000/health

## Stop
```powershell
& $docker compose down
```

## Notes
- Artifacts are mounted to `./artifacts` on host and `/artifacts` inside the api container.
- Current MVP ingestion stores email records as JSON under `artifacts/emails/`.
