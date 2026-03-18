# Local PyInstaller build for Windows — mirrors the release workflow exactly.
# Run from the project root: .\scripts\build-local.ps1
# Then test immediately: .\dist\docker-sentinel\docker-sentinel.exe --help
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

pyinstaller `
  --additional-hooks-dir hooks `
  --runtime-hook hooks/rthook_pywin32.py `
  --name docker-sentinel `
  --collect-all litellm `
  --collect-all tiktoken `
  --collect-all tiktoken_ext `
  --collect-all google.adk `
  --collect-all google.genai `
  --collect-all anthropic `
  --collect-all openai `
  --collect-all pydantic `
  --collect-all docker `
  --collect-all certifi `
  --collect-all aiohttp `
  --collect-all fastapi `
  --collect-all starlette `
  --collect-all uvicorn `
  --collect-all opentelemetry `
  --collect-all mcp `
  --hidden-import win32api `
  --hidden-import pywintypes `
  `
  --exclude-module litellm.proxy `
  --exclude-module litellm.integrations `
  --exclude-module litellm.router `
  --exclude-module litellm.batches `
  --exclude-module litellm.fine_tuning `
  --exclude-module google.adk.cli `
  --exclude-module google.adk.web `
  --exclude-module google.adk.a2a `
  --exclude-module google.genai.tests `
  --exclude-module openai.cli `
  --exclude-module openai.helpers `
  `
  --exclude-module boto3 `
  --exclude-module botocore `
  --exclude-module s3transfer `
  --exclude-module aiobotocore `
  --exclude-module azure `
  --exclude-module google.cloud `
  --exclude-module cohere `
  --exclude-module replicate `
  --exclude-module huggingface_hub `
  `
  --exclude-module torch `
  --exclude-module tensorflow `
  --exclude-module transformers `
  --exclude-module jax `
  --exclude-module pandas `
  --exclude-module numpy `
  --exclude-module scipy `
  --exclude-module matplotlib `
  --exclude-module sklearn `
  --exclude-module PIL `
  `
  --exclude-module flask `
  --exclude-module django `
  `
  --exclude-module prometheus_client `
  --exclude-module sqlalchemy `
  --exclude-module redis `
  --exclude-module celery `
  --exclude-module langchain `
  docker_sentinel/cli.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild succeeded. Testing binary..." -ForegroundColor Green
    & ".\dist\docker-sentinel\docker-sentinel.exe" --help
} else {
    Write-Host "`nBuild failed." -ForegroundColor Red
    exit 1
}
