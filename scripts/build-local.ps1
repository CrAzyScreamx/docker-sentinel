# Local PyInstaller build for Windows — clean slate workflow.
# Run from the project root: .\scripts\build-local.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

pyinstaller `
  --additional-hooks-dir hooks `
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
  --collect-all pywin32 `
  --collect-all docker_sentinel `
  --hidden-import win32api `
  --hidden-import pywintypes `
  --hidden-import win32con `
  --hidden-import win32file `
  --hidden-import win32pipe `
  --hidden-import win32event `
  --hidden-import win32security `
  --hidden-import ntsecuritycon `
  --hidden-import google.adk.tools `
  --hidden-import google.adk.tools.function_tool `
  --hidden-import google.adk.tools.base_tool `
  --hidden-import google.adk.models.lite_llm `
  --hidden-import google.adk.flows `
  --hidden-import google.adk.events `
  --hidden-import google.genai.types `
  --copy-metadata docker-sentinel `
  --copy-metadata google-adk `
  --copy-metadata google-genai `
  --copy-metadata pydantic `
  --clean `
  -y `
  docker_sentinel/cli.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild succeeded. Testing binary..." -ForegroundColor Green
    & ".\dist\docker-sentinel\docker-sentinel.exe" --help
} else {
    Write-Host "`nBuild failed." -ForegroundColor Red
    exit 1
}