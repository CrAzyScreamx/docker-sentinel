# Install docker-sentinel on Windows (user-local, no admin needed)
# Usage: irm https://raw.githubusercontent.com/CrAzyScreamx/docker-sentinel/main/scripts/install.ps1 | iex
$ErrorActionPreference = 'Stop'

$Repo       = "CrAzyScreamx/docker-sentinel"
$AssetName  = "docker-sentinel-windows-amd64.zip"
$InstallDir = "$env:LOCALAPPDATA\docker-sentinel"

Write-Host "Fetching latest release..."
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
$Asset   = $Release.assets | Where-Object { $_.name -eq $AssetName }
if (-not $Asset) { Write-Error "Asset $AssetName not found in latest release"; exit 1 }

$TmpZip = "$env:TEMP\docker-sentinel-tmp.zip"
$TmpDir = "$env:TEMP\docker-sentinel-extract"

Write-Host "Downloading: $($Asset.browser_download_url)"
Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $TmpZip -UseBasicParsing

# Clean previous extraction temp dir
if (Test-Path $TmpDir) { Remove-Item $TmpDir -Recurse -Force }
Expand-Archive -Path $TmpZip -DestinationPath $TmpDir -Force
Remove-Item $TmpZip -Force

# Remove previous installation and move new one in
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
Move-Item "$TmpDir\docker-sentinel" $InstallDir
Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue

# Add to user PATH (no admin, persists via registry)
$RegKey  = 'HKCU:\Environment'
$Current = (Get-ItemProperty -Path $RegKey -Name Path -ErrorAction SilentlyContinue).Path
if ($Current -notlike "*$InstallDir*") {
    $NewPath = if ($Current) { "$Current;$InstallDir" } else { $InstallDir }
    Set-ItemProperty -Path $RegKey -Name Path -Value $NewPath
    # Broadcast PATH change so new terminals pick it up immediately
    Add-Type -Namespace Win32 -Name NativeMethod -MemberDefinition @'
        [DllImport("user32.dll", CharSet=CharSet.Auto)]
        public static extern IntPtr SendMessageTimeout(
            IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam,
            uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@ -ErrorAction SilentlyContinue
    $r = [UIntPtr]::Zero
    [Win32.NativeMethod]::SendMessageTimeout([IntPtr]0xffff, 0x001A, [UIntPtr]::Zero,
        "Environment", 2, 5000, [ref]$r) | Out-Null
    Write-Host "Added $InstallDir to PATH. Restart terminal for full effect."
}

Write-Host "Installed: $InstallDir\docker-sentinel.exe"
& "$InstallDir\docker-sentinel.exe" --help
