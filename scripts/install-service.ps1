<#
.SYNOPSIS
    Installs WebOSINT Pro as a Windows Service.

.DESCRIPTION
    Registers the service so it starts at boot and restarts automatically after
    a crash. Once installed the service is manageable with the standard tools:

        sc.exe query WebOSINT
        sc.exe start WebOSINT
        sc.exe stop WebOSINT
        Get-Service WebOSINT
        Restart-Service WebOSINT
        services.msc

    Windows has no native equivalent of a POSIX daemon, so the service is
    hosted by NSSM when available (recommended), falling back to a plain
    sc.exe registration.

.PARAMETER Uninstall
    Remove the service instead of installing it.

.EXAMPLE
    .\install-service.ps1 -Port 8000
    .\install-service.ps1 -Uninstall

.NOTES
    Must be run from an elevated PowerShell prompt.
#>

[CmdletBinding()]
param(
    [string]$ServiceName = 'WebOSINT',
    [string]$BindHost = '127.0.0.1',
    [int]$Port = 8000,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run from an elevated PowerShell prompt.'
    }
}

Assert-Administrator

$repoRoot = Split-Path -Parent $PSScriptRoot
$entryPoint = Join-Path $repoRoot 'webserve.py'

if ($Uninstall) {
    Write-Host "Removing the $ServiceName service ..."
    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $existing) {
        Write-Host 'The service is not installed. Nothing to do.'
        exit 0
    }
    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
    }
    $nssm = Get-Command nssm.exe -ErrorAction SilentlyContinue
    if ($nssm) {
        & nssm.exe remove $ServiceName confirm | Out-Null
    }
    else {
        & sc.exe delete $ServiceName | Out-Null
    }
    Write-Host 'Service removed.'
    exit 0
}

if (-not (Test-Path $entryPoint)) {
    throw "Cannot find $entryPoint."
}

# Prefer the project virtual environment if one is present.
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    $python = Join-Path $repoRoot 'venv\Scripts\python.exe'
}
if (-not (Test-Path $python)) {
    $resolved = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        throw 'Python was not found. Install Python 3.10 or newer and retry.'
    }
    $python = $resolved.Source
}

$logDirectory = Join-Path $repoRoot 'logs'
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Host "The $ServiceName service already exists. Remove it first with -Uninstall."
    exit 1
}

$arguments = "`"$entryPoint`" --host $BindHost --port $Port"
$nssm = Get-Command nssm.exe -ErrorAction SilentlyContinue

if ($nssm) {
    Write-Host "Installing $ServiceName with NSSM ..."
    & nssm.exe install $ServiceName $python $arguments | Out-Null
    & nssm.exe set $ServiceName AppDirectory $repoRoot | Out-Null
    & nssm.exe set $ServiceName DisplayName 'WebOSINT Pro' | Out-Null
    & nssm.exe set $ServiceName Description 'WebOSINT Pro Attack Surface Management platform' | Out-Null
    & nssm.exe set $ServiceName Start SERVICE_AUTO_START | Out-Null
    & nssm.exe set $ServiceName AppStdout (Join-Path $logDirectory 'webosint.log') | Out-Null
    & nssm.exe set $ServiceName AppStderr (Join-Path $logDirectory 'webosint.err') | Out-Null
    # Rotate the captured output at 10 MB so the log cannot grow without bound.
    & nssm.exe set $ServiceName AppRotateFiles 1 | Out-Null
    & nssm.exe set $ServiceName AppRotateBytes 10485760 | Out-Null
    # Restart automatically after a crash, with a short backoff.
    & nssm.exe set $ServiceName AppExit Default Restart | Out-Null
    & nssm.exe set $ServiceName AppRestartDelay 5000 | Out-Null
    & nssm.exe set $ServiceName AppEnvironmentExtra "WEBOSINT_RUNTIME_DIR=$repoRoot\.runtime" | Out-Null
}
else {
    Write-Warning 'NSSM was not found. Falling back to sc.exe.'
    Write-Warning 'NSSM is strongly recommended: https://nssm.cc/ (choco install nssm)'
    $binPath = "`"$python`" $arguments"
    & sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= 'WebOSINT Pro' | Out-Null
    & sc.exe description $ServiceName 'WebOSINT Pro Attack Surface Management platform' | Out-Null
    # Restart on the first, second and subsequent failures after 5 seconds.
    & sc.exe failure $ServiceName reset= 300 actions= restart/5000/restart/5000/restart/5000 | Out-Null
}

Write-Host ''
Write-Host "Installed. The service will start automatically at boot." -ForegroundColor Green
Write-Host ''
Write-Host '  Start:   sc.exe start WebOSINT'
Write-Host '  Stop:    sc.exe stop WebOSINT'
Write-Host '  Status:  Get-Service WebOSINT'
Write-Host '  Remove:  .\install-service.ps1 -Uninstall'
Write-Host ''
Write-Host "Dashboard: http://${BindHost}:${Port}"
