#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Install','Start','Stop','Status','Uninstall')][string]$Action,
    [string]$Python = 'C:\Program Files\Python312\python.exe',
    [string]$Config = (Join-Path (Split-Path $PSScriptRoot) 'config.yaml'),
    [string]$CAFile,
    [string]$CredentialsFile
)
$ErrorActionPreference = 'Stop'
$installRoot = Join-Path $env:ProgramFiles 'Tulhy'
$stateRoot = Join-Path $env:ProgramData 'Tulhy'
$serviceName = 'TulhyAgent'
function Invoke-Python {
    & $Python @args
    if ($LASTEXITCODE -ne 0) { throw "Python failed with exit code $LASTEXITCODE" }
}
switch ($Action) {
    'Status' { Get-Service -Name $serviceName; break }
    'Start' { Start-Service -Name $serviceName; Get-Service -Name $serviceName; break }
    'Stop' { Stop-Service -Name $serviceName; Get-Service -Name $serviceName; break }
    'Install' {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already installed; uninstall the service before replacing its code. State is preserved.' }
        if (-not (Test-Path -LiteralPath $Python)) { throw 'Install Python 3.12+ for all users and pass its executable with -Python.' }
        Invoke-Python -c "import sys; assert sys.version_info >= (3,12); assert sys.prefix == sys.base_prefix, 'Use a global Python installation, not a virtual environment'"
        if ($CredentialsFile) {
            $enrollment = Get-Content -LiteralPath $CredentialsFile -Raw | ConvertFrom-Json
            $env:SIEM_AGENT_ID = $enrollment.agent_id
            $env:SIEM_AGENT_TOKEN = $enrollment.agent_token
        }
        $existingCredentials = Join-Path $stateRoot 'credentials.json'
        if (Test-Path -LiteralPath $existingCredentials) {
            $previous = Get-Content -LiteralPath $existingCredentials -Raw | ConvertFrom-Json
            if ($previous.agent_id -ne $env:SIEM_AGENT_ID) { throw 'Existing state belongs to another agent. Preserve/export its queue before changing identity.' }
        }
        if (-not $env:SIEM_AGENT_ID -or -not $env:SIEM_AGENT_TOKEN) { throw 'Set SIEM_AGENT_ID and SIEM_AGENT_TOKEN in this process before installation.' }
        Invoke-Python -c "import os; from uuid import UUID; UUID(os.environ['SIEM_AGENT_ID']); assert len(os.environ['SIEM_AGENT_TOKEN']) >= 32"
        New-Item -ItemType Directory -Path $installRoot,$stateRoot -Force | Out-Null
        # Apply ACLs BEFORE writing credentials, queue data or executable code.
        foreach ($securedPath in @($installRoot,$stateRoot)) {
            & icacls.exe $securedPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'Failed to restrict directory permissions' }
        }
        $sourceRoot = Split-Path $PSScriptRoot
        foreach ($package in @('agent','shared')) {
            Copy-Item -LiteralPath (Join-Path $sourceRoot $package) -Destination $installRoot -Recurse -Force
        }
        Invoke-Python -m pip install -r (Join-Path $sourceRoot 'requirements-agent.txt')
        Invoke-Python (Join-Path $sourceRoot 'scripts/prepare_service.py') $Config $stateRoot
        $postInstall = & $Python -c "import pathlib,sys; print(pathlib.Path(sys.prefix)/'Scripts'/'pywin32_postinstall.py')"
        if ($LASTEXITCODE -ne 0) { throw 'Failed to locate pywin32 post-install script' }
        Invoke-Python $postInstall -install
        Invoke-Python -c "import pathlib,site,sys; pathlib.Path(site.getsitepackages()[0], 'tulhy-service.pth').write_text(sys.argv[1]+'\n', encoding='utf-8')" $installRoot
        $credentials = @{ agent_id=$env:SIEM_AGENT_ID; agent_token=$env:SIEM_AGENT_TOKEN } | ConvertTo-Json
        [System.IO.File]::WriteAllText((Join-Path $stateRoot 'credentials.json'), $credentials, [System.Text.UTF8Encoding]::new($false))
        Invoke-Python -c "import pathlib,sys,yaml; from agent.config.settings import Config; p=pathlib.Path(sys.argv[1]); d=yaml.safe_load(p.read_text(encoding='utf-8-sig')); d['data_dir']=str(pathlib.Path(sys.argv[2])/'data'); c=Config.model_validate(d); pathlib.Path(sys.argv[2],'config.yaml').write_text(yaml.safe_dump(c.model_dump()),encoding='utf-8')" $Config $stateRoot
        if ($CAFile) { Copy-Item -LiteralPath $CAFile -Destination (Join-Path $stateRoot 'ca.pem') -Force }
        Invoke-Python -m agent.windows_service --startup auto install
        & sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/120000/restart/300000 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Failed to configure service recovery' }
        Start-Service -Name $serviceName
        Get-Service -Name $serviceName
        Write-Host 'Installed as visible LocalSystem service. Credentials and telemetry are restricted to SYSTEM and Administrators.'
        break
    }
    'Uninstall' {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Stopped') { Stop-Service -Name $serviceName }
        if ($service) {
            & sc.exe delete $serviceName
            if ($LASTEXITCODE -ne 0) { throw 'Failed to remove service' }
        }
        # Deliberately preserve pending telemetry and credentials; no recursive deletion.
        Write-Host "Service removed. Preserved code: $installRoot; queue and configuration: $stateRoot"
        Write-Host 'Revoke the agent token on the server. Review/export pending events before manually removing these directories.'
        break
    }
}
