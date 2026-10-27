#Requires -RunAsAdministrator
[CmdletBinding()]
param([ValidateSet('Install','Start','Stop','Status','Uninstall')][string]$Action = 'Install')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot
Set-Location -LiteralPath $root
if ($Action -ne 'Install') {
    & "$PSScriptRoot/windows-agent.ps1" -Action $Action
    exit
}
Write-Host 'Pare o agente antigo com Ctrl+C e espere o terminal encerrar antes de continuar.'
$answer = Read-Host 'O agente antigo esta parado? Digite SIM para continuar'
if ($answer -ne 'SIM') { throw 'Instalacao cancelada; nenhum servico instalado.' }
$python = ''
if (Get-Command py -ErrorAction SilentlyContinue) {
    $python = & py -3 -c "import sys; print(sys.executable)"
    if ($LASTEXITCODE -ne 0) { $python = '' }
}
if (-not $python -or -not $python.StartsWith($env:ProgramFiles + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-Host 'Use Python 3.12+ instalado para TODOS os usuarios em Program Files.'
    $python = Read-Host 'Caminho completo do python.exe (exemplo C:\Program Files\Python312\python.exe)'
}
if (-not $python.StartsWith($env:ProgramFiles + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Instale Python para todos os usuarios em Program Files e tente novamente.'
}
& "$PSScriptRoot/windows-agent.ps1" -Action Install -Python $python -Config "$root/config.yaml" -CredentialsFile "$root/credentials.json" -CAFile "$root/server-ca.pem"
Write-Host 'Servico instalado. Pode fechar esta janela. Inicia automaticamente com o Windows.'
