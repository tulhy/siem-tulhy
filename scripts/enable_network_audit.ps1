$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Execute ATUALIZAR_AGENTE.cmd como administrador.'
}
$backupDir = Join-Path $env:ProgramData 'Tulhy\update-backups'
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
$backup = Join-Path $backupDir ('audit-before-network-' + [guid]::NewGuid().ToString() + '.csv')
$audit = Join-Path $env:SystemRoot 'System32\auditpol.exe'
& $audit /backup "/file:$backup"
if ($LASTEXITCODE -ne 0) { throw 'Falha no backup. Auditoria nao alterada.' }
Write-Host 'Ativando auditoria WFP; isto aumenta o volume do log Security do Windows.'
& $audit /set '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}' /success:enable /failure:enable
if ($LASTEXITCODE -ne 0) { throw "Falha ao configurar conexoes. Backup: $backup" }
& $audit /set '/subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}' /failure:enable
if ($LASTEXITCODE -ne 0) { throw "Falha ao configurar descartes; conexoes ja alteradas. Backup: $backup" }
& $audit /get '/subcategory:{0CCE9226-69AE-11D9-BED3-505054503030}'
if ($LASTEXITCODE -ne 0) { throw 'Falha ao verificar conexoes.' }
& $audit /get '/subcategory:{0CCE9225-69AE-11D9-BED3-505054503030}'
if ($LASTEXITCODE -ne 0) { throw 'Falha ao verificar descartes.' }
Write-Host "Backup completo da politica: $backup"
Write-Host 'GPO pode sobrescrever a auditoria. A HOST descarta eventos LOW conforme solicitado.'
Write-Host 'Auditoria ativa nao comprova entrega nem deteccao no painel.'
