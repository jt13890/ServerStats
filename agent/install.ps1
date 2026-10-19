<#
.SYNOPSIS
Installs the ServerStats agent on a Windows host.

.DESCRIPTION
Run from an elevated (Administrator) PowerShell. Join with the server's join
key (shown under "Add host"), no config edit needed:

  & ([scriptblock]::Create((irm https://stats.example.com/api/agent/install.ps1))) `
      -Url https://stats.example.com -Join <JOIN KEY> [-Name NAME]

...or with a token you put in config.yaml yourself: -Token <TOKEN>

The agent is the same single Python file the Linux hosts run (Python 3.6+, no
packages needed). It runs as a scheduled task at startup, as the unprivileged
LOCAL SERVICE account, and reports to the server over HTTPS. Logs:
C:\ProgramData\ServerStats\logs\agent.log

.PARAMETER Url         Server base URL, e.g. https://stats.example.com
.PARAMETER Join        The server's join key (adds the host by itself)
.PARAMETER Token       A per-host token from config.yaml (instead of -Join)
.PARAMETER Name        With -Join: the name to show (default: this computer's name)
.PARAMETER Interval    Seconds between reports (default 15)
.PARAMETER CaFile      CA bundle for a server with a private certificate. (A CA
                       installed in the Windows certificate store works too.)
.PARAMETER Python      Path to python.exe (default: found automatically)
.PARAMETER RunAsSystem Run as SYSTEM instead of LOCAL SERVICE. Only needed if
                       your Python is installed for one user (under C:\Users)
                       or if per-process details are missing for some processes.
.PARAMETER Uninstall   Remove the agent
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string]$Token,
    [string]$Join,
    [string]$Name,
    [int]$Interval = 15,
    [string]$CaFile,
    [string]$Python,
    [switch]$RunAsSystem,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Die 'run this from an elevated PowerShell (Run as administrator)' }

$TaskName = 'ServerStats Agent'
$Dir      = Join-Path $env:ProgramData 'ServerStats'
$LogDir   = Join-Path $Dir 'logs'
$AgentPy  = Join-Path $Dir 'serverstats_agent.py'
$EnvFile  = Join-Path $Dir 'agent.env'
$LogFile  = Join-Path $LogDir 'agent.log'

function Stop-Agent {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*serverstats_agent.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($Uninstall) {
    Stop-Agent
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $Dir) { Remove-Item -Recurse -Force $Dir }
    Write-Host 'ServerStats agent removed.'
    exit 0
}

# -- check the arguments -------------------------------------------------------
if (-not $Url) { Die 'usage: install.ps1 -Url <server url> (-Join <join key> [-Name name] | -Token <token>) [-Interval 15] [-CaFile path] [-RunAsSystem] | -Uninstall' }
$Url = $Url.TrimEnd('/')
if ($Url -notmatch '^https?://[^\s''"]+$') { Die '-Url must look like https://stats.example.com' }
if ([bool]$Token -eq [bool]$Join) { Die 'use one of -Join or -Token' }
if ($Interval -lt 2) { Die '-Interval must be at least 2 seconds' }
if ($CaFile -and -not (Test-Path -LiteralPath $CaFile)) { Die "-CaFile not found: $CaFile" }
if ($CaFile) { $CaFile = (Resolve-Path -LiteralPath $CaFile).Path }

# -- find Python -----------------------------------------------------------------
function Test-Python($exe) {
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) { return $false }
    if ($exe -like '*\WindowsApps\*') { return $false }   # the Microsoft Store stub, not a real install
    try { $v = & $exe -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null } catch { return $false }
    if ($LASTEXITCODE -ne 0 -or $v -notmatch '^(\d+)\.(\d+)$') { return $false }
    return ([int]$Matches[1] -gt 3) -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -ge 6)
}
$py = $null
if ($Python) {
    if (-not (Test-Python $Python)) { Die "$Python isn't a usable Python 3.6+" }
    $py = (Resolve-Path -LiteralPath $Python).Path
} else {
    $candidates = @()
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) { try { $candidates += (& $launcher.Source -3 -c 'import sys; print(sys.executable)' 2>$null) } catch { } }
    $candidates += @(Get-Command python.exe -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    foreach ($c in $candidates) { if (Test-Python $c) { $py = $c; break } }
}
if (-not $py) {
    Die 'Python 3.6+ is required. Install it for all users (e.g. winget install Python.Python.3.12 --scope machine), then run this again. The Microsoft Store alias does not count.'
}
$userDirs = @($env:USERPROFILE, (Join-Path $env:SystemDrive 'Users')) | Where-Object { $_ }
if (-not $RunAsSystem -and ($userDirs | Where-Object { $py -like ($_.TrimEnd('\') + '\*') })) {
    Die "$py is installed for one user, and the LOCAL SERVICE account the agent runs as can't read it. Install Python for all users (winget install Python.Python.3.12 --scope machine), or add -RunAsSystem."
}
Write-Host "Using Python at $py"

# -- install the agent -------------------------------------------------------------
Stop-Agent
New-Item -ItemType Directory -Force -Path $Dir, $LogDir | Out-Null
$runSid  = if ($RunAsSystem) { '*S-1-5-18' } else { '*S-1-5-19' }   # SYSTEM, or LOCAL SERVICE
$runUser = if ($RunAsSystem) { 'NT AUTHORITY\SYSTEM' } else { 'NT AUTHORITY\LocalService' }
# Only administrators and SYSTEM can change the agent or its settings; the
# account that runs it can read them, and write only to the logs folder.
& icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${runSid}:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { Die "couldn't set permissions on $Dir" }
& icacls.exe $LogDir /grant "${runSid}:(OI)(CI)M" | Out-Null

$local = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'serverstats_agent.py' } else { $null }
if ($local -and (Test-Path -LiteralPath $local)) {
    Copy-Item -LiteralPath $local -Destination $AgentPy -Force
} else {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -Uri "$Url/api/agent/serverstats_agent.py" -OutFile $tmp
        $first = Get-Content -LiteralPath $tmp -TotalCount 1
        if ($first -notmatch 'python3') { Die 'download did not return the agent (is /api/agent/ excluded from SSO?)' }
        Copy-Item -LiteralPath $tmp -Destination $AgentPy -Force
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

# -- join, or reuse the token this host already has --------------------------------
function Read-EnvValue($key) {
    if (-not (Test-Path -LiteralPath $EnvFile)) { return $null }
    foreach ($line in Get-Content -LiteralPath $EnvFile) {
        if ($line -like "$key=*") { return $line.Substring($key.Length + 1) }
    }
    return $null
}
if ($Join) {
    # Reinstalling? Keep the token this host already has for this server.
    if ((Read-EnvValue 'SERVERSTATS_URL') -eq $Url) { $Token = Read-EnvValue 'SERVERSTATS_TOKEN' }
    if (-not $Token) {
        if (-not $Name) { $Name = $env:COMPUTERNAME }
        $Name = [regex]::Replace($Name, '[^A-Za-z0-9._-]', '-')
        if ($Name.Length -gt 64) { $Name = $Name.Substring(0, 64) }
        # The key goes in via the environment, not the command line.
        $env:SERVERSTATS_JOIN_KEY = $Join
        try {
            $enrollArgs = @($AgentPy, '--enroll', $Name, '--url', $Url)
            if ($CaFile) { $enrollArgs += @('--ca-file', $CaFile) }
            $out = & $py @enrollArgs
            if ($LASTEXITCODE -ne 0) { Die 'joining failed (see the message above)' }
        } finally { Remove-Item Env:\SERVERSTATS_JOIN_KEY -ErrorAction SilentlyContinue }
        $parts = ([string]($out | Select-Object -Last 1)).Trim() -split ' ', 2
        if ($parts.Count -ne 2 -or $parts[1] -notmatch '^[0-9a-f]{64}$') { Die 'joining failed: unexpected reply from the server' }
        $Token = $parts[1]
        Write-Host "Joined ServerStats as $($parts[0])."
    }
}

$lines = @(
    "SERVERSTATS_URL=$Url",
    "SERVERSTATS_TOKEN=$Token",
    "SERVERSTATS_INTERVAL=$Interval",
    "SERVERSTATS_LOG_FILE=$LogFile"
)
if ($CaFile) { $lines += "SERVERSTATS_CA_FILE=$CaFile" }
# UTF-8 without a byte order mark, which the agent's parser would read as part of the first key.
[IO.File]::WriteAllText($EnvFile, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))

# -- the service: a scheduled task that starts at boot and restarts if it dies ------
$action    = New-ScheduledTaskAction -Execute $py -Argument "`"$AgentPy`" --env-file `"$EnvFile`"" -WorkingDirectory $Dir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId $runUser -LogonType ServiceAccount -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
    -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'Reports this computer''s stats to ServerStats' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "ServerStats agent installed and running as $runUser."
Write-Host "Logs: Get-Content -Wait '$LogFile'"
Write-Host "Remove it with: install.ps1 -Uninstall"
