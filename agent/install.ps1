<#
.SYNOPSIS
Installs the ServerStats agent on a Windows host. No administrator rights needed.

.DESCRIPTION
Run in a normal PowerShell. Join with the server's join key (shown under
"Add host"), no config edit needed:

  & ([scriptblock]::Create((irm https://stats.example.com/api/agent/install.ps1))) `
      -Url https://stats.example.com -Join <JOIN KEY> [-Name NAME]

...or with a token you put in config.yaml yourself: -Token <TOKEN>

The agent is the same single Python file the Linux hosts run (Python 3.6+, no
packages needed). By default it runs as you, in the background, from sign-in
until you sign out, and reports to the server over HTTPS. Nothing is installed
system-wide. Files: %LOCALAPPDATA%\ServerStats (log: logs\agent.log).

For a machine that should report from boot, before anyone signs in (a server),
add -Service from an elevated PowerShell instead.

.PARAMETER Url         Server base URL, e.g. https://stats.example.com
.PARAMETER Join        The server's join key (adds the host by itself)
.PARAMETER Token       A per-host token from config.yaml (instead of -Join)
.PARAMETER Name        With -Join: the name to show (default: this computer's name)
.PARAMETER Interval    Seconds between reports (default 15)
.PARAMETER Gpu         Start with GPU stats on (the dashboard can turn them on or off any time)
.PARAMETER CaFile      CA bundle for a server with a private certificate. (A CA
                       installed in the Windows certificate store works too.)
.PARAMETER Python      Path to python.exe (default: found automatically)
.PARAMETER Service     Run from boot as the LOCAL SERVICE account, as a scheduled
                       task, instead of as you from sign-in. Needs an elevated
                       PowerShell, and Python installed for all users.
.PARAMETER RunAsSystem With -Service: run as SYSTEM instead of LOCAL SERVICE
.PARAMETER Uninstall   Remove the agent
#>
[CmdletBinding()]
param(
    [string]$Url,
    [string]$Token,
    [string]$Join,
    [string]$Name,
    [int]$Interval = 15,
    [switch]$Gpu,
    [string]$CaFile,
    [string]$Python,
    [switch]$Service,
    [switch]$RunAsSystem,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

if ($RunAsSystem) { $Service = [switch]$true }
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($Service -and -not $isAdmin) { Die '-Service needs an elevated PowerShell (Run as administrator). Leave it out to install for just your account, with no administrator rights.' }

$TaskName = 'ServerStats Agent'                                        # -Service: scheduled task
$RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'      # default: starts when you sign in
$UserDir  = Join-Path $env:LOCALAPPDATA 'ServerStats'
$ServiceDir = Join-Path $env:ProgramData 'ServerStats'
$Dir      = if ($Service) { $ServiceDir } else { $UserDir }
$LogDir   = Join-Path $Dir 'logs'
$SpoolDir = Join-Path $Dir 'spool'                                    # reports kept while the server is away
$AgentPy  = Join-Path $Dir 'serverstats_agent.py'
$EnvFile  = Join-Path $Dir 'agent.env'
$LogFile  = Join-Path $LogDir 'agent.log'

function Stop-Agent {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    # The processes you can see: your own, or everyone's when elevated.
    Get-CimInstance Win32_Process -Filter "Name LIKE 'python%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like '*serverstats_agent.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($Uninstall) {
    Stop-Agent
    Remove-ItemProperty -Path $RunKey -Name $TaskName -ErrorAction SilentlyContinue
    if (Test-Path $UserDir) { Remove-Item -Recurse -Force $UserDir }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        if ($isAdmin) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            if (Test-Path $ServiceDir) { Remove-Item -Recurse -Force $ServiceDir }
        } else {
            Write-Host 'The boot-time service is still installed: run this again from an elevated PowerShell to remove it.' -ForegroundColor Yellow
        }
    }
    Write-Host 'ServerStats agent removed.'
    exit 0
}

# -- check the arguments -------------------------------------------------------
if (-not $Url) { Die 'usage: install.ps1 -Url <server url> (-Join <join key> [-Name name] | -Token <token>) [-Gpu] [-Interval 15] [-CaFile path] [-Service [-RunAsSystem]] | -Uninstall' }
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
    Die 'Python 3.6+ is required (it can be installed without administrator rights: winget install Python.Python.3.12). The Microsoft Store alias does not count.'
}
$userDirs = @($env:USERPROFILE, (Join-Path $env:SystemDrive 'Users')) | Where-Object { $_ }
if ($Service -and -not $RunAsSystem -and ($userDirs | Where-Object { $py -like ($_.TrimEnd('\') + '\*') })) {
    Die "$py is installed for one user, and the LOCAL SERVICE account can't read it. Install Python for all users (winget install Python.Python.3.12 --scope machine), or add -RunAsSystem."
}
# pythonw.exe runs without a console window.
$pyw = Join-Path (Split-Path -Parent $py) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pyw)) { $pyw = $py }
Write-Host "Using Python at $py"

# -- install the agent -------------------------------------------------------------
Stop-Agent
New-Item -ItemType Directory -Force -Path $Dir, $LogDir, $SpoolDir | Out-Null
if ($Service) {
    $runSid  = if ($RunAsSystem) { '*S-1-5-18' } else { '*S-1-5-19' }   # SYSTEM, or LOCAL SERVICE
    $runUser = if ($RunAsSystem) { 'NT AUTHORITY\SYSTEM' } else { 'NT AUTHORITY\LocalService' }
    # Only administrators and SYSTEM can change the agent or its settings; the
    # account that runs it can read them, and write only to the logs folder.
    & icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${runSid}:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { Die "couldn't set permissions on $Dir" }
    & icacls.exe $LogDir /grant "${runSid}:(OI)(CI)M" | Out-Null
    & icacls.exe $SpoolDir /grant "${runSid}:(OI)(CI)M" | Out-Null
}   # otherwise the folder is in your profile: only you, SYSTEM and administrators can read the token

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
    "SERVERSTATS_GPU=$([int][bool]$Gpu)",
    "SERVERSTATS_LOG_FILE=$LogFile",
    "SERVERSTATS_SPOOL_DIR=$SpoolDir"
)
if ($CaFile) { $lines += "SERVERSTATS_CA_FILE=$CaFile" }
# UTF-8 without a byte order mark, which the agent's parser would read as part of the first key.
[IO.File]::WriteAllText($EnvFile, (($lines -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))

# -- start it -------------------------------------------------------------------------
$agentArgs = "`"$AgentPy`" --env-file `"$EnvFile`""
if ($Service) {
    # A scheduled task that starts at boot and restarts if it dies.
    $action    = New-ScheduledTaskAction -Execute $py -Argument $agentArgs -WorkingDirectory $Dir
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId $runUser -LogonType ServiceAccount -RunLevel Limited
    $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Reports this computer''s stats to ServerStats' -Force | Out-Null
    Remove-ItemProperty -Path $RunKey -Name $TaskName -ErrorAction SilentlyContinue   # not both
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "ServerStats agent installed and running from boot as $runUser."
} else {
    # Starts when you sign in; your own HKCU key, so no administrator rights.
    New-Item -Path $RunKey -Force | Out-Null
    New-ItemProperty -Path $RunKey -Name $TaskName -PropertyType String -Force -Value "`"$pyw`" $agentArgs" | Out-Null
    Start-Process -FilePath $pyw -ArgumentList $agentArgs -WorkingDirectory $Dir -WindowStyle Hidden
    Write-Host "ServerStats agent installed and running. It starts whenever you sign in."
}
Write-Host "Logs: Get-Content -Wait '$LogFile'"
Write-Host "Remove it with: install.ps1 -Uninstall"
