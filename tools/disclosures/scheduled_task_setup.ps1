<#
.SYNOPSIS
  Registers (or removes) the scheduled Windows task that checks the upstream disclosures
  daily.

.DESCRIPTION
  RUN ONLY AFTER THE CLIENT HAS APPROVED IT. Without a switch the script only shows
  what it would do (dry run).

  The task "UJC-Disclosure-Watch" starts this script daily with -Run. The run calls
    python tools/disclosures/disclosure_watch.py --flag
  in the checker root (read-only gh queries, mailbox read-only). Exit 1 (news) or 2
  (error): the file private/disclosures/NEW.flag is created (by the Python tool) and
  a Windows balloon appears. Log: private/disclosures/watch.log (git-ignored).

  Prerequisites: gh is logged in for the user (gh auth status), python in PATH
  or pass -Python. For the mailbox: -VaultEnv <path to vault_env.py or its folder>
  (set as UJC_VAULT_ENV) or the security_mail_* variables in the user profile.
  The task only runs while the user is logged on (balloon).

.EXAMPLE
  .\tools\disclosures\scheduled_task_setup.ps1                         # dry run
  .\tools\disclosures\scheduled_task_setup.ps1 -Install -Time 08:30
  .\tools\disclosures\scheduled_task_setup.ps1 -Install -DayOfWeek Monday -Time 08:30   # weekly
  .\tools\disclosures\scheduled_task_setup.ps1 -Remove
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Remove,
    [switch]$Run,
    [string]$Time = "08:30",
    [ValidateSet("", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")]
    [string]$DayOfWeek = "",
    [string]$Python = "python",
    [string]$TaskName = "UJC-Disclosure-Watch",
    [string]$VaultEnv = ""
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Watch = Join-Path $Root "tools\disclosures\disclosure_watch.py"
$Log = Join-Path $Root "private\disclosures\watch.log"

function Show-Balloon([string]$Title, [string]$Text) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        $n = New-Object System.Windows.Forms.NotifyIcon
        $n.Icon = [System.Drawing.SystemIcons]::Information
        $n.BalloonTipTitle = $Title
        $n.BalloonTipText = $Text
        $n.Visible = $true
        $n.ShowBalloonTip(15000)
        Start-Sleep -Seconds 16
        $n.Dispose()
    } catch {
        # The notification is a convenience; NEW.flag and the report remain the source.
    }
}

if ($Run) {
    Set-Location $Root
    $env:PYTHONIOENCODING = "utf-8"
    if ($VaultEnv) { $env:UJC_VAULT_ENV = $VaultEnv }
    $stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    # Windows PowerShell 5.1 turns redirected stderr lines into errors; with "Stop" the first one
    # would end the run before exit code and log are written - Continue just for this call.
    $ErrorActionPreference = "Continue"
    $output = & $Python $Watch --flag 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    New-Item -ItemType Directory -Force -Path (Split-Path $Log) | Out-Null
    Add-Content -Path $Log -Encoding ascii -Value ("[$stamp] exit=$code")
    Add-Content -Path $Log -Encoding ascii -Value ($output | Out-String)
    if ($code -eq 1) {
        Show-Balloon "Upstream disclosures: news" "Reports under private\disclosures\reports, notice in private\disclosures\NEW.flag"
    } elseif ($code -ne 0) {
        Show-Balloon "Upstream disclosures: ERROR" "Check failed (exit $code) - private\disclosures\watch.log"
    }
    exit $code
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument ("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"{0}`" -Run -Python `"{1}`" -VaultEnv `"{2}`"" -f $PSCommandPath, $Python, $VaultEnv) `
    -WorkingDirectory $Root
# -DayOfWeek <day>: once a week on that day instead of daily
$trigger = if ($DayOfWeek) { New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At $Time } else { New-ScheduledTaskTrigger -Daily -At $Time }
$when = if ($DayOfWeek) { "weekly on $DayOfWeek $Time" } else { "daily $Time" }
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -MultipleInstances IgnoreNew

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Output "OK: task $TaskName removed"
    exit 0
}

if (-not $Install) {
    Write-Output "DRY RUN - nothing registered."
    Write-Output "Task:      $TaskName"
    Write-Output "Time:      $when (catch up if missed)"
    Write-Output "Starts:    powershell.exe -File $PSCommandPath -Run"
    Write-Output "Checks:    $Python $Watch --flag (read-only)"
    Write-Output "Install only after approval: -Install"
    exit 0
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description "Checks upstream disclosures of ujc-security-checker (read-only), report under disclosures\reports" | Out-Null
Write-Output "OK: task $TaskName registered ($when)"
