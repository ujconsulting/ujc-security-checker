# Thin wrapper for tools/setup.sh on Windows (PowerShell 5.1 or 7).
# Finds Git Bash and passes all parameters through:
#   .\tools\setup.ps1 [--check | --rebuild | --remove]
# Git Bash can be set with UJC_BASH (environment or private/environment.conf).
# Output is ASCII only.
$ErrorActionPreference = 'Stop'

$script = Join-Path $PSScriptRoot 'setup.sh'
$private = Join-Path (Split-Path $PSScriptRoot -Parent) 'private\environment.conf'

$bash = $env:UJC_BASH
if (-not $bash -and (Test-Path $private)) {
    $line = Get-Content $private | Where-Object { $_ -match '^UJC_BASH=' } | Select-Object -First 1
    if ($line) {
        $bash = $line.Substring(9).Trim()
        # UJC_BASH="C:\Program Files\Git\bin\bash.exe" - drop one matching pair of quotes
        if ($bash.Length -ge 2 -and (($bash[0] -eq '"' -and $bash[-1] -eq '"') -or ($bash[0] -eq "'" -and $bash[-1] -eq "'"))) {
            $bash = $bash.Substring(1, $bash.Length - 2)
        }
    }
}
if (-not $bash) {
    $candidates = @()
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($git) {
        # ...\Git\cmd\git.exe -> ...\Git\bin\bash.exe
        $candidates += Join-Path (Split-Path (Split-Path $git.Source -Parent) -Parent) 'bin\bash.exe'
    }
    $candidates += Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    if ($env:LOCALAPPDATA) { $candidates += Join-Path $env:LOCALAPPDATA 'Programs\Git\bin\bash.exe' }
    $bash = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if (-not $bash -or -not (Test-Path $bash)) {
    Write-Output 'ERROR: Git Bash not found. Install Git for Windows or set UJC_BASH=<path to bash.exe>.'
    exit 2
}
# WSL bash (System32\bash.exe) sees Windows paths differently - use Git Bash only
if ($bash -match 'System32') {
    Write-Output "ERROR: $bash is the WSL bash; please use Git Bash (UJC_BASH)."
    exit 2
}

& $bash $script @args
exit $LASTEXITCODE
