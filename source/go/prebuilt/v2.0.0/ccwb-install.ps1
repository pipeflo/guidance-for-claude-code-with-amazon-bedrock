# Claude Code Authentication Installer for Windows (generic)
param(
    [string]$ScriptDir = (Split-Path -Parent $MyInvocation.MyCommand.Path)
)

$ErrorActionPreference = 'Stop'
Set-Location $ScriptDir

Write-Host '======================================'
Write-Host 'Claude Code Authentication Installer'
Write-Host '======================================'
Write-Host ''

# Check prerequisites
Write-Host 'Checking prerequisites...'
$hasErrors = $false

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Host 'ERROR: AWS CLI is not installed'
    Write-Host '       Please install from https://aws.amazon.com/cli/'
    $hasErrors = $true
}

if (-not (Test-Path 'config.json')) {
    Write-Host 'ERROR: config.json not found in current directory'
    Write-Host '       Make sure you are running this from the extracted package folder'
    $hasErrors = $true
}

if (-not (Test-Path 'credential-process-windows.exe')) {
    Write-Host 'ERROR: credential-process-windows.exe not found'
    Write-Host '       The package may be incomplete or corrupted'
    $hasErrors = $true
}

if ($hasErrors) {
    Read-Host 'Press Enter to exit'
    exit 1
}

if (-not (Test-Path 'claude-settings/settings.json')) {
    Write-Host 'WARNING: claude-settings/settings.json not found'
    Write-Host '         Claude Code IDE settings will not be configured automatically'
    Write-Host ''
}

Write-Host 'OK Prerequisites validated'
Write-Host ''

# Create directory
Write-Host 'Installing authentication tools...'
$installDir = Join-Path $env:USERPROFILE 'claude-code-with-bedrock'
if (-not (Test-Path $installDir)) { New-Item -ItemType Directory -Path $installDir -Force | Out-Null }

# Copy credential process
Write-Host 'Copying credential process...'
Copy-Item -Force 'credential-process-windows.exe' (Join-Path $installDir 'credential-process.exe')

# Copy OTEL helper if it exists
if (Test-Path 'otel-helper-windows.exe') {
    Write-Host 'Copying OTEL helper...'
    Copy-Item -Force 'otel-helper-windows.exe' (Join-Path $installDir 'otel-helper.exe')
}

# Copy configuration
Write-Host 'Copying configuration...'
Copy-Item -Force 'config.json' $installDir

# Install Claude Code settings
$claudeDir = Join-Path $env:USERPROFILE '.claude'
if (Test-Path 'claude-settings/settings.json') {
    Write-Host ''
    Write-Host 'Installing Claude Code settings...'
    if (-not (Test-Path $claudeDir)) { New-Item -ItemType Directory -Path $claudeDir -Force | Out-Null }

    $doWrite = $true
    $settingsTarget = Join-Path $claudeDir 'settings.json'
    if (Test-Path $settingsTarget) {
        Write-Host 'Existing Claude Code settings found'
        $backupName = "settings.json.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $backupPath = Join-Path $claudeDir $backupName
        Copy-Item $settingsTarget $backupPath
        Write-Host "  Backed up to: $backupPath"
        $answer = Read-Host 'Overwrite with new settings? (Y/n)'
        if ($answer -and $answer -ne 'y' -and $answer -ne 'Y') {
            $doWrite = $false
            Write-Host 'Skipping Claude Code settings...'
        }
    }

    if ($doWrite) {
        $otelPath = ((Join-Path $installDir 'otel-helper.exe') -replace '\\', '/')
        $credPath = ((Join-Path $installDir 'credential-process.exe') -replace '\\', '/')
        $settings = Get-Content 'claude-settings/settings.json' -Raw | ConvertFrom-Json
        if ($settings.otelHeadersHelper) {
            $settings.otelHeadersHelper = "`"$otelPath`""
        }
        if ($settings.awsAuthRefresh) {
            $settings.awsAuthRefresh = $settings.awsAuthRefresh -replace '__CREDENTIAL_PROCESS_PATH__', "`"$credPath`""
        }
        $settings | ConvertTo-Json -Depth 10 | Set-Content -Encoding UTF8 $settingsTarget

        $settingsContent = Get-Content $settingsTarget -Raw
        if ($settingsContent -match '__CREDENTIAL_PROCESS_PATH__|__OTEL_HELPER_PATH__') {
            Write-Host 'WARNING: Some path placeholders were not replaced in settings.json'
            Write-Host "         You may need to edit the file manually: $settingsTarget"
        } else {
            Write-Host "OK Claude Code settings configured: $settingsTarget"
        }
    }
} else {
    Write-Host ''
    Write-Host 'WARNING: No claude-settings/settings.json found in package'
    Write-Host '         Skipping Claude Code IDE settings configuration'
}

# Configure AWS profiles
Write-Host ''
Write-Host 'Configuring AWS profiles...'
$configJson = Get-Content 'config.json' | ConvertFrom-Json
$profiles = $configJson.PSObject.Properties.Name

foreach ($p in $profiles) {
    Write-Host "Configuring AWS profile: $p"
    $region = $configJson.$p.aws_region
    if (-not $region) { $first = $profiles | Select-Object -First 1; $region = $configJson.$first.aws_region; if (-not $region) { $region = 'us-east-1' } }
    $credExe = (Join-Path $installDir 'credential-process.exe') -replace '\\', '/'
    $awsConfigDir = Join-Path $env:USERPROFILE '.aws'
    if (-not (Test-Path $awsConfigDir)) { New-Item -ItemType Directory -Path $awsConfigDir -Force | Out-Null }
    $awsConfigFile = Join-Path $awsConfigDir 'config'
    $profileBlock = "[profile $p]`ncredential_process = `"$credExe`" --profile $p`nregion = $region`n"
    if (Test-Path $awsConfigFile) {
        $lines = Get-Content $awsConfigFile
        $newLines = @()
        $skipSection = $false
        foreach ($line in $lines) {
            if ($line -match "^\[profile $p\]") {
                $skipSection = $true
                continue
            }
            if ($skipSection -and $line -match '^\[') {
                $skipSection = $false
            }
            if (-not $skipSection) {
                $newLines += $line
            }
        }
        while ($newLines.Count -gt 0 -and $newLines[-1] -eq '') { $newLines = $newLines[0..($newLines.Count-2)] }
        if ($newLines.Count -gt 0) {
            $newContent = ($newLines -join "`n") + "`n`n" + $profileBlock
        } else {
            $newContent = $profileBlock
        }
    } else {
        $newContent = $profileBlock
    }
    [System.IO.File]::WriteAllText($awsConfigFile, $newContent)
    Write-Host "  OK Created AWS profile '$p'"
}

# Optional: install PowerShell `claude` function for GDPR per-zone isolation.
# Only runs when the bundle was packaged with enforce_project_isolation=true
# (so config.json has zone_inference_profiles). Other installs skip this
# block entirely and nothing touches the user's $PROFILE.
$firstProfileName = $profiles | Select-Object -First 1
$firstProfileCfg = $configJson.$firstProfileName
# Simple truthiness: missing property -> $null (falsy), false -> falsy,
# true -> truthy. Avoids the PSObject.Properties.Match quirk that returns
# zero on PSCustomObjects from ConvertFrom-Json in some PS versions.
Write-Host ''
Write-Host ('[debug] first profile: ' + $firstProfileName + '; enforce_project_isolation: ' + $firstProfileCfg.enforce_project_isolation)
if ($firstProfileCfg.enforce_project_isolation) {
    Write-Host ''
    Write-Host 'Installing Claude Code wrapper for per-zone inference profile isolation...'

    $wrapperFile = Join-Path $installDir 'claude-wrapper.ps1'
    $credExePs = (Join-Path $installDir 'credential-process.exe')
    $modelShort = $firstProfileCfg.model_short_name
    if (-not $modelShort) { $modelShort = 'opus-4-6' }
    $awsRegion = $firstProfileCfg.aws_region
    if (-not $awsRegion) { $awsRegion = 'us-east-1' }
    $zmap = $firstProfileCfg.zone_inference_profiles

    # Build the `switch` arms from the zone -> ARN map at install time.
    $switchArms = foreach ($zoneProp in $zmap.PSObject.Properties) {
        $zone = $zoneProp.Name
        $arn  = $zoneProp.Value.$modelShort
        if ($arn) { "        '$zone' { $" + "arn = '$arn' }" }
    }
    $switchBody = ($switchArms -join "`n")

    $wrapperContent = @"
# Generated by ccwb-install.ps1. Do not edit by hand.
# Regenerated on every re-install. Safe to dot-source multiple times.

Remove-Item Env:ANTHROPIC_MODEL -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_SMALL_FAST_MODEL -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue

function global:claude {
    [CmdletBinding()]
    param([Parameter(ValueFromRemainingArguments=`$true)] `$Args)
    `$zone = & '$credExePs' --profile $firstProfileName --get-tag Zone 2>`$null
    if (`$LASTEXITCODE -ne 0 -or -not `$zone) {
        Write-Error "Claude Code: no Zone assignment found on your Okta token. Ask your administrator to add you to a $firstProfileName-<zone>-<project> group."
        return
    }
    `$arn = `$null
    switch (`$zone.Trim()) {
$switchBody
        default {
            Write-Error "Claude Code: zone '`$zone' has no inference profile mapping. Ask your administrator to run: ccwb inference-profile create --zone `$zone --model $modelShort"
            return
        }
    }
    # Find the actual claude binary on PATH, bypassing this function so we
    # don't recurse. Claude Code installs as claude.exe on Windows (not
    # claude.cmd); use Get-Command -CommandType Application to match any
    # executable extension (.exe/.cmd/.bat) regardless of how the CLI was
    # installed (Bun, npm global, scoop, winget, etc.).
    `$claudeApp = Get-Command -CommandType Application -Name claude -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not `$claudeApp) {
        Write-Error "Claude Code binary not found on PATH. Install Claude Code first (e.g. 'npm install -g @anthropic-ai/claude-code')."
        return
    }
    # CLAUDE_CODE_USE_BEDROCK, AWS_REGION, and AWS_PROFILE must be in the
    # process env at the moment Claude Code starts, not only in settings.json.
    # Claude Code decides Bedrock-vs-API mode from its own env at init time;
    # settings.json.env is applied after that decision and only to child
    # processes Claude Code spawns. Without these explicit exports, the
    # Linux/Mac banner shows "API Usage Billing" mode and Bedrock routing
    # never engages — ANTHROPIC_MODEL from the wrapper becomes dead code.
    `$previousUseBedrock = `$env:CLAUDE_CODE_USE_BEDROCK
    `$previousRegion     = `$env:AWS_REGION
    `$previousProfile    = `$env:AWS_PROFILE
    `$env:CLAUDE_CODE_USE_BEDROCK = '1'
    `$env:AWS_REGION = '$awsRegion'
    `$env:AWS_PROFILE = '$firstProfileName'
    `$env:ANTHROPIC_MODEL = `$arn
    try {
        & `$claudeApp.Source @Args
    } finally {
        Remove-Item Env:ANTHROPIC_MODEL -ErrorAction SilentlyContinue
        if (`$null -ne `$previousUseBedrock) { `$env:CLAUDE_CODE_USE_BEDROCK = `$previousUseBedrock } else { Remove-Item Env:CLAUDE_CODE_USE_BEDROCK -ErrorAction SilentlyContinue }
        if (`$null -ne `$previousRegion)     { `$env:AWS_REGION = `$previousRegion }             else { Remove-Item Env:AWS_REGION -ErrorAction SilentlyContinue }
        if (`$null -ne `$previousProfile)    { `$env:AWS_PROFILE = `$previousProfile }           else { Remove-Item Env:AWS_PROFILE -ErrorAction SilentlyContinue }
    }
}
"@
    Set-Content -Path $wrapperFile -Value $wrapperContent -Encoding UTF8

    # Ensure the user's PowerShell profile exists and dot-sources the wrapper.
    if (-not (Test-Path $PROFILE)) {
        New-Item -ItemType File -Path $PROFILE -Force | Out-Null
    }
    $marker = '# >>> ccwb claude wrapper >>>'
    $profileContent = if (Test-Path $PROFILE) { Get-Content $PROFILE -Raw } else { '' }
    if (-not $profileContent -or -not $profileContent.Contains($marker)) {
        $block = @"

# >>> ccwb claude wrapper >>>
# GDPR per-zone inference-profile isolation. Managed by ccwb-install.ps1.
# Re-running the installer regenerates the sourced file; `ccwb cleanup`
# removes this block and the wrapper file together.
if (Test-Path '$wrapperFile') { . '$wrapperFile' }
# <<< ccwb claude wrapper <<<
"@
        Add-Content -Path $PROFILE -Value $block
        Write-Host "  Added ccwb claude wrapper block to $PROFILE"
    } else {
        Write-Host "  ccwb claude wrapper block already present in $PROFILE (wrapper file refreshed)"
    }
    Write-Host "  Wrapper written to $wrapperFile"
    Write-Host '  Restart PowerShell or run: . $PROFILE'
}

# Post-install validation
Write-Host ''
Write-Host 'Validating installation...'
$credBinary = Join-Path $installDir 'credential-process.exe'
if (Test-Path $credBinary) {
    Write-Host "  OK credential-process.exe: $credBinary"
} else {
    Write-Host "  FAIL credential-process.exe not found at: $credBinary"
}
$settingsFile = Join-Path (Join-Path $env:USERPROFILE '.claude') 'settings.json'
if (Test-Path $settingsFile) {
    Write-Host "  OK settings.json: $settingsFile"
} else {
    Write-Host "  WARN settings.json not found at: $settingsFile"
}

Write-Host ''
Write-Host '======================================'
Write-Host 'Installation complete!'
Write-Host '======================================'
Write-Host ''
Write-Host 'Available profiles:'
foreach ($p in $profiles) { Write-Host "  - $p" }
Write-Host ''
Write-Host 'To use Claude Code authentication:'
Write-Host '  set AWS_PROFILE=<profile-name>'
Write-Host '  aws sts get-caller-identity'
Write-Host ''
$first = $profiles | Select-Object -First 1
Write-Host "Example:"
Write-Host "  set AWS_PROFILE=$first"
Write-Host '  aws sts get-caller-identity'
Write-Host ''
Write-Host 'Note: Authentication will automatically open your browser when needed.'
