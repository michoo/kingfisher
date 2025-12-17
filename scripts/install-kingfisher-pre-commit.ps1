<#!
.SYNOPSIS
  Install or remove Kingfisher Git pre-commit hooks (POSIX-safe).

.DESCRIPTION
  Writes POSIX-compliant shell hooks that work on macOS, Linux,
  and Windows (Git for Windows / sh).
  Safely bootstraps ~/.git/hooks if needed.

.PARAMETER Global
  Install into the global Git hooks directory.

.PARAMETER HooksPath
  Manually override the hooks directory (repo only).

.PARAMETER Uninstall
  Remove the Kingfisher hook and restore a legacy hook if present.
#>

[CmdletBinding()]
param(
    [string]$HooksPath,
    [switch]$Uninstall,
    [switch]$Global
)

function Ensure-GlobalHooksPath {
    $existing = git config --global --get core.hooksPath 2>$null
    if ($existing) {
        return $existing
    }

    # Git expands ~, PowerShell should not
    $gitHooksPath = "~/.git/hooks"
    $fsHooksPath  = Join-Path $HOME ".git\hooks"

    if (-not (Test-Path $fsHooksPath)) {
        New-Item -ItemType Directory -Force -Path $fsHooksPath | Out-Null
    }

    git config --global core.hooksPath $gitHooksPath
    Write-Host "Configured global Git hooks at $gitHooksPath"

    return $gitHooksPath
}

function Resolve-HooksPath {
    param([string]$Override, [switch]$Global)

    if ($Override) {
        $resolved = Resolve-Path -LiteralPath $Override -ErrorAction SilentlyContinue
        if ($resolved) {
            return $resolved.Path
        }
        return [IO.Path]::GetFullPath($Override)
    }

    if ($Global) {
        $configured = git config --global --get core.hooksPath 2>$null
        if ($configured) {
            return $configured
        }
        return Ensure-GlobalHooksPath
    }

    $repoHooks = git rev-parse --git-path hooks 2>$null
    if ($repoHooks) {
        return $repoHooks.Trim()
    }

    $fallback = Join-Path (Get-Location) ".git\hooks"
    Write-Host "Git repository not detected; using fallback hooks path $fallback"
    return $fallback
}

function Uninstall-Kingfisher {
    param($PreCommit, $Legacy, $KFHook, $Marker)

    if (Test-Path $PreCommit) {
        if (Select-String -Quiet -SimpleMatch -Path $PreCommit -Pattern $Marker) {
            if (Test-Path $Legacy) {
                Move-Item -Force $Legacy $PreCommit
                Write-Host "Restored previous pre-commit hook from $Legacy"
            } else {
                Remove-Item -Force $PreCommit
                Write-Host "Removed Kingfisher pre-commit wrapper."
            }
        }
    }

    Remove-Item -Force -ErrorAction SilentlyContinue $KFHook, $Legacy
    Write-Host "Kingfisher pre-commit hook uninstalled."
}

# ------------------------------
# Resolve hooks directory
# ------------------------------
$hooksDir = Resolve-HooksPath -Override $HooksPath -Global:$Global

# Convert ~/.git/hooks to filesystem path if needed
if ($hooksDir -eq "~/.git/hooks") {
    $fsHooksDir = Join-Path $HOME ".git\hooks"
} else {
    $fsHooksDir = $hooksDir
}

if (-not (Test-Path $fsHooksDir)) {
    New-Item -ItemType Directory -Force -Path $fsHooksDir | Out-Null
}

$preCommit = Join-Path $fsHooksDir "pre-commit"
$legacy    = Join-Path $fsHooksDir "pre-commit.legacy.kingfisher"
$kfHook    = Join-Path $fsHooksDir "kingfisher-pre-commit"
$marker    = "# Kingfisher pre-commit wrapper"

# ------------------------------
# Uninstall
# ------------------------------
if ($Uninstall) {
    Uninstall-Kingfisher $preCommit $legacy $kfHook $marker
    return
}

# ------------------------------
# Kingfisher hook (POSIX sh)
# ------------------------------
$kfContent = @'
#!/usr/bin/env sh
set -eu

command -v kingfisher >/dev/null 2>&1 || exit 0

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

kingfisher scan . --staged --quiet --no-update-check
'@

Set-Content -Path $kfHook -Value $kfContent -NoNewline -Encoding ASCII
& chmod +x $kfHook 2>$null | Out-Null

# ------------------------------
# Preserve existing hook
# ------------------------------
if (Test-Path $preCommit) {
    if (-not (Select-String -Quiet -SimpleMatch -Path $preCommit -Pattern $marker)) {
        Move-Item -Force $preCommit $legacy
        & chmod +x $legacy 2>$null | Out-Null
        Write-Host "Existing pre-commit hook preserved at $legacy"
    }
}

# ------------------------------
# Wrapper (POSIX-safe)
# ------------------------------
$wrapper = @'
#!/usr/bin/env sh
# Kingfisher pre-commit wrapper
set -eu

hooks_dir="$(git rev-parse --git-path hooks)"
legacy_hook="$hooks_dir/pre-commit.legacy.kingfisher"
kf_hook="$hooks_dir/kingfisher-pre-commit"

if [ -f "$legacy_hook" ] && [ -x "$legacy_hook" ]; then
  "$legacy_hook" "$@"
fi

"$kf_hook" "$@"
'@

Set-Content -Path $preCommit -Value $wrapper -NoNewline -Encoding ASCII
& chmod +x $preCommit 2>$null | Out-Null

Write-Host "Kingfisher pre-commit hook installed at $preCommit"
if (Test-Path $legacy) {
    Write-Host "Existing hook will run first from $legacy"
}
