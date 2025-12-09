<#!
.SYNOPSIS
  Install or remove Kingfisher Git pre-commit hooks (local or global).

.DESCRIPTION
  Supports repo installs, global installs (via core.hooksPath), and
  custom hook directories. Preserves existing hooks safely and provides
  uninstall behavior mirroring the Bash installer.

.PARAMETER Global
  Install into the global Git hooks directory.

.PARAMETER HooksPath
  Manually override the hooks directory.

.PARAMETER Uninstall
  Remove the Kingfisher hook and restore a legacy hook if present.
#>

[CmdletBinding()]
param(
    [string]$HooksPath,
    [switch]$Uninstall,
    [switch]$Global
)

function Ensure-InRepo {
    if (-not $Global -and -not (git rev-parse --is-inside-work-tree 2>$null)) {
        throw "This installer must be run inside a Git repository unless --Global is specified."
    }
}

function Resolve-HooksPath {
    param([string]$Override, [switch]$Global)

    # Explicit override wins
    if ($Override) {
        return (Resolve-Path $Override).Path
    }

    # Global mode
    if ($Global) {
        $p = git config --global core.hooksPath 2>$null
        if (-not $p) {
            # Default global hooks directory
            $p = Join-Path $HOME ".git-hooks"
            git config --global core.hooksPath $p
            Write-Host "Configured global Git hooks at $p"
        }
        return $p
    }

    # Repo mode
    $repoHooks = git rev-parse --git-path hooks 2>$null
    if (-not $repoHooks) { throw "Unable to resolve repository hooks path." }
    return $repoHooks.Trim()
}

function Uninstall-Kingfisher {
    param(
        [string]$PreCommit,
        [string]$Legacy,
        [string]$KFHook,
        [string]$Marker
    )

    # Only try to inspect hook if it exists
    if (Test-Path $PreCommit) {
        # Only restore if this is our wrapper
        if (Select-String -Quiet -SimpleMatch -Path $PreCommit -Pattern $Marker) {
            if (Test-Path $Legacy) {
                Move-Item -Force $Legacy $PreCommit
                & chmod +x $PreCommit 2>$null | Out-Null
                Write-Host "Restored previous pre-commit hook from $Legacy"
            }
            else {
                Remove-Item -Force $PreCommit
                Write-Host "Removed Kingfisher pre-commit wrapper."
            }
        }
    }

    # Always clean up wrapper + legacy
    Remove-Item -Force -ErrorAction SilentlyContinue $KFHook, $Legacy
    Write-Host "Kingfisher pre-commit hook uninstalled."
}

Ensure-InRepo

# Determine hooks directory safely
$hooksDir = Resolve-HooksPath -Override $HooksPath -Global:$Global

if (-not (Test-Path $hooksDir)) {
    New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null
}

$preCommit = Join-Path $hooksDir "pre-commit"
$legacy    = Join-Path $hooksDir "pre-commit.legacy.kingfisher"
$kfHook    = Join-Path $hooksDir "kingfisher-pre-commit"
$marker    = "# Kingfisher pre-commit wrapper"

if ($Uninstall) {
    Uninstall-Kingfisher -PreCommit $preCommit -Legacy $legacy -KFHook $kfHook -Marker $marker
    return
}

# ---- Kingfisher hook ----
$kfContent = @"
#!/usr/bin/env bash
set -euo pipefail

if ! command -v kingfisher >/dev/null 2>&1; then
  echo "Kingfisher is not on PATH; skipping scan." >&2
  exit 0
fi

repo_root="\$(git rev-parse --show-toplevel)"
cd "\$repo_root"

kingfisher scan . --staged --quiet --redact --only-valid --no-update-check
"@

# ---- Wrapper ----
# Note: No dirname logic here — absolute paths only
$wrapper = @"
#!/usr/bin/env bash
$marker
set -euo pipefail

legacy_hook="$legacy"
kingfisher_hook="$kfHook"

if [[ -f "\$legacy_hook" && -x "\$legacy_hook" ]]; then
  "\$legacy_hook" "\$@"
fi

"\$kingfisher_hook" "\$@"
"@

# Write inner Kingfisher hook
Set-Content -Path $kfHook -Value $kfContent -NoNewline
& chmod +x $kfHook 2>$null | Out-Null

# Preserve existing hook ONLY if it exists
if (Test-Path $preCommit) {
    # And if it's not our wrapper
    if (-not (Select-String -Quiet -SimpleMatch -Path $preCommit -Pattern $marker)) {
        Move-Item -Force $preCommit $legacy
        & chmod +x $legacy 2>$null
        Write-Host "Existing pre-commit hook preserved at $legacy"
    }
}

# Write wrapper
Set-Content -Path $preCommit -Value $wrapper -NoNewline
& chmod +x $preCommit 2>$null | Out-Null

Write-Host "Kingfisher pre-commit hook installed at $preCommit"
if (Test-Path $legacy) {
    Write-Host "Existing hook will run first from $legacy"
}
