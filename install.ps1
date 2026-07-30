# install.ps1 -- PLUG-AND-PLAY, ONE-SHOT Windows installer for kern.
#     irm https://raw.githubusercontent.com/getkern/kern/main/install.ps1 | iex
#
# One command -> kern works immediately. It:
#   1. ensures the WSL2 engine (no Ubuntu needed -- we bring our own distro). If WSL must be enabled it
#      self-elevates (UAC) and resumes automatically after the required reboot.
#   2. imports kern's OWN pre-baked distro (`wsl --import kern`): a tiny Alpine + curl + the kern binary,
#      already inside. No Ubuntu, no curl-in-WSL, no step that can fail.
#   3. drops the kern.exe shim in %LOCALAPPDATA%\kern and puts it on the USER PATH.
#   4. verifies end-to-end.
#
# The shim targets the `kern` distro by default, so `kern ...` just works. Steps 2-4 need no admin.
# Local test: drop kern.exe + kern-wsl-rootfs.tar.gz next to this script (the dist/ bundle does).

$ErrorActionPreference = 'Stop'

# By default pull from the LATEST GitHub release (its Windows assets are CI-built + sha256-signed);
# pin an exact release with KERN_VERSION=v0.6.5. GitHub's /releases/latest/download/<asset> redirects
# to the newest release's asset of that name.
$RelBase    = if ($env:KERN_VERSION) { "https://github.com/getkern/kern/releases/download/$env:KERN_VERSION" } else { 'https://github.com/getkern/kern/releases/latest/download' }
$InstallDir = Join-Path $env:LOCALAPPDATA 'kern'
$DistroName = 'kern'
$DistroDir  = Join-Path $InstallDir 'distro'
$ExePath    = Join-Path $InstallDir 'kern.exe'
$ExeUrl     = "$RelBase/kern-windows-x86_64.exe"
$RootfsUrl  = "$RelBase/kern-wsl-rootfs.tar.gz"
# The standalone static-musl Linux binary (same asset the Linux installer uses) - runs as-is inside the
# Alpine WSL distro, so an UPGRADE can swap just this file and keep the distro's image cache + boxes.
$BinUrl     = "$RelBase/kern-x86_64-unknown-linux-musl.tar.gz"
$ScriptUrl  = 'https://raw.githubusercontent.com/getkern/kern/main/install.ps1'
$RunOnceKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'

function Info($m) { Write-Host "kern: $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "kern: $m" -ForegroundColor Green }
function Warn($m) { Write-Host "kern: $m" -ForegroundColor Yellow }
# `throw`, never `exit`. This script is documented as `irm ... | iex`, so it runs INSIDE the reader's
# shell: `exit` terminates THAT process and their PowerShell window vanishes, taking the message with
# it. Every failure path goes through Die, so every failure used to close the window before it could
# be read. Measured on real PowerShell: with `exit` the calling session dies; with `throw` the script
# stops, the red reason stays, and the prompt returns. Write-Host runs FIRST so the readable line is
# above the exception text.
function Die($m)  { Write-Host "kern: $m" -ForegroundColor Red; throw "kern install aborted: $m" }

# If we are the post-reboot RunOnce resume, our key already fired and is gone -- but ALSO clean up any
# leftover from an earlier aborted run, so an orphaned entry can never re-execute a remote script at
# some future logon (that would be unattended remote code execution of whatever the URL serves then).
Remove-ItemProperty -Path $RunOnceKey -Name 'kern-install' -ErrorAction SilentlyContinue

# How this very invocation can be re-launched (elevation / post-reboot resume). A FILE run re-launches
# the same local file -- so a dist/offline install keeps its local artifacts and pinned version; only a
# true `irm | iex` run resumes from the URL.
function Get-Relaunch {
    if ($PSCommandPath) { return "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" }
    return "-NoProfile -ExecutionPolicy Bypass -Command `"irm $ScriptUrl | iex`""
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# a local file next to the script (or via env) wins over downloading -- for offline/dev/test installs
function Resolve-Local($envName, $fileName) {
    $v = [Environment]::GetEnvironmentVariable($envName)
    if ($v -and (Test-Path $v)) { return $v }
    if ($PSScriptRoot) {
        $beside = Join-Path $PSScriptRoot $fileName
        if (Test-Path $beside) { return $beside }
    }
    return $null
}

# Download + sha256-verify (each release ships `<asset>.sha256` next to it, same as the Linux side).
# TLS alone is not integrity: a corporate TLS-intercepting proxy or a swapped release asset would
# otherwise hand us an arbitrary exe / rootfs. Local files (dev/offline) skip verification, and
# KERN_SKIP_VERIFY=1 is the explicit escape hatch.
function Fetch($url, $dest, $envName, $fileName, $what) {
    $local = Resolve-Local $envName $fileName
    if ($local) { Info "using local ${what}: $local"; Copy-Item $local $dest -Force; return }
    Info "downloading $what..."
    try { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing }
    catch { Die "could not download $what from $url ($($_.Exception.Message))" }
    if ($env:KERN_SKIP_VERIFY -eq '1') { Warn "KERN_SKIP_VERIFY=1 -- skipping checksum for $what"; return }
    $shaFile = "$dest.sha256"
    try { Invoke-WebRequest -Uri "$url.sha256" -OutFile $shaFile -UseBasicParsing }
    catch { Die "could not download the checksum for $what ($url.sha256) -- refusing to install unverified. (KERN_SKIP_VERIFY=1 overrides.)" }
    $want = ((Get-Content $shaFile -Raw) -split '\s+')[0].ToLower()
    $got  = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
    Remove-Item $shaFile -ErrorAction SilentlyContinue
    if ($want -ne $got) { Die "checksum MISMATCH for ${what}: expected $want, got $got. Not installing." }
    Info "$what verified (sha256 ok)."
}

# Idempotent USER-PATH add. SAME semantics as pathtool.ps1 (keep the two in sync): raw registry
# read/write with DoNotExpandEnvironmentNames + ExpandString, so an existing `%USERPROFILE%\bin`
# entry is NOT flattened to a literal path; case-insensitive, trailing-backslash-insensitive de-dup.
function Add-UserPath($dir) {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    try {
        $cur  = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $norm = $dir.TrimEnd('\')
        $parts = @($cur -split ';' | Where-Object { $_ -ne '' -and $_.TrimEnd('\') -ne $norm })
        $k.SetValue('Path', (($parts + $dir) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $k.Close() }
    # broadcast WM_SETTINGCHANGE so NEW terminals see it without a logoff
    $sig = '[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
    $t = Add-Type -MemberDefinition $sig -Name 'Win32SendMessage' -Namespace kern -PassThru
    [UIntPtr]$r = [UIntPtr]::Zero
    $t::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r) | Out-Null
}

# ---- 1. WSL2 engine (NOT a distro -- we bring our own) ------------------------
function Ensure-WslEngine {
    $wslPresent = $false
    try { $null = Get-Command wsl.exe -ErrorAction Stop; $wslPresent = $true } catch { }
    $ready = $false
    if ($wslPresent) { try { wsl.exe --status *> $null; $ready = ($LASTEXITCODE -eq 0) } catch { } }
    if ($ready) { return $true }

    # WSL present but won't start -> not fixable by an installer: BIOS virtualization or org policy.
    if ($wslPresent) {
        Die @"
WSL is installed but won't start. Almost always one of:
  * Virtualization is OFF in BIOS/UEFI     -> enable Intel VT-x / AMD-V, reboot.
  * 'Virtual Machine Platform' feature off -> run as admin:  wsl --install --no-distribution
  * Your org blocks WSL/Hyper-V (locked work PC) -> use a personal machine.
Fix that, then re-run this installer.
"@
    }

    # Not installed at all. Too old for the one-command path?
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 19041) {
        Die "Windows is too old for one-command WSL (build $build; need 19041 / v2004+). Update Windows, then re-run."
    }

    Info "enabling the WSL2 engine (the one step that needs admin + a reboot)..."
    if (-not (Test-Admin)) {
        Info "requesting administrator rights (UAC)..."
        Start-Process powershell -Verb RunAs -ArgumentList (Get-Relaunch) | Out-Null
        Info "continuing in the elevated window - you can close this one."
        return $false
    }
    wsl.exe --install --no-distribution
    if ($LASTEXITCODE -ne 0) {
        Die "'wsl --install' failed - likely BIOS virtualization off or org policy. Enable VT-x/AMD-V + 'Virtual Machine Platform', then re-run."
    }
    # Arm the post-reboot resume ONLY after the install step succeeded -- a failed run must never
    # leave a RunOnce behind that executes a remote script at some future logon.
    New-ItemProperty -Path $RunOnceKey -Name 'kern-install' -Force `
        -Value "powershell $(Get-Relaunch)" | Out-Null
    Warn "WSL2 enabled. REBOOT now; after you log back in, kern's install continues on its own."
    return $false
}

# ---- 2. import kern's own distro --------------------------------------------
# The version this installer targets: KERN_VERSION if pinned, else the latest GitHub release tag.
function Get-TargetVersion {
    if ($env:KERN_VERSION) { return ($env:KERN_VERSION -replace '^v', '') }
    try {
        $t = (Invoke-RestMethod -TimeoutSec 8 https://api.github.com/repos/getkern/kern/releases/latest).tag_name
        return ($t -replace '^v', '')
    } catch { return $null }
}

# Upgrade the kern binary INSIDE the existing distro WITHOUT re-importing it - so the image cache and
# boxes (which live in the distro's own filesystem) survive an update. The pre-baked distro is Alpine
# x86_64, so the standalone static-musl binary runs in it verbatim. Returns $true only when the swap is
# done AND verified; on ANY failure it returns $false and the caller falls back to a full re-import.
function Update-DistroBinary($want) {
    $tgz    = Join-Path $env:TEMP 'kern-bin.tar.gz'
    $binDir = Join-Path $env:TEMP 'kern-bin'
    try {
        # NON-FATAL download + sha256 verify (mirrors Fetch, but returns $false instead of Die-ing - a
        # failed in-place update must FALL BACK to a full re-import, never kill the installer).
        $local = Resolve-Local 'KERN_BIN_LOCAL' 'kern-x86_64-unknown-linux-musl.tar.gz'
        if ($local) {
            Copy-Item $local $tgz -Force
        } else {
            try { Invoke-WebRequest -Uri $BinUrl -OutFile $tgz -UseBasicParsing } catch { return $false }
            if ($env:KERN_SKIP_VERIFY -ne '1') {
                try { Invoke-WebRequest -Uri "$BinUrl.sha256" -OutFile "$tgz.sha256" -UseBasicParsing } catch { return $false }
                $want256 = ((Get-Content "$tgz.sha256" -Raw) -split '\s+')[0].ToLower()
                $got256  = (Get-FileHash $tgz -Algorithm SHA256).Hash.ToLower()
                Remove-Item "$tgz.sha256" -ErrorAction SilentlyContinue
                if ($want256 -ne $got256) { return $false }
            }
        }
        Remove-Item -Recurse -Force $binDir -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Force -Path $binDir | Out-Null
        tar.exe -xzf $tgz -C $binDir
        if ($LASTEXITCODE -ne 0) { return $false }
        $winBin = Join-Path $binDir 'kern'
        if (-not (Test-Path $winBin)) { return $false }
        # Where does kern live inside the distro? (fall back to the conventional path if PATH lookup fails)
        $dest = (wsl.exe -d $DistroName -u root -- sh -lc 'command -v kern' 2>$null | Out-String).Trim()
        if (-not $dest) { $dest = '/usr/local/bin/kern' }
        # The distro's view of the downloaded Windows file, then an atomic in-place swap (keeps the cache).
        # NB: pass the path with FORWARD slashes - `wsl -- wslpath` eats backslashes in a Windows path
        # ("C:\a\b" -> "C:ab"), so a backslashed path returns empty and would wrongly force a re-import.
        $src = (wsl.exe -d $DistroName -- wslpath -u "$($winBin -replace '\\','/')" 2>$null | Out-String).Trim()
        if (-not $src) { return $false }
        wsl.exe -d $DistroName -u root -- sh -c "cp '$src' '$dest.new' && chmod 0755 '$dest.new' && mv -f '$dest.new' '$dest'" *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
        # Verify the swap actually took (else fall back to a clean re-import).
        $now = ([regex]'\d+\.\d+\.\d+').Match(((wsl.exe -d $DistroName --exec kern --version 2>$null) | Out-String)).Value
        return ($now -eq $want)
    } catch { return $false }
    finally {
        Remove-Item -Recurse -Force $binDir -ErrorAction SilentlyContinue
        Remove-Item -Force $tgz -ErrorAction SilentlyContinue
    }
}

function Import-Distro {
    $existing = ((wsl.exe -l -q) -replace "`0","") -split "`r?`n" | ForEach-Object { $_.Trim() }
    if ($existing -contains $DistroName) {
        # Present -- but is it HEALTHY? A previous half-import can register a distro that won't run;
        # skipping silently would end in 'done' + every kern command failing.
        wsl.exe -d $DistroName --exec /bin/true *> $null
        if ($LASTEXITCODE -ne 0) {
            Die "distro '$DistroName' exists but won't start (a previous import may have failed). Run 'wsl --unregister $DistroName', then re-run this installer."
        }
        # Healthy -- but is it CURRENT? Re-running the installer must UPGRADE, not silently keep an old
        # kern. Compare the distro's kern version to the target; re-import only when they differ.
        $have = ([regex]'\d+\.\d+\.\d+').Match(((wsl.exe -d $DistroName --exec kern --version 2>$null) | Out-String)).Value
        $want = Get-TargetVersion
        if (-not ($have -and $want -and $have -ne $want)) {
            Info "distro '$DistroName' already present and up to date$(if ($have) { " (kern $have)" }) -- skipping import."
            return
        }
        Info "kern distro is $have -> upgrading to $want..."
        # Preferred: swap ONLY the binary in place, so the image cache and boxes (which live inside the
        # distro's filesystem) survive the update. Full re-import - which WIPES them - is the fallback.
        if (Update-DistroBinary $want) {
            Info "kern updated to $want in place -- image cache and boxes preserved."
            return
        }
        Warn "in-place update unavailable -- re-importing the distro. Cached images and boxes will be RESET (re-pulled on next use). To keep them, cancel now and run 'wsl --export kern <file.tar>' first."
        wsl.exe --unregister $DistroName *> $null
        Remove-Item -Recurse -Force $DistroDir -ErrorAction SilentlyContinue
    }
    $tar = Join-Path $env:TEMP 'kern-wsl-rootfs.tar.gz'
    try {
        Fetch $RootfsUrl $tar 'KERN_ROOTFS_LOCAL' 'kern-wsl-rootfs.tar.gz' 'the kern WSL distro'
        New-Item -ItemType Directory -Force -Path $DistroDir | Out-Null
        Info "importing the kern distro (wsl --import $DistroName)..."
        wsl.exe --import $DistroName $DistroDir $tar --version 2
        if ($LASTEXITCODE -ne 0) {
            # Never leave PARTIAL state: a half-registered distro / stray vhdx makes every re-run
            # skip-and-break or fail differently. Roll back to zero so re-running just works.
            wsl.exe --unregister $DistroName *> $null
            Remove-Item -Recurse -Force $DistroDir -ErrorAction SilentlyContinue
            Die "wsl --import failed. State rolled back -- check 'wsl --status', free disk space, and re-run."
        }
    } finally {
        Remove-Item $tar -ErrorAction SilentlyContinue
    }
}

# ---- 3. shim + PATH ---------------------------------------------------------
function Install-Shim {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Fetch $ExeUrl $ExePath 'KERN_EXE_LOCAL' 'kern.exe' 'the kern.exe bridge'
    Add-UserPath $InstallDir
    # The registry PATH reaches only NEW processes, so the shell that ran the installer still could not
    # see `kern` - while the next line invited the reader to type exactly that. `iex` runs this script
    # inside their session, so prepending to the in-process PATH fixes it where they are looking.
    if (($env:PATH -split ';') -notcontains $InstallDir) {
        $env:PATH = "$InstallDir;$env:PATH"
    }
    # Belt as well as braces: a global alias to the absolute path cannot be defeated by a policy that
    # rewrites PATH or a profile that resets it. It lives only in this session; a new terminal resolves
    # through the registry entry that Add-UserPath just wrote.
    Set-Alias -Name kern -Value $ExePath -Scope Global -Force -ErrorAction SilentlyContinue
    if (Install-CmdFallback) { Info "wrote a kern.cmd fallback next to it (used only if the exe goes missing)." }
    Info "added $InstallDir to your PATH, usable in this window already."
}


# A `kern.cmd` next to the exe, written ALWAYS and not only after a failure.
#
# PATHEXT resolves .EXE before .CMD, so while kern.exe is present it wins and this file is inert. It
# takes over by itself the moment the exe is gone - which is not hypothetical: an antivirus deleted a
# freshly downloaded, checksum-verified kern.exe on a real machine four times over, and a fallback that
# needs the user to re-run an installer would not have helped somebody whose `kern` broke a week later.
#
# TWO things it cannot do, both stated in the file so whoever opens it knows:
#   - no Windows path translation. The exe rewrites `C:\data` to `/mnt/c/data`; a batch wrapper cannot,
#     so `-v C:\data:/data` has to be written `-v /mnt/c/data:/data` while the exe is unavailable.
#   - it is not a real executable, so a program that spawns `kern` as a process directly (the Python and
#     Node SDKs do) will not find it. Those need the exe.
function Install-CmdFallback {
    $cmdPath = Join-Path $InstallDir 'kern.cmd'
    $lines = @(
        '@echo off',
        'rem kern fallback bridge, written by install.ps1 alongside kern.exe.',
        'rem PATHEXT resolves .EXE before .CMD, so this is inert while kern.exe exists; it takes over',
        'rem automatically if an antivirus removes the unsigned exe.',
        'rem LIMITS, all from cmd.exe being in the path that kern.exe was not:',
        'rem  - no Windows-path translation: write -v /mnt/c/data:/data, not -v C:\data:/data',
        'rem  - cmd.exe re-parses the arguments, so %VAR%, !, ^, & and | are eaten before kern sees them',
        'rem  - Ctrl-C on an interactive box asks "Terminate batch job (Y/N)?" first',
        'rem  - it is not an executable, so anything spawning kern as a process (the Python and Node',
        'rem    SDKs, run from Windows) will not find it: those need kern.exe, or run them inside WSL',
        "wsl.exe -d $DistroName --exec kern %*",
        'exit /b %ERRORLEVEL%'
    )
    # ASCII, no BOM: cmd.exe reads a UTF-8 BOM as part of the first command and fails on `@echo off`.
    [System.IO.File]::WriteAllLines($cmdPath, $lines, (New-Object System.Text.UTF8Encoding($false)))
    return (Test-Path $cmdPath)
}

# ---- verification -----------------------------------------------------------
# Did Defender record a detection naming kern? Absence proves nothing (a third-party AV, or a
# policy that does not log to this API), so callers treat a hit as evidence and a miss as silence.
# One definition because two failure branches need the same answer.
# Which antivirus is actually GUARDING this machine, and can Defender's own exclusion API be used?
# Windows puts Defender in passive mode when a third-party product registers, stopping the WinDefend
# service - and then `Add-MpPreference` fails with 0x800106ba. Suggesting it anyway hands the reader a
# command that cannot work, which is worse than saying nothing: measured on a machine running
# Malwarebytes, where Defender was registered but its service was Stopped.
#
# Returns @{ third = 'Malwarebytes'; defenderUsable = $false }. `third` is '' when Defender is the only
# product. Both fields are best-effort: an AV that does not register with Security Center is invisible
# here, so a caller must not read "no third party" as proof.
function Get-AvSituation {
    $third = @()
    try {
        $third = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
                   Where-Object { $_.displayName -and $_.displayName -notmatch 'Windows Defender' } |
                   ForEach-Object { $_.displayName })
    } catch { }
    $defenderUsable = $false
    try { $defenderUsable = ((Get-Service WinDefend -ErrorAction Stop).Status -eq 'Running') } catch { }
    return @{ third = ($third -join ', '); defenderUsable = $defenderUsable }
}

# The remedy lines for "an antivirus is eating the bridge", written from what is ACTUALLY on the machine
# rather than from an assumption that every Windows host runs Defender. One definition, three callers.
function Warn-AvRemedy {
    $av = Get-AvSituation
    if ($av.third) {
        # Both halves of this sentence are DERIVED. Stating "Defender is in passive mode" as a fixed
        # clause printed it on a machine where Defender was running, and naming one product's menu path
        # printed "In Malwarebytes" to somebody running Avast.
        if ($av.defenderUsable) { Warn "Your antivirus is $($av.third), with Defender also active." }
        else { Warn "Your active antivirus is $($av.third) (Defender is in passive mode)." }
        Warn "Add this folder to its allow list, then re-run this installer:"
        Warn "  $InstallDir"
        if ($av.third -match 'Malwarebytes') {
            Warn "In Malwarebytes: Settings -> Allow List -> Add -> allow a file or folder."
        } else {
            Warn "The setting is usually called Allow List, Exclusions or Exceptions."
        }
        Warn "Its quarantine or detection history should also list kern.exe, which you can restore and"
        Warn "allow from there."
        if ($av.defenderUsable) {
            Warn "For Defender as well:"
            Warn "  Add-MpPreference -ExclusionPath '$InstallDir'    (admin PowerShell)"
        }
    } elseif ($av.defenderUsable) {
        Warn "Allow the folder in an admin PowerShell, then re-run this installer:"
        Warn "  Add-MpPreference -ExclusionPath '$InstallDir'"
    } else {
        Warn "Add this folder to your antivirus allow list, then re-run this installer:"
        Warn "  $InstallDir"
        Warn "(Defender's service is not running, so Add-MpPreference would fail with 0x800106ba.)"
    }
}

function Get-KernDetection {
    try {
        return (Get-MpThreatDetection -ErrorAction Stop |
                Where-Object { $_.Resources -match 'kern' } |
                Select-Object -First 1 -ExpandProperty ThreatID) -join ''
    } catch { return '' }
}

# Does the .cmd companion work? Asked only when the exe cannot answer. A pass here is a REAL working
# install for interactive use, so it returns $true - with the limits named, because a caller who then
# reaches for the Python SDK needs to know the exe is still missing.
# Where to work, said once and used by both success paths. The advice is identical whether the exe
# survived or the .cmd is carrying the install, and writing it twice is how the two drift apart.
#
# It does NOT contradict the `try it` line: an interactive `-it -- sh` pays the crossing ONCE and then you
# are in a shell, so the bridge is exactly right for that. The crossing is per COMMAND, which is why loops,
# scripts, builds and the SDKs want to be on the Linux side of it.
#
# No millisecond figure here: the ones measured belong to one machine, and printing them on someone
# else's would state as general something never measured there.
function Info-FastPath {
    Info "  for loops, scripts and the SDKs, work INSIDE the distro: a command typed in Windows spawns"
    Info "  wsl.exe to cross into it, and that crossing costs more than kern's own work. Inside there is"
    Info "  no crossing, and the SDKs find the Linux binary without needing kern.exe at all."
    Info "    wsl -d $DistroName          then kern ..."
    # The pre-baked distro is a minimal Alpine (kern + curl), so it has no python3/node: saying "run the
    # SDK in here" without saying that would send the reader straight into `python3: not found`.
    Info "  the distro is a minimal Alpine, so for the SDKs add a runtime first: apk add python3 py3-pip"
}

# Nothing on the Windows side answered. The distro is imported and verified, so kern IS installed and
# usable; only the two ways of reaching it from Windows are blocked. Said here and nowhere else, because
# when the fallback works this would be the third overlapping suggestion in one screen.
function Warn-UseWslDirectly {
    Warn "kern itself is installed and verified - only the Windows bridge is unreachable. Use it directly:"
    Warn "  wsl -d $DistroName -- kern box dev --image alpine -it -- sh"
}

function Verify-Fallback {
    $cmdPath = Join-Path $InstallDir 'kern.cmd'
    if (-not (Test-Path $cmdPath)) {
        Warn-UseWslDirectly
        return $false
    }
    $out = Join-Path $env:TEMP 'kern-verify-cmd.txt'
    Remove-Item $out -ErrorAction SilentlyContinue
    $ver = ''
    try {
        $pr = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', "`"$cmdPath`"", '--version' `
                -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -ErrorAction Stop
        if ($pr.ExitCode -eq 0 -and (Test-Path $out)) { $ver = ((Get-Content $out -Raw) + '').Trim() }
    } catch { }
    if ($ver -notmatch '\d+\.\d+\.\d+') {
        Warn "the kern.cmd fallback did not answer either."
        Warn-UseWslDirectly
        return $false
    }
    Ok "the kern.cmd fallback works: $ver"
    Ok "  typing kern in a NEW terminal will work, through WSL, with the identical CLI."
    Warn "  while the exe is missing: write -v /mnt/c/data:/data instead of -v C:\data:/data,"
    Warn "  and the Python/Node SDKs need the exe ONLY when you run them from Windows: they spawn kern"
    Warn "  as a process. Run them inside the distro and they call the Linux binary directly."
    Info-FastPath
    return $true
}

# Returns $true only when typing `kern` actually works. Reports and returns; never `exit`.
function Verify-Install {
    Info "verifying end-to-end..."

    # EXISTENCE first, and never `$LASTEXITCODE` for it: when a path does not exist, `&` raises
    # CommandNotFoundException and leaves $LASTEXITCODE at whatever the PREVIOUS command set, which was
    # 0. The old check read that stale zero and printed "done" for an install that had left nothing
    # behind, so the only symptom was the failure of the next command the reader typed. Measured on
    # Windows 10 PS 5.1: the file was absent while "verified (sha256 ok)" had printed moments earlier.
    if (-not (Test-Path $ExePath)) {
        Warn "kern.exe was downloaded, its checksum verified, and it is no longer on disk:"
        Warn "  $ExePath"
        $det = Get-KernDetection
        if ($det) { Warn "Microsoft Defender recorded a detection naming kern (threat id $det)." }
        # OBSERVATION first, cause second, and named as probable. The file was verified and then was gone:
        # that is what we know. Antivirus is the overwhelmingly likely explanation and the one worth acting
        # on first, but a software-restriction policy that removes or refuses unsigned binaries produces the
        # same observation, and asserting the wrong one sends the reader to the wrong settings page.
        Warn "The checksum matched, so the bytes were intact: something removed it afterwards."
        Warn "Almost always that is antivirus quarantining an unsigned binary. On a managed machine an"
        Warn "AppLocker/WDAC/SRP policy does the same thing."
        Warn-AvRemedy
        return (Verify-Fallback)
    }

    # Judge by what it PRINTS, and when it fails, report WHY. An empty `catch` here told the reader
    # "present but printed nothing" for a file that had been DELETED between the Test-Path above and
    # this line: antivirus removes an unsigned binary within seconds of it being written, so the two
    # checks disagree about a file that existed for both of a few hundred milliseconds. Swallowing the
    # exception turned a precise diagnosis into a wrong one.
    # stdout and stderr captured SEPARATELY, via files, and the verdict read from stdout alone.
    #
    # `& $ExePath --version 2>&1` cannot do this job here: with $ErrorActionPreference = 'Stop' (set at
    # the top of this script) PowerShell 5.1 turns a native command's stderr into a TERMINATING error, so
    # any stderr line lands in the catch and the version never gets read. The shim writes one to stderr on
    # every first run by design ("first run - locating your WSL distro"), which made this print
    # "present but could not be run" for a bridge that worked, on every clean install. Measured twice.
    #
    # Start-Process also hands back a real exit code, which the pipeline form does not for a program that
    # printed nothing.
    $ver = ''
    $why = ''
    $rc = $null
    $outFile = Join-Path $env:TEMP 'kern-verify-out.txt'
    $errFile = Join-Path $env:TEMP 'kern-verify-err.txt'
    Remove-Item $outFile, $errFile -ErrorAction SilentlyContinue
    try {
        $pr = Start-Process -FilePath $ExePath -ArgumentList '--version' -NoNewWindow -Wait -PassThru `
                -RedirectStandardOutput $outFile -RedirectStandardError $errFile -ErrorAction Stop
        $rc = $pr.ExitCode
        if (Test-Path $outFile) { $ver = ((Get-Content $outFile -Raw) + '').Trim() }
        if (Test-Path $errFile) { $stderrText = ((Get-Content $errFile -Raw) + '').Trim() }
    } catch { $why = $_.Exception.Message }
    # A non-zero exit with nothing on stdout is a failure even if stderr said something friendly.
    if ($ver -and $rc -ne 0) { $why = "it printed '$ver' but exited $rc" ; $ver = '' }
    if (-not $ver) {
        if (-not (Test-Path $ExePath)) {
            # NOT a different cause from the branch above: the same removal, observed a moment later,
            # because whatever removes it does so asynchronously. Report when we noticed, not a timeline
            # the evidence does not establish.
            Warn "kern.exe was present a moment ago and is gone now:"
            Warn "  $ExePath"
            Warn "The checksum had matched, so the bytes were intact. Something removes it within seconds"
            Warn "of the download: antivirus in almost every case, or a restriction policy."
            Warn-AvRemedy
        } elseif ($why) {
            Warn "kern.exe is present but could not be run: $why"
        } else {
            # It exists, it ran, it said nothing. Ask the Linux side directly: that separates "the
            # bridge is being blocked" from "the distro is broken", and the two have opposite fixes.
            # Guessing here printed "check the distro" on a machine whose distro was answering
            # perfectly, which sent the reader looking in the one place that was fine.
            $distroSays = ''
            try { $distroSays = (& wsl.exe -d $DistroName --exec kern --version 2>&1 | Out-String).Trim() } catch { }
            if ($distroSays -match '\d+\.\d+\.\d+') {
                Warn "kern.exe is on disk and its checksum matched, but running it produces no output,"
                Warn "while the SAME kern inside WSL answers normally:"
                Warn "  wsl -d $DistroName --exec kern --version   ->  $distroSays"
                Warn "So the Linux side is fine and only the Windows bridge produces no output."
                $det = Get-KernDetection
                if ($det) { Warn "Microsoft Defender recorded a detection naming kern (threat id $det)." }
                # The checksum already ruled out a corrupt download and the release asset is x86_64, so what
                # remains is: something blocking execution (antivirus, or an AppLocker/WDAC/SRP rule) or a
                # missing runtime dependency. Antivirus is the common one and the first worth trying; it is
                # not the only thing that produces silence, and saying so as a fact would be a guess.
                Warn "Something is blocking it from running. Antivirus is by far the most common cause; on a"
                Warn "managed machine an AppLocker/WDAC/SRP rule does the same."
                Warn-AvRemedy
            } else {
                if ($stderrText) { Warn "kern.exe wrote this to stderr: $stderrText" }
                Warn "kern.exe ran and printed nothing on stdout, and the distro did not answer either."
                Warn "  check the distro:  wsl -l -v      (expect '$DistroName')"
                if ($distroSays) { Warn "  it said: $distroSays" }
            }
        }
        # One exit for all three exe failures: the fallback either carries this install or it does not.
        return (Verify-Fallback)
    }
    Info "the bridge answers: $ver"

    # The only check the reader cares about: does the NAME resolve here? Two independent mechanisms
    # were set up for that, so ask the shell rather than trusting either.
    $resolved = Get-Command kern -ErrorAction SilentlyContinue
    if (-not $resolved) {
        Warn "kern.exe works, but the name 'kern' does not resolve in this shell."
        Warn "  run it by path:  & '$ExePath' box dev --image alpine -it -- sh"
        Warn "  a new terminal will pick up the PATH entry just added."
        return $false
    }
    Ok "installed and verified: $ver"
    # `.Source` is empty for an ALIAS, and Install-Shim sets one deliberately - so this line printed
    # "binary:" followed by nothing, which is the one line whose whole job is to say where kern is. An
    # alias keeps its target in `.Definition`; fall back to the known path rather than print a blank.
    $where = $resolved.Source
    if (-not $where) { $where = $resolved.Definition }
    if (-not $where) { $where = $ExePath }
    Ok "  binary:  $where"
    Ok "  try it:  kern box dev --image alpine -it -- sh"
    # Said HERE because this is the line a new user actually reads, and because the alternative is for
    # them to discover it by benchmarking a loop through the bridge and concluding kern is slow.
    Info-FastPath
    return $true
}

# ---- run --------------------------------------------------------------------
# Last, so every function it calls is already defined: PowerShell resolves a call at runtime against
# what the script has defined SO FAR.
#
# `Ensure-WslEngine` answers "may we continue in THIS session?" and says no when the work moves
# elsewhere, to an elevated window or to the post-reboot resume. It used to say that with `exit 0`,
# which under `iex` closed the reader's window on the very line telling them to reboot.
if (Ensure-WslEngine) {
    Import-Distro
    Install-Shim
    if (-not (Verify-Install)) {
        Warn "install NOT verified - nothing above was silently accepted."
    }
}
