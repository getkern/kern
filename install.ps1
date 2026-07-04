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
# pin an exact release with KERN_VERSION=v0.6.2. GitHub's /releases/latest/download/<asset> redirects
# to the newest release's asset of that name.
$RelBase    = if ($env:KERN_VERSION) { "https://github.com/getkern/kern/releases/download/$env:KERN_VERSION" } else { 'https://github.com/getkern/kern/releases/latest/download' }
$InstallDir = Join-Path $env:LOCALAPPDATA 'kern'
$DistroName = 'kern'
$DistroDir  = Join-Path $InstallDir 'distro'
$ExePath    = Join-Path $InstallDir 'kern.exe'
$ExeUrl     = "$RelBase/kern-windows-x86_64.exe"
$RootfsUrl  = "$RelBase/kern-wsl-rootfs.tar.gz"
$ScriptUrl  = 'https://raw.githubusercontent.com/getkern/kern/main/install.ps1'
$RunOnceKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'

function Info($m) { Write-Host "kern: $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "kern: $m" -ForegroundColor Green }
function Warn($m) { Write-Host "kern: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "kern: $m" -ForegroundColor Red; exit 1 }

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
    if ($ready) { return }

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
        exit 0
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
    exit 0
}

# ---- 2. import kern's own distro --------------------------------------------
function Import-Distro {
    $existing = ((wsl.exe -l -q) -replace "`0","") -split "`r?`n" | ForEach-Object { $_.Trim() }
    if ($existing -contains $DistroName) {
        # Present -- but is it HEALTHY? A previous half-import can register a distro that won't run;
        # skipping silently would end in 'done' + every kern command failing.
        wsl.exe -d $DistroName --exec /bin/true *> $null
        if ($LASTEXITCODE -eq 0) {
            Info "distro '$DistroName' already present and healthy -- skipping import. ('wsl --unregister $DistroName' to reinstall)"
            return
        }
        Die "distro '$DistroName' exists but won't start (a previous import may have failed). Run 'wsl --unregister $DistroName', then re-run this installer."
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
    Info "ensured $InstallDir is on your PATH (open a new terminal to pick it up)."
}

# ---- run --------------------------------------------------------------------
Ensure-WslEngine            # may exit here (elevation / reboot); RunOnce resumes us afterwards
Import-Distro
Install-Shim

Info "verifying end-to-end..."
& $ExePath --version
if ($LASTEXITCODE -ne 0) { Warn "kern.exe ran but --version failed -- check 'wsl -l -v'." }
else { Ok "done. Try:  kern box dev --image alpine -it -- sh" }
