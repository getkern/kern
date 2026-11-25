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

# THIS RUNS IN THE READER'S OWN SESSION, so the preference has to be GIVEN BACK. The documented
# invocation is `irm ... | iex`, which executes this text in the caller's scope - the same fact the
# note further down records about `exit`. A bare assignment here therefore does not configure "the
# script", it reconfigures the SHELL, and it stays reconfigured after the installer is done: from
# that point every command in that window which writes a single line to stderr becomes a terminating
# error. MEASURED, in a field report: the first `wsl ... kern compose config` run after installing
# died on an INFORMATIONAL line, and the reader had to set `Continue` by hand to get the session back.
#
# `Stop` is kept for the installer itself, where it is load-bearing: a failed step must abort rather
# than carry a broken install forward. It is the LEAK that is the defect, not the setting.
#
# `try`/`finally` and not a `trap`: `try` does NOT create a new scope in PowerShell, so the body
# below keeps script scope exactly as before - every function it defines stays visible to the run
# block at the end, and not one line of it had to be re-indented. Both of this script's exits are
# covered: normal completion, and `throw`, which is the only way it ever fails (it never calls
# `exit`, deliberately, because under `iex` that would close the reader's window).
$KernPrevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Stop'
try {

# By default pull from the LATEST GitHub release (its Windows assets are CI-built, each with a
# `.sha256` beside it and, from 0.52.0 on, a minisign `.minisig`: see Check-Signature);
# pin an exact release with KERN_VERSION=v0.6.5. GitHub's /releases/latest/download/<asset> redirects
# to the newest release's asset of that name.
# A release's tag is `v<version>`: KERN_VERSION may be given with or without the `v`.
# KERN_RELEASE_URL: a mirror holding one release's files (an internal server, an offline copy), with
# KERN_VERSION naming that release. The checks are the same, so a mirror cannot hand over a file the
# release keys did not sign.
if ($env:KERN_RELEASE_URL -and -not $env:KERN_VERSION) { throw "kern: KERN_RELEASE_URL names a mirror: set KERN_VERSION too (the release it holds)." }
# THE VERSION IS ASKED ONCE, and every download then comes from THAT release. `latest` used to be
# resolved here for the signature rule and then again by each download (`releases/latest/download`),
# and once more by Get-TargetVersion: a release published in between made the files name one version
# and the rule expect another, and the install was refused. Unanswered: `latest/download`, treated as
# signed, as before.
$script:TargetVersion = $null
if ($env:KERN_VERSION) {
    $script:TargetVersion = $env:KERN_VERSION -replace '^v', ''
} elseif (-not $env:KERN_RELEASE_URL) {
    try {
        $rel = Invoke-RestMethod -TimeoutSec 8 -Uri 'https://api.github.com/repos/getkern/kern/releases/latest' -UseBasicParsing
        if ($rel.tag_name -match '^v(\d+\.\d+\.\d+)$') { $script:TargetVersion = $Matches[1] }
    } catch { $script:TargetVersion = $null }
}
$RelBase    = if ($env:KERN_RELEASE_URL) { $env:KERN_RELEASE_URL.TrimEnd('/') } elseif ($script:TargetVersion) { "https://github.com/getkern/kern/releases/download/v$($script:TargetVersion)" } else { 'https://github.com/getkern/kern/releases/latest/download' }
# KERN_WSL_DISTRO and KERN_INSTALL_DIR put a trial install somewhere else: another distro name (kern.exe
# reads the same variable at run time) and another folder for kern.exe, so the real installer can be
# run into a throwaway distro without touching the user's `kern`.
$InstallDir = if ($env:KERN_INSTALL_DIR) { $env:KERN_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'kern' }
$DistroName = if ($env:KERN_WSL_DISTRO) { $env:KERN_WSL_DISTRO } else { 'kern' }
$DistroDir  = Join-Path $InstallDir 'distro'
$ExePath    = Join-Path $InstallDir 'kern.exe'
$ExeUrl     = "$RelBase/kern-windows-x86_64.exe"
# The release keys, the same two `kern self-update`, install.sh and scripts/sign-release.sh carry (a
# unit test in crates/kern-cli/src/selfupdate.rs fails if the copies disagree).
$KernReleaseKeys = @('RWSuYG/qtD8AV5p5IzIqfRuCwh5eJlT7ed5+7lVKrgILE1qvIpPGv+Ej', 'RWRLQt2lFPXXsC0g2+1SPfSmOdjpxJ/f+t5DU+xPOaRNjElnisOR0Uo3')
# Which version the signatures must name: the pinned one, or (latest) the one the first signed asset
# names, which every other asset must then name too. And whether this release is one whose Windows
# assets are signed (0.52.0 on): a missing signature there is refused, not skipped.
$script:WantVersion = $null
$script:SignedEra = $true
if ($script:TargetVersion) {
    $script:WantVersion = $script:TargetVersion
    $vp = $script:WantVersion -split '\.'
    if ($vp.Count -eq 3 -and [int]$vp[0] -eq 0 -and [int]$vp[1] -lt 52) {
        $script:SignedEra = $false
    }
}
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

# WHAT WAS CHECKED, file by file, said at the end: a reader must not have to infer from a scrolled-away
# line whether a file was signature-checked, only hash-checked, or taken as it came.
$script:Checks = [ordered]@{}
function Note-Check($what, $state) {
    if ($script:Checks.Contains($what)) { $script:Checks[$what] = "$($script:Checks[$what]); $state" }
    else { $script:Checks[$what] = $state }
}
function Show-Checks {
    if ($script:Checks.Count -eq 0) { return }
    Info "what was checked:"
    foreach ($k in $script:Checks.Keys) { Info "  ${k}: $($script:Checks[$k])" }
}

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
# `$fileNames`: the release asset's own name first, so the files of a release saved next to this
# script are found as they were downloaded; older names after it.
function Resolve-Local($envName, $fileNames) {
    $v = [Environment]::GetEnvironmentVariable($envName)
    if ($v -and (Test-Path $v)) { return $v }
    if ($PSScriptRoot) {
        foreach ($f in @($fileNames)) {
            $beside = Join-Path $PSScriptRoot $f
            if (Test-Path $beside) { return $beside }
        }
    }
    return $null
}

# Download + sha256-verify (each release ships `<asset>.sha256` next to it, same as the Linux side).
# TLS alone is not integrity: a corporate TLS-intercepting proxy or a swapped release asset would
# otherwise hand us an arbitrary exe / rootfs. Local files (dev/offline) skip verification, and
# KERN_SKIP_VERIFY=1 is the explicit escape hatch.
function Fetch($url, $dest, $envName, $fileName, $what, $target) {
    $local = Resolve-Local $envName $fileName
    if ($local) {
        Info "using local ${what}: $local"
        Copy-Item $local $dest -Force
        Note-Check $what 'NOT verified (local file)'
        return
    }
    Info "downloading $what..."
    try { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing }
    catch { Die "could not download $what from $url ($($_.Exception.Message))" }
    if ($env:KERN_SKIP_VERIFY -eq '1') {
        Warn "KERN_SKIP_VERIFY=1 -- skipping checksum for $what"
        Note-Check $what 'NOT verified (KERN_SKIP_VERIFY=1)'
        return
    }
    $shaFile = "$dest.sha256"
    try { Invoke-WebRequest -Uri "$url.sha256" -OutFile $shaFile -UseBasicParsing }
    catch { Die "could not download the checksum for $what ($url.sha256) -- refusing to install unverified. (KERN_SKIP_VERIFY=1 overrides.)" }
    $want = ((Get-Content $shaFile -Raw) -split '\s+')[0].ToLower()
    $got  = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
    Remove-Item $shaFile -ErrorAction SilentlyContinue
    if ($want -ne $got) { Die "checksum MISMATCH for ${what}: expected $want, got $got. Not installing." }
    Info "$what verified (sha256 ok)."
    Note-Check $what 'sha256 ok'
    Check-Signature $dest $url $target $what
}

# One minisign check of a release file, the rules in ONE place for every caller: a valid signature by
# one of the release keys, whose signed comment names this target, this file and (when one is wanted)
# this version. Returns the version on success, or throws with the reason.
function Test-MinisignFile($ms, $file, $sig, $target, $asset) {
    # Local `Continue`: minisign reports a refusal on stderr, which PS 5.1 under `Stop` turns into an
    # error carrying minisign's own words; the reason is said below in ours.
    $ErrorActionPreference = 'Continue'
    $ok = $false
    foreach ($k in $KernReleaseKeys) {
        & $ms.Source -V -q -P $k -m $file -x $sig *> $null
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
    }
    if (-not $ok) { throw "the signature of $asset does not check out with the kern release keys: the file was changed after it was signed, or was signed by someone else" }
    $line = Select-String -Path $sig -Pattern '^trusted comment: (.*)$' | Select-Object -First 1
    $comment = if ($line) { $line.Matches[0].Groups[1].Value } else { '' }
    $words = $comment -split ' '
    if ($words -notcontains "target=$target") { throw "the signature of $asset is valid but names another target ($comment)" }
    if ($words -notcontains "file=$asset") { throw "the signature of $asset is valid but names another file ($comment)" }
    $v = (($words | Where-Object { $_ -like 'version=*' }) -replace '^version=', '') | Select-Object -First 1
    if (-not $v) { throw "the signature of $asset names no version ($comment)" }
    if ($script:WantVersion -and $v -ne $script:WantVersion) { throw "the signature of $asset is valid but names version $v, not $($script:WantVersion)" }
    return $v
}

# One minisign check of a downloaded release file, WITHOUT deciding what to do about the outcome:
# Check-Signature (the files of an install) and Update-DistroBinary (the in-place swap) both ask it,
# so which verifier is used, which version it must name and what a mirror needs are written once.
# The two used to carry their own copy and already differed (a missing signature was fatal in one
# and a fall-back in the other for the same release). State: verified, unchecked, none or refused.
function Get-ReleaseSignature($dest, $url, $target) {
    $asset = ($url -split '/')[-1]
    $sig = "$dest.minisig"
    try { Invoke-WebRequest -Uri "$url.minisig" -OutFile $sig -UseBasicParsing }
    catch { return @{ State = 'none'; Asset = $asset } }
    try {
        $ms = Get-Command minisign.exe -ErrorAction SilentlyContinue
        if ($ms) {
            try { $v = Test-MinisignFile $ms $dest $sig $target $asset }
            catch { return @{ State = 'refused'; Asset = $asset; Why = $_.Exception.Message } }
            if (-not $script:WantVersion) { $script:WantVersion = $v }
            return @{ State = 'verified'; Asset = $asset; Version = $v; By = 'minisign' }
        }
        # NO MINISIGN: the kern that was installed BEFORE this run checks it, with the keys built into
        # it and the same rules as `kern self-update` (see Save-Verifier); a refusal there stops the
        # install. A first install, or a kern too old to check, leaves it unchecked.
        $v = Verify-InDistro $dest $sig $target $asset
        if ($v) {
            if (-not $script:WantVersion) { $script:WantVersion = $v }
            return @{ State = 'verified'; Asset = $asset; Version = $v; By = 'the kern installed before' }
        }
        return @{ State = 'unchecked'; Asset = $asset; Why = $script:VerifierWhyNot }
    } finally {
        Remove-Item $sig -ErrorAction SilentlyContinue
    }
}

# THE SIGNATURE, when minisign is installed (`winget install jedisct1.minisign`). The `.sha256`
# beside a file only proves the download matches a file on the same server; the signature proves the
# file is a release, made with one of the two kern release keys, and its signed comment names this
# file, this target and this version, so an older or another platform's signed file cannot stand in.
# Without minisign it is said and skipped, as on the Linux side.
function Check-Signature($dest, $url, $target, $what) {
    $r = Get-ReleaseSignature $dest $url $target
    switch ($r.State) {
        'none' {
            if ($script:SignedEra) { Die "$what has no signature ($($r.Asset).minisig), and every release from 0.52.0 on signs it. Not installing. If the network dropped, run this again." }
            Info "  ($what predates signed Windows assets: none to check)"
            Note-Check $what 'signature: none (this release predates them)'
        }
        'refused' { Die "$($r.Why). Not installing." }
        'verified' {
            Info "$what signature verified by $($r.By) ($($r.Version))."
            Note-Check $what "signature verified by $($r.By) ($($r.Version))"
        }
        default {
            # A MIRROR IS TRUSTED ONLY THROUGH THE SIGNATURE: what came from it was not served by
            # github.com over its HTTPS, so with nothing able to check the signature there is nothing
            # to trust.
            if ($env:KERN_RELEASE_URL) {
                Die "$what came from the mirror $RelBase and its signature could not be checked ($($r.Why)). A mirror is trusted only through the signatures: install minisign (winget install jedisct1.minisign) and run this again, or install from github.com."
            }
            Info "  (signature of $what not checked: install minisign to check it, e.g. winget install jedisct1.minisign)"
            Note-Check $what "signature NOT verified ($($r.Why)): trusting HTTPS from github.com"
        }
    }
}

# THE VERIFIER IS THE KERN INSTALLED BEFORE THIS RUN, copied out of the distro before anything is
# replaced. Taken at check time it could already be the new binary (the in-place update swaps it before
# kern.exe is fetched), which would be the download vouching for the files it came with.
$script:VerifierPath = $null
$script:VerifierWhyNot = 'first install: no kern installed before to check it'
function Save-Verifier {
    # LOCAL `Continue`: under the script's `Stop`, PowerShell 5.1 turns a native program's stderr
    # behind `2>&1` into a terminating error, and a kern older than 0.52.0 answers this probe on
    # stderr (MEASURED on Windows 10, PS 5.1: every update from 0.51.3 stopped here with exit 1).
    $ErrorActionPreference = 'Continue'
    $names = ((wsl.exe -l -q 2>$null) -replace "`0", '') -split "`r?`n" | ForEach-Object { $_.Trim() }
    if ($names -notcontains $DistroName) { return }
    # A FOLDER OF ITS OWN, random name, made by this script; and the copy's SHA256 recorded now and
    # checked before every use, on Windows and again inside the distro on the very copy that runs. No
    # folder is out of reach of another process of the same user, so the hash is what makes a
    # replacement show: a verifier that changed is not used.
    $dir = Join-Path $env:TEMP ("kern-verifier-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $path = Join-Path $dir 'kern'
    $wpath = (wsl.exe -d $DistroName -- wslpath -u "$($path -replace '\\','/')" 2>$null | Out-String).Trim()
    if (-not $wpath) {
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        $script:VerifierWhyNot = "the '$DistroName' distro does not start"
        return
    }
    # NO SHELL QUOTING ON THE WAY IN: PowerShell 5.1 does not escape a double quote inside an argument to a
    # native program, so `sh -c 'cp "$(command -v kern)" "$1"'` reached the distro cut apart and the copy
    # never happened (MEASURED on Windows 10, PS 5.1). Each step is its own `--exec` with plain arguments.
    $kp = (& wsl.exe -d $DistroName --exec sh -c 'command -v kern' 2>$null | Out-String).Trim()
    if ($kp) { & wsl.exe -d $DistroName --exec cp $kp $wpath *> $null }
    if (-not $kp -or -not (Test-Path $path)) {
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        $script:VerifierWhyNot = "no kern found in the '$DistroName' distro"
        return
    }
    # Does it know the check? 0.52.0 on answers usage (2) to no arguments; an older kern answers 1.
    $probeSha = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    $null = Run-Verifier $wpath $probeSha @()
    if ($script:VerifierCode -ne 2) {
        Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
        $script:VerifierWhyNot = 'the kern installed before is older than 0.52.0 and cannot check signatures'
        return
    }
    $script:VerifierPath = $path
    $script:VerifierDir = $dir
    $script:VerifierSha = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
}

# Run the saved verifier inside the distro (a copy in the distro's /tmp, so a Windows folder's mount
# options cannot stop it from executing). Returns its output; $LASTEXITCODE is its exit code.
function Run-Verifier($wpath, $sha, $vargs) {
    # LOCAL `Continue`: under the script's `Stop`, PowerShell 5.1 turns a native program's stderr
    # behind `2>&1` into a terminating error, and a kern older than 0.52.0 answers this probe on
    # stderr (MEASURED on Windows 10, PS 5.1: every update from 0.51.3 stopped here with exit 1).
    $ErrorActionPreference = 'Continue'
    # One `--exec` per step, arguments passed as they are (see Save-Verifier): a copy in the distro's
    # /tmp, its SHA256 checked against the one recorded when it was saved, then run. KERN_WSL_AS_ROOT=1:
    # a check reads two files and needs no box. The exit code is left in $script:VerifierCode (4: the
    # copy about to run is not the verifier that was saved).
    $script:VerifierCode = 1
    $t = (& wsl.exe -d $DistroName --exec mktemp 2>$null | Out-String).Trim()
    if (-not $t) { return '' }
    try {
        & wsl.exe -d $DistroName --exec cp $wpath $t *> $null
        & wsl.exe -d $DistroName --exec chmod 0755 $t *> $null
        $h = (((& wsl.exe -d $DistroName --exec sha256sum $t 2>$null | Out-String).Trim()) -split '\s+')[0]
        if ($h -ne $sha) { $script:VerifierCode = 4; return '' }
        $out = (& wsl.exe -d $DistroName --exec env KERN_WSL_AS_ROOT=1 $t __verify-release @vargs 2>&1 | Out-String)
        $script:VerifierCode = $LASTEXITCODE
        return $out
    } finally {
        & wsl.exe -d $DistroName --exec rm -f $t *> $null
    }
}

# Check a release file with the saved verifier: its version on success, $null when there is none or
# the distro cannot run it now. A refusal (exit 3) stops the install.
function Verify-InDistro($dest, $sig, $target, $asset) {
    # LOCAL `Continue`: under the script's `Stop`, PowerShell 5.1 turns a native program's stderr
    # behind `2>&1` into a terminating error, and a kern older than 0.52.0 answers this probe on
    # stderr (MEASURED on Windows 10, PS 5.1: every update from 0.51.3 stopped here with exit 1).
    $ErrorActionPreference = 'Continue'
    if (-not $script:VerifierPath -or -not (Test-Path $script:VerifierPath)) { return $null }
    # A VERIFIER THAT CHANGED DURING THE INSTALL is something replacing files under this install: stop.
    if ((Get-FileHash $script:VerifierPath -Algorithm SHA256).Hash.ToLower() -ne $script:VerifierSha) {
        Die "the saved copy of the kern installed before was changed during the install. Not installing."
    }
    $w = (wsl.exe -d $DistroName -- wslpath -u "$($script:VerifierPath -replace '\\','/')" 2>$null | Out-String).Trim()
    $f = (wsl.exe -d $DistroName -- wslpath -u "$($dest -replace '\\','/')" 2>$null | Out-String).Trim()
    $g = (wsl.exe -d $DistroName -- wslpath -u "$($sig -replace '\\','/')" 2>$null | Out-String).Trim()
    if (-not $w -or -not $f -or -not $g) { $script:VerifierWhyNot = "the '$DistroName' distro did not answer"; return $null }
    $vargs = @($f, $g, $target, $asset)
    if ($script:WantVersion) { $vargs += $script:WantVersion }
    $out = Run-Verifier $w $script:VerifierSha $vargs
    $code = $script:VerifierCode
    if ($code -eq 4) { Die "the copy of the kern installed before changed on its way into the '$DistroName' distro. Not installing." }
    if ($code -eq 0 -and $out -match 'verified (\d+\.\d+\.\d+)') { return $Matches[1] }
    if ($code -eq 3) { Die "the kern installed before refused the signature of ${asset}: $($out.Trim()). Not installing." }
    $script:VerifierWhyNot = "the kern installed before could not run the check (exit $code)"
    return $null
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
# The version resolved once at the top (see $script:TargetVersion), never asked again.
function Get-TargetVersion { return $script:TargetVersion }

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
            Note-Check 'the kern in the distro' 'NOT verified (local file)'
        } else {
            try { Invoke-WebRequest -Uri $BinUrl -OutFile $tgz -UseBasicParsing } catch { return $false }
            if ($env:KERN_SKIP_VERIFY -ne '1') {
                try { Invoke-WebRequest -Uri "$BinUrl.sha256" -OutFile "$tgz.sha256" -UseBasicParsing } catch { return $false }
                $want256 = ((Get-Content "$tgz.sha256" -Raw) -split '\s+')[0].ToLower()
                $got256  = (Get-FileHash $tgz -Algorithm SHA256).Hash.ToLower()
                Remove-Item "$tgz.sha256" -ErrorAction SilentlyContinue
                if ($want256 -ne $got256) { return $false }
                # The signature, by the one check every download uses: any doubt (missing in a release that
                # signs, refused, unchecked from a mirror) falls back to the full re-import, which checks
                # the rootfs and stops there if it must.
                $r = Get-ReleaseSignature $tgz $BinUrl 'x86_64-unknown-linux-musl'
                switch ($r.State) {
                    'verified' { Note-Check 'the kern in the distro' "sha256 ok; signature verified by $($r.By) ($($r.Version))" }
                    'none' {
                        if ($script:SignedEra) { return $false }
                        Note-Check 'the kern in the distro' 'sha256 ok; signature: none (this release predates them)'
                    }
                    'unchecked' {
                        if ($env:KERN_RELEASE_URL) { return $false }
                        Note-Check 'the kern in the distro' "sha256 ok; signature NOT verified ($($r.Why)): trusting HTTPS from github.com"
                    }
                    default { return $false }
                }
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
        # FETCHED AND CHECKED WHILE THE OLD DISTRO IS STILL THERE: its kern is the one that checks the
        # new rootfs, and after the unregister there is nothing left to run it in.
        $tar = Join-Path $env:TEMP 'kern-wsl-rootfs.tar.gz'
        Fetch $RootfsUrl $tar 'KERN_ROOTFS_LOCAL' 'kern-wsl-rootfs.tar.gz' 'the kern WSL distro' 'x86_64-wsl-rootfs'
        $script:RootfsFetched = $true
        wsl.exe --unregister $DistroName *> $null
        Remove-Item -Recurse -Force $DistroDir -ErrorAction SilentlyContinue
    }
    $tar = Join-Path $env:TEMP 'kern-wsl-rootfs.tar.gz'
    try {
        if (-not $script:RootfsFetched) {
            Fetch $RootfsUrl $tar 'KERN_ROOTFS_LOCAL' 'kern-wsl-rootfs.tar.gz' 'the kern WSL distro' 'x86_64-wsl-rootfs'
        }
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

# ---- 2b. kern runs boxes as an ordinary user, not root ----------------------
# MEASURED on 2026-11-18: in the distro this installer created, kern ran as root, so a box's uid 0
# was the distro's uid 0 and an escape held every capability, /mnt/c read-write and the other
# distributions' disks. A distro imported from a current rootfs already has the user `kern` and the
# marker that makes kern give root up (crates/kern-cli/src/wslentry.rs); one installed before has
# neither, and its image cache and volumes live under /root. This brings either to the same state,
# idempotently: the user and its uid range, passt (pods had no network without it), root's boxes
# stopped, root's kern state moved to the user with uid 0 shifted to the user's uid ONLY where it is
# 0 (an image layer's other owners sit in the subordinate range, which the user inherits from root),
# the marker, and a restart of the distro so the next command starts clean.
$KernWslSetup = @'
set -u
U=kern
ID=1000
say() { echo "kern: $*"; }
# AN ACCOUNT ALREADY ON UID 1000 IS THE USER. MEASURED on a distro where someone had run `adduser`:
# a second name on the same uid split the identity (the system answers uid 1000 with the first
# name, the uid ranges were written for the second), and every box fell back to a single-uid map.
other=$(awk -F: -v id="$ID" '$3 == id { print $1; exit }' /etc/passwd)
if ! grep -q "^$U:" /etc/passwd && [ -n "$other" ]; then
  U=$other
fi
# The marker holds a plain name only (kern refuses any other): a name it could not hold, no change.
case "$U" in
  ''|*[!a-z0-9_-]*|?????????????????????????????????*)
    say "uid $ID is the account '$U', a name kern's marker cannot hold: kern keeps running as root here"
    exit 0 ;;
esac
# The user, its group and home, and the uid ranges (the user takes root's, root the next one).
grep -q "^$U:" /etc/passwd || echo "$U:x:$ID:$ID:kern:/home/$U:/bin/sh" >> /etc/passwd
grep -q "^$U:" /etc/group || grep -q "^[^:]*:[^:]*:$ID:" /etc/group || echo "$U:x:$ID:" >> /etc/group
grep -q "^$U:" /etc/shadow 2>/dev/null || echo "$U:!::0:::::" >> /etc/shadow
H=$(awk -F: -v u="$U" '$1 == u { print $6; exit }' /etc/passwd)
G=$(awk -F: -v u="$U" '$1 == u { print $4; exit }' /etc/passwd)
case "$H" in /home/?*) ;; *) say "the home of '$U' is '$H', not under /home: kern keeps running as root here"; exit 0 ;; esac
case "$G" in ''|*[!0-9]*) G=$ID ;; esac
mkdir -p "$H" && [ ! -L "$H" ] && chown -h "$ID:$G" "$H"
for f in /etc/subuid /etc/subgid; do
  if ! grep -q "^$U:" "$f" 2>/dev/null; then
    grep -v '^root:' "$f" 2>/dev/null > "$f.new"
    printf '%s:100000:65536\nroot:165536:65536\n' "$U" >> "$f.new"
    mv "$f.new" "$f"
  fi
  # The same range under the uid NUMBER too, which is found whatever name the uid has.
  r=$(grep "^$U:" "$f" | head -1 | cut -d: -f2-)
  grep -q "^$ID:" "$f" || printf '%s:%s\n' "$ID" "$r" >> "$f"
done
# No way back to root from the user: root's password locked, `su` without setuid.
sed -i 's/^root::/root:*:/' /etc/shadow
[ -e /bin/bbsuid ] && chmod u-s /bin/bbsuid
# passt: pods have no network without it. Judged by what is there afterwards, not by apk's status.
command -v pasta >/dev/null 2>&1 || apk add -q passt >/dev/null 2>&1
command -v pasta >/dev/null 2>&1 || say "passt is not installed (no network now?): run 'apk add passt' in the distro"
# zstd (images with zstd-compressed layers) and /etc/localtime (compose files mount it), as a new
# distro has them.
command -v zstd >/dev/null 2>&1 || apk add -q zstd >/dev/null 2>&1
[ -e /etc/localtime ] || { apk add -q tzdata >/dev/null 2>&1; [ -f /usr/share/zoneinfo/UTC ] && ln -sf /usr/share/zoneinfo/UTC /etc/localtime; }
# FILES ON C:\ BELONG TO THE USER BOXES RUN AS, and keep a chown/chmod (drvfs `metadata`). MEASURED on
# 0.51.3: /mnt/c mounted `uid=0`, so a box's root (this user) could neither chown nor chmod a bind
# mount of a project folder on C:\, and a database keeping its data there (Supabase's
# ./volumes/db/data) restarted for hours on `chown: Operation not permitted`. Applied at the restart
# below. An [automount] section someone wrote is theirs: left as it is, and said.
# /etc/wsl.conf: ONE merge routine for every key kern sets there (`ensure_key`), so no edit drops
# another one or a value the user wrote.
# ensure_key <section> <key> <value>: key=value in [section] of $WSLCONF unless the key is already set
# there (a value someone wrote is theirs). Prints `added`, or `kept:<the value found>`.
ensure_key() {
  f="${WSLCONF:-/etc/wsl.conf}"
  [ -f "$f" ] || : > "$f"
  cur=$(awk -v s="[$1]" -v k="$2" '
    /^[ \t]*\[/ { sect = $0; gsub(/[ \t]/, "", sect); ins = (sect == s); next }
    ins && index($0, "=") {
      name = substr($0, 1, index($0, "=") - 1); gsub(/^[ \t]+|[ \t]+$/, "", name)
      if (name == k) { v = substr($0, index($0, "=") + 1); gsub(/^[ \t]+|[ \t]+$/, "", v); print v; exit }
    }' "$f")
  if [ -n "$cur" ]; then echo "kept:$cur"; return 0; fi
  if awk -v s="[$1]" '{ t = $0; gsub(/[ \t]/, "", t); if (t == s) found = 1 } END { exit !found }' "$f"; then
    awk -v s="[$1]" -v line="$2=$3" '{ print; t = $0; gsub(/[ \t]/, "", t); if (t == s) print line }' "$f" > "$f.new" && cat "$f.new" > "$f" && rm -f "$f.new"
  else
    printf '[%s]\n%s=%s\n' "$1" "$2" "$3" >> "$f"
  fi
  echo added
}
# NO WINDOWS PROGRAM FROM INSIDE THE DISTRO ([interop] enabled=false): a process that escapes a box is
# this user, and with interop on it could start cmd.exe or powershell.exe as the Windows user. kern
# uses none (MEASURED with it off: boxes, --gpus, published ports and their names, kern.exe from
# Windows all work). appendWindowsPath=false too: with interop off, Windows' PATH entries would only
# be listed, never run. FILES ON C:\ BELONG TO THE USER BOXES RUN AS and keep a chown/chmod (drvfs
# `metadata`): MEASURED on 0.51.3, /mnt/c mounted uid=0 left a box's root unable to chown a bind of a
# project folder, and a database keeping its data there restarted for hours. Applied at the restart
# below. A value someone wrote is kept, and said.
G=$(awk -F: -v id="$ID" '$3==id{print $4; exit}' /etc/passwd); [ -n "$G" ] || G=$ID
AUTO="metadata,uid=$ID,gid=$G,umask=022"
case "$(ensure_key interop enabled false)" in
  added) say "Windows refuses the programs started from inside the distro (wsl.conf [interop] enabled=false)" ;;
  kept:false) ;;
  kept:*) say "/etc/wsl.conf turns interop on: a process that escapes a box can start Windows programs as you (kern doctor says)" ;;
esac
ensure_key interop appendWindowsPath false >/dev/null
case "$(ensure_key automount options "\"$AUTO\"")" in
  added) say "files on C:\\ now belong to '$U' (the user boxes run as) and keep chown/chmod: wsl.conf [automount] $AUTO" ;;
  "kept:\"$AUTO\"") ;;
  kept:*) say "/etc/wsl.conf has its own [automount] options, left as they are: a box's root may not chown files on C:\\ (kern doctor says)" ;;
esac
# The marker first: the image import below runs kern as the user, which the marker is what decides.
mkdir -p /etc/kern && chmod 755 /etc/kern
printf '%s\n' "$U" > /etc/kern/wsl-user
chmod 644 /etc/kern/wsl-user
chown 0:0 /etc/kern /etc/kern/wsl-user
# THE MIGRATION, resumable: everything below is safe to run again, and only its end writes the
# flag, so a distro stopped halfway finishes on the next run.
# NOTHING THE USER CAN POINT ELSEWHERE IS FOLLOWED AS ROOT. The user `kern` owns its home: a symlink
# it put at ~/.config (to /usr/local/bin, /etc) would make a root `chown` hand that directory over,
# and a hard link to a root file inside its data would make the owner shift hand over the file. So:
# no migration through a symlinked path, `chown -h` everywhere, and a regular file is shifted only
# when it has a single name.
user_paths_safe() {
  for p in "$H" "$H/.local" "$H/.local/share" "$H/.config" \
           "$H/.local/share/kern" "$H/.config/kern"; do
    [ -L "$p" ] && { say "$p is a symbolic link: not migrating through it (remove it and run install.ps1 again)"; return 1; }
  done
  return 0
}
if [ ! -e /etc/kern/wsl-migrated ] && ! user_paths_safe; then
  echo "kern-wsl-setup: ok"
  exit 0
fi
if [ ! -e /etc/kern/wsl-migrated ]; then
  KERN_WSL_AS_ROOT=1 kern stop --all -t 10 >/dev/null 2>&1
  # Data and configuration: moved, then owner/group 0 become the user's, and every file gets its
  # own mode back afterwards, because a chown clears setuid and setgid.
  for rel in .local/share/kern .config/kern; do
    src="/root/$rel"; dst="$H/$rel"
    if [ -d "$src" ] && [ ! -e "$dst" ]; then
      mkdir -p "$(dirname "$dst")"
      mv "$src" "$dst" || continue
    fi
    [ -d "$dst" ] || continue
    [ -L "$dst" ] && continue
    find "$dst" -xdev \( -user 0 -o -group 0 \) \( -type d -o -type l -o -links 1 \) -exec sh -c '
      for f; do
        m=$(stat -c %a "$f"); u=$(stat -c %u "$f"); g=$(stat -c %g "$f")
        [ "$u" = 0 ] && u='"$ID"'
        [ "$g" = 0 ] && g='"$G"'
        chown -h "$u:$g" "$f"
        [ -L "$f" ] || chmod "$m" "$f"
      done' sh {} +
  done
  for d in "$H/.local" "$H/.local/share" "$H/.config"; do
    [ -d "$d" ] && [ ! -L "$d" ] && chown -h "$ID:$G" "$d"
  done
  # Images: NOT moved as files, and not through `kern save`, which flattens a layer's owners to
  # root and strips its setuid bits (MEASURED: debian:bookworm-slim, 11 setuid/setgid files before,
  # 8 after a save/load). Each image is pulled again by the user, so its layers are extracted as on a
  # fresh install, setuid bits and file capabilities included; only an image that cannot be pulled
  # (built here, or no network) falls back to save/load, and says so. An image leaves root's cache
  # only once the user has it; root's cache is removed only when root's own listing is empty.
  if [ -d /root/.cache/kern ]; then
    if refs=$(KERN_WSL_AS_ROOT=1 kern images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null); then
      t=$(mktemp -d /var/tmp/kern-migrate.XXXXXX) && chmod 755 "$t"
      moved=""
      # FIRST every image into the user's cache. Pulled again BY TAG: kern 0.51.1 recorded no
      # digest, so the registry's CURRENT image for that tag is what the user gets (the same as a
      # fresh install would).
      for ref in $refs; do
        case "$ref" in *"<none>"*) continue ;; esac
        if kern pull "$ref" >/dev/null 2>&1; then
          say "image pulled again for the user, by tag (the registry's current $ref): $ref"
        elif KERN_WSL_AS_ROOT=1 kern save "$ref" -o "$t/image.tar" >/dev/null 2>&1 && chmod 644 "$t/image.tar" && kern load -i "$t/image.tar" >/dev/null 2>&1; then
          say "image moved with save/load (it could not be pulled; setuid bits are not kept that way): $ref"
        else
          say "image NOT moved, kept in /root/.cache/kern: $ref"
          rm -f "$t/image.tar"
          continue
        fi
        rm -f "$t/image.tar"
        moved="$moved $ref"
      done
      case "$t" in /var/tmp/kern-migrate.*) rmdir "$t" 2>/dev/null ;; esac
      # THEN out of root's, in rounds: an image another one is built on cannot go while that one is
      # there (MEASURED: alpine:3.20 under a local build stayed, and the migration finished only on a
      # second run). Each round removes what it can; it stops when a round removes nothing.
      for _ in 1 2 3 4 5 6 7 8; do
        before=$(KERN_WSL_AS_ROOT=1 kern images --format '{{.Repository}}' 2>/dev/null | wc -l)
        for ref in $moved; do KERN_WSL_AS_ROOT=1 kern rmi "$ref" >/dev/null 2>&1; done
        after=$(KERN_WSL_AS_ROOT=1 kern images --format '{{.Repository}}' 2>/dev/null | wc -l)
        [ "$after" -lt "$before" ] || break
      done
    fi
    if left=$(KERN_WSL_AS_ROOT=1 kern images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null) && [ -z "$(printf '%s\n' "$left" | grep -v '<none>')" ]; then
      # Root's listing is empty (an unnamed leftover counts as nothing): what is left there is
      # layers no image references.
      case /root/.cache/kern in /root/.cache/kern) rm -rf /root/.cache/kern ;; esac
    else
      say "some images stayed in root's cache: the migration resumes on the next install.ps1 run"
      echo "kern-wsl-setup: ok"
      exit 0
    fi
  fi
  : > /etc/kern/wsl-migrated
  chmod 644 /etc/kern/wsl-migrated
fi
echo "kern-wsl-setup: ok"
'@

function Set-DistroUser {
    $tmp = Join-Path $env:TEMP 'kern-wsl-setup.sh'
    try {
        # LF line endings: the script runs under the distro's sh.
        [IO.File]::WriteAllText($tmp, ($KernWslSetup -replace "`r`n", "`n"))
        $src = (wsl.exe -d $DistroName -- wslpath -u "$($tmp -replace '\\','/')" 2>$null | Out-String).Trim()
        if (-not $src) { Warn "could not reach the setup script from the distro: kern still runs boxes as root there"; return }
        $said = (wsl.exe -d $DistroName -u root -- sh $src 2>&1 | Out-String)
        if ($said -notmatch 'kern-wsl-setup: ok') {
            Warn "setting up the user kern runs boxes as did not finish: $($said.Trim())"
            return
        }
        # WHAT THE SETUP CHANGED, said: its `kern: ...` lines (the user, the images moved, how C:\ is
        # mounted) were only checked for the final ok and never shown.
        foreach ($l in ($said -split "`r?`n")) {
            if ($l -like 'kern: *') { Info ($l -replace '^kern: ', '') }
        }
        # A restart, so no process started as root before the change is left behind, and so the
        # [automount] options apply.
        wsl.exe --terminate $DistroName *> $null
        Info "kern runs its boxes as the distro's ordinary user 'kern'."
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

# ---- 3. shim + PATH ---------------------------------------------------------
function Install-Shim {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Fetch $ExeUrl $ExePath 'KERN_EXE_LOCAL' @('kern-windows-x86_64.exe', 'kern.exe') 'the kern.exe bridge' 'x86_64-pc-windows-gnu'
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
    # FIRST, before anything is replaced: the kern installed now is the one that checks every download.
    Save-Verifier
    try {
        Import-Distro
        Set-DistroUser
        Install-Shim
        if (-not (Verify-Install)) {
            Warn "install NOT verified - nothing above was silently accepted."
        }
        Show-Checks
    } finally {
        if ($script:VerifierDir) { Remove-Item -Recurse -Force $script:VerifierDir -ErrorAction SilentlyContinue }
    }
}
} finally {
    # GIVEN BACK ON EVERY PATH, including the `throw`s above. `Remove-Variable` because the saved
    # value would otherwise be left behind in the reader's session too: this script's scope IS their
    # scope, so every variable it creates is one they did not ask for.
    $ErrorActionPreference = $KernPrevEAP
    Remove-Variable -Name KernPrevEAP -ErrorAction SilentlyContinue
}
