# kern uninstaller for Windows.
#
#   irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1 | iex          # shows what it would remove, removes nothing
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1))) -Yes    # actually removes it
#
# Windows installs kern in three places, so removing it is three steps: the WSL distro that holds the
# Linux side (and everything inside it: images, volumes, config), the kern.exe bridge, and the user
# PATH entry pointing at it. Before this file there was no uninstaller at all, on any platform.
#
# A DRY RUN by default. It prints what it found and what it would remove, then stops. `-Yes` performs
# it. A verb that erases a WSL distro without showing you first is one nobody tries in order to find
# out what it does.
#
# Never `exit`: this script is meant to be run as `irm ... | iex`, so it executes inside the caller's
# shell and `exit` would close their PowerShell window, taking the output with it. Measured the hard
# way. Failures report and return.

param(
    [switch]$Yes,
    # Keep the WSL distro (and therefore the image cache, volumes and config inside it) and remove only
    # the Windows-side bridge and PATH entry. For reinstalling the bridge without refetching gigabytes.
    [switch]$KeepDistro
)

# These three MUST match install.ps1. `distro/` lives inside $InstallDir, so removing that folder
# takes the downloaded rootfs with it; the registered distro is separate WSL state and needs its own step.
$DistroName = 'kern'
$InstallDir = Join-Path $env:LOCALAPPDATA 'kern'

function Info($m) { Write-Host "kern: $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "kern: $m" -ForegroundColor Green }
function Warn($m) { Write-Host "kern: $m" -ForegroundColor Yellow }

# Is the distro registered? `wsl -l -q` lists names one per line; WSL emits UTF-16, which is why the
# comparison strips NULs rather than trusting the encoding.
function Get-KernDistro {
    $names = @()
    try { $names = (& wsl.exe -l -q 2>$null) -split "`n" | ForEach-Object { ($_ -replace "`0", '').Trim() } } catch { }
    return ($names | Where-Object { $_ -eq $DistroName } | Select-Object -First 1)
}

# PURE, and separate from the registry on purpose: this is the one computation in the file that can
# silently damage something the user did not ask us to touch. Kept as a function with no I/O so it can
# be asserted directly, rather than restating the same expression in a test and proving nothing.
# Returns $null when $dir is not present, meaning "do not write anything back".
function Remove-PathEntry([string]$cur, [string]$dir) {
    $norm  = $dir.TrimEnd('\')
    $parts = @($cur -split ';' | Where-Object { $_ -ne '' })
    $keep  = @($parts | Where-Object { $_.TrimEnd('\') -ne $norm })
    if ($keep.Count -eq $parts.Count) { return $null }
    return ($keep -join ';')
}

# The USER PATH entry, read from the registry WITHOUT expanding environment names, so an existing
# `%USERPROFILE%\bin` is not flattened into a literal path when we write the value back. Same
# semantics the installer uses to add it.
function Remove-UserPath($dir) {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if (-not $k) { return $false }
    try {
        $cur  = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $keep = Remove-PathEntry $cur $dir
        if ($null -eq $keep) { return $false }
        $k.SetValue('Path', $keep, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally { $k.Close() }
    # Broadcast WM_SETTINGCHANGE, the same way install.ps1 does when it ADDS the entry. Without this,
    # Explorer keeps handing the stale block to every new terminal until a logoff, so the removal would
    # look like it had not happened.
    try {
        $sig = '[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);'
        $t = Add-Type -MemberDefinition $sig -Name 'Win32SendMessageU' -Namespace kernu -PassThru
        [UIntPtr]$r = [UIntPtr]::Zero
        $t::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$r) | Out-Null
    } catch { }
    return $true
}

function Test-UserPathHas($dir) {
    $k = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $false)
    if (-not $k) { return $false }
    try {
        $cur = [string]$k.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        # Asked through the SAME rule that removal uses: "would removal change anything?" is exactly
        # "is it present?", and two spellings of that rule is how they drift apart.
        return ($null -ne (Remove-PathEntry $cur $dir))
    } finally { $k.Close() }
}

function Invoke-Uninstall {
    $distro  = Get-KernDistro
    $hasDir  = Test-Path $InstallDir
    $hasPath = Test-UserPathHas $InstallDir

    if (-not $distro -and -not $hasDir -and -not $hasPath) {
        Ok "nothing to remove - kern is not installed for this user."
        return $true
    }

    Info "found:"
    if ($distro) {
        if ($KeepDistro) {
            Info "  WSL distro '$DistroName' - KEPT (-KeepDistro), with its images, volumes and config"
        } else {
            # Everything the Linux side holds lives inside the distro, so unregistering it is what
            # actually reclaims the space. Say so, because the number is not small.
            Info "  WSL distro '$DistroName' - will be UNREGISTERED: images, volumes and config inside it go with it"
        }
    }
    if ($hasDir)  { Info "  $InstallDir - the kern.exe bridge and the downloaded rootfs" }
    if ($hasPath) { Info "  the user PATH entry for that folder" }

    if (-not $Yes) {
        Write-Host ""
        Warn "nothing was removed. to actually do it:"
        # `irm ... | iex` CANNOT take -Yes: iex receives the script as pipeline input and has no such
        # parameter, so the flag would be a parameter-binding error on iex itself. Turning the text into
        # a scriptblock first is what makes arguments reachable.
        Warn '  & ([scriptblock]::Create((irm https://raw.githubusercontent.com/getkern/kern/main/uninstall.ps1))) -Yes'
        Info "not touched: your other WSL distros, and anything outside the folder above."
        return $true
    }

    $failed = @()

    if ($distro -and -not $KeepDistro) {
        # A running distro can be unregistered, but terminating first makes the failure modes fewer and
        # the error clearer if something holds it.
        try { & wsl.exe --terminate $DistroName 2>$null | Out-Null } catch { }
        try {
            & wsl.exe --unregister $DistroName 2>&1 | Out-Null
            if (Get-KernDistro) { $failed += "the WSL distro '$DistroName' is still registered" }
            else { Ok "unregistered the WSL distro '$DistroName'" }
        } catch { $failed += "wsl --unregister $DistroName : $($_.Exception.Message)" }
    }

    if ($hasDir) {
        try {
            Remove-Item -Recurse -Force $InstallDir -ErrorAction Stop
            Ok "removed $InstallDir"
        } catch { $failed += "$InstallDir : $($_.Exception.Message)" }
    }

    if ($hasPath) {
        if (Remove-UserPath $InstallDir) { Ok "removed the user PATH entry" }
        else { $failed += "could not rewrite the user PATH entry" }
    }

    # This session keeps whatever it resolved at startup, plus the alias the installer may have set.
    if (Get-Alias kern -ErrorAction SilentlyContinue) {
        Remove-Item alias:kern -Force -ErrorAction SilentlyContinue
    }
    $live = Remove-PathEntry $env:PATH $InstallDir
    if ($null -ne $live) { $env:PATH = $live }

    Write-Host ""
    if ($failed.Count -eq 0) {
        Ok "kern is uninstalled."
        Info "a new terminal will no longer see it on PATH; this one already does not."
        return $true
    }
    Warn "some parts could not be removed:"
    foreach ($f in $failed) { Warn "  $f" }
    return $false
}

if (-not (Invoke-Uninstall)) {
    Warn "uninstall INCOMPLETE - nothing above was silently accepted."
}
