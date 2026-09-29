<#
Install the Windows x64 prerelease for the current user.
Use -Prerelease vMAJOR.MINOR.PATCH-LABEL.N with an unstamped source file.
Run openllm start after installation to complete startup.
#>
[CmdletBinding(PositionalBinding = $false)]
param([AllowEmptyString()][string] $Prerelease)

& {
    param([string] $RequestedTag, [bool] $HasRequestedTag)

    $OpenLlmPrereleaseTag = ''
    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 2.0
    $savedTls = [Net.ServicePointManager]::SecurityProtocol
    $stage = $null
    $transactionLock = $null

    function Resolve-PrereleaseTag {
        param([string] $Embedded, [string] $Explicit, [bool] $Supplied)
        $grammar = '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[A-Za-z][A-Za-z0-9-]*\.(0|[1-9][0-9]*)\z'
        if ($Embedded -and $Embedded -cnotmatch $grammar) { throw 'Invalid embedded prerelease tag.' }
        if ($Supplied -and $Explicit -cnotmatch $grammar) { throw 'Invalid -Prerelease value.' }
        if ($Embedded -and $Supplied -and $Embedded -cne $Explicit) { throw '-Prerelease does not match the embedded tag.' }
        if ($Supplied) { return $Explicit }
        if ($Embedded) { return $Embedded }
        throw 'Windows stable installation is not available in this preview. Use the tagged prerelease command.'
    }

    function Assert-SafePath {
        param([string] $Path)
        $current = [IO.Path]::GetFullPath($Path)
        while ($current) {
            # Get attributes directly. Test-Path can hide a dangling link.
            try { $attributes = [IO.File]::GetAttributes($current) }
            catch [IO.FileNotFoundException] { $attributes = 0 }
            catch [IO.DirectoryNotFoundException] { $attributes = 0 }
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Reparse point refused: $current" }
            $parent = [IO.Path]::GetDirectoryName($current)
            if ($parent -eq $current) { break }
            $current = $parent
        }
    }

    function Get-InstallRoot {
        if (Test-Path Env:OPENLLM_DAEMON_STATE_DIR) {
            throw 'OPENLLM_DAEMON_STATE_DIR selects isolated CLI state. Clear it before the user installation. No files were changed.'
        }
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess -or
            $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
            throw 'This installer requires Windows x64 and a 64-bit PowerShell process.'
        }
        # Query the platform. An emulated process can report AMD64 on ARM64.
        $processors = @(Get-CimInstance -ClassName Win32_Processor -Property Architecture -OperationTimeoutSec 5 -ErrorAction Stop)
        if ($processors.Count -eq 0 -or @($processors | Where-Object { $_.Architecture -ne 9 }).Count -ne 0) {
            throw 'This installer requires a native Windows x64 host. ARM64 is not supported.'
        }
        if (-not $env:USERPROFILE -or -not [IO.Path]::IsPathRooted($env:USERPROFILE)) { throw 'USERPROFILE must be an absolute path.' }
        $profile = [IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
        if ($profile.StartsWith('\\')) { throw 'A local user profile is required.' }
        if ($env:HOME -and -not [string]::Equals([IO.Path]::GetFullPath($env:HOME).TrimEnd('\'), $profile, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'HOME conflicts with USERPROFILE. Use the same home for the installer, daemon, and CLI.'
        }
        $root = Join-Path $profile '.openllm'
        Assert-SafePath $root
        return $root
    }

    function New-PrivateDirectory {
        param([string] $Path)
        Assert-SafePath $Path
        $security = New-Object Security.AccessControl.DirectorySecurity
        $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.SetOwner($sid)
        $security.SetAccessRuleProtection($true, $false)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
        $directory = New-Object IO.DirectoryInfo($Path)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            [IO.FileSystemAclExtensions]::Create($directory, $security)
        } else {
            $directory.Create($security)
        }
        Assert-SafePath $Path
    }

    function Receive-ReleaseFile {
        param([uri] $Uri, [string] $Path, [int] $Seconds, [long] $Limit)
        $handler = New-Object Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $false
        $client = New-Object Net.Http.HttpClient($handler)
        $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
        $deadline = New-Object Threading.CancellationTokenSource
        $deadline.CancelAfter($Seconds * 1000)
        try {
            for ($redirect = 0; $redirect -le 5; $redirect++) {
                if ($Uri.Scheme -cne 'https' -or $Uri.UserInfo) { throw 'Only HTTPS release downloads are allowed.' }
                $response = $client.GetAsync($Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $deadline.Token).GetAwaiter().GetResult()
                try {
                    $status = [int]$response.StatusCode
                    if ($status -in @(301, 302, 303, 307, 308)) {
                        if ($redirect -eq 5 -or $null -eq $response.Headers.Location) { throw 'Release redirect limit exceeded.' }
                        $Uri = New-Object Uri($Uri, $response.Headers.Location)
                        continue
                    }
                    if ($status -ne 200) { throw "Release download returned HTTP $status." }
                    if ($response.Content.Headers.ContentLength -gt $Limit) { throw 'Release download is too large.' }
                    $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                    $outputStream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                    try {
                        $buffer = New-Object byte[] 65536
                        [long] $total = 0
                        while (($count = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $deadline.Token).GetAwaiter().GetResult()) -gt 0) {
                            $total += $count
                            if ($total -gt $Limit) { throw 'Release download is too large.' }
                            $outputStream.Write($buffer, 0, $count)
                        }
                        if ($null -ne $response.Content.Headers.ContentLength -and $total -ne $response.Content.Headers.ContentLength) { throw 'Incomplete release download.' }
                        $outputStream.Flush($true)
                    } finally {
                        $outputStream.Dispose()
                        $inputStream.Dispose()
                    }
                    return
                } finally { $response.Dispose() }
            }
        } finally {
            $deadline.Dispose()
            $client.Dispose()
            $handler.Dispose()
        }
    }

    function Read-ReleaseManifest {
        param([string] $Text, [string] $Component, [string] $Tag)
        if ([Text.Encoding]::UTF8.GetByteCount($Text) -gt 65536) { throw 'Manifest exceeds 64 KiB.' }
        # Tokenize data. Never execute manifest text.
        $tokens = New-Object 'Collections.Generic.List[string]'
        $pattern = '\G(?:\s+|\uFEFF|//[^\r\n]*(?:\r?\n|$)|/\*[\s\S]*?\*/|("(?:[^"\\\r\n]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")|([A-Za-z_][A-Za-z_0-9]*)|([{}\[\]:,;=]))'
        $position = 0
        while ($position -lt $Text.Length) {
            # Match from the current position without accepting skipped text.
            $match = [regex]::new($pattern, [Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(1)).Match($Text, $position)
            if (-not $match.Success -or $match.Index -ne $position) { throw 'Invalid manifest syntax.' }
            for ($group = 1; $group -le 3; $group++) {
                if ($match.Groups[$group].Success) { $tokens.Add($match.Groups[$group].Value) }
            }
            $position += $match.Length
        }
        $cursor = @{ Index = 0 }
        function Read-Token {
            if ($cursor.Index -ge $tokens.Count) { throw 'Incomplete manifest.' }
            $value = $tokens[$cursor.Index]
            $cursor.Index++
            return $value
        }
        function Require-Token {
            param([string] $Expected)
            if ((Read-Token) -cne $Expected) { throw "Expected manifest token: $Expected" }
        }
        function Read-String {
            $value = Read-Token
            if (-not $value.StartsWith('"')) { throw 'Expected a manifest string.' }
            return ConvertFrom-Json -InputObject $value
        }
        function Read-Data {
            param([int] $Depth = 0)
            if ($Depth -gt 4) { throw 'Manifest nesting is too deep.' }
            $token = Read-Token
            if ($token.StartsWith('"')) { return ConvertFrom-Json -InputObject $token }
            if ($token -eq '{') {
                $result = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
                while ($tokens[$cursor.Index] -ne '}') {
                    $key = Read-Token
                    if ($key.StartsWith('"')) { $key = ConvertFrom-Json -InputObject $key }
                    elseif ($key -cnotmatch '^[A-Za-z_][A-Za-z_0-9]*$') { throw 'Invalid manifest key.' }
                    if ($result.ContainsKey($key)) { throw "Duplicate manifest key: $key" }
                    Require-Token ':'
                    $result.Add($key, (Read-Data ($Depth + 1)))
                    if ($tokens[$cursor.Index] -eq '}') { break }
                    Require-Token ','
                }
                Require-Token '}'
                return ,$result
            }
            if ($token -eq '[') {
                $items = New-Object 'Collections.Generic.List[object]'
                while ($tokens[$cursor.Index] -ne ']') {
                    $items.Add((Read-Data ($Depth + 1)))
                    if ($tokens[$cursor.Index] -eq ']') { break }
                    Require-Token ','
                }
                Require-Token ']'
                return ,$items.ToArray()
            }
            throw 'Manifest expressions are not allowed.'
        }
        $exportName = 'DAEMON_RELEASE'
        $typeName = 'TDaemonRelease'
        if ($Component -eq 'cli') { $exportName = 'CLI_RELEASE'; $typeName = 'TCliRelease' }
        if ($tokens.Count -eq 0) { throw 'Empty manifest.' }
        if ($tokens[0] -eq 'import') {
            Require-Token 'import'; Require-Token 'type'; Require-Token '{'; Require-Token $typeName
            Require-Token '}'; Require-Token 'from'
            if ((Read-String) -cne './release-types') { throw 'Invalid manifest type import.' }
            Require-Token ';'
        }
        Require-Token 'export'; Require-Token 'const'; Require-Token $exportName
        if ($tokens[$cursor.Index] -eq ':') { Require-Token ':'; Require-Token $typeName }
        Require-Token '='
        $record = Read-Data
        Require-Token ';'
        if ($cursor.Index -ne $tokens.Count) { throw 'Extra manifest statements are not allowed.' }
        if ($record -isnot [Collections.Generic.Dictionary[string,object]] -or $record.Count -ne 4) { throw 'Invalid release object.' }
        foreach ($key in @('repo', 'tag', 'targets', 'sha256')) {
            if (-not $record.ContainsKey($key)) { throw "Missing manifest field: $key" }
        }
        if ($record['repo'] -cne "openllmsh/$Component" -or $record['tag'] -cne $Tag) { throw 'Manifest repository or tag mismatch.' }
        if ($record['targets'] -isnot [object[]] -or $record['sha256'] -isnot [Collections.Generic.Dictionary[string,object]]) { throw 'Invalid manifest targets or digests.' }
        $targets = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($target in $record['targets']) {
            if ($target -isnot [string] -or -not $targets.Add($target)) { throw 'Invalid or duplicate manifest target.' }
        }
        foreach ($entry in $record['sha256'].GetEnumerator()) {
            if (-not $targets.Contains($entry.Key) -or $entry.Value -isnot [string] -or $entry.Value -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid manifest digest.' }
        }
        if (-not $targets.Contains('win32-x64') -or -not $record['sha256'].ContainsKey('win32-x64')) { throw 'Manifest has no Windows x64 digest.' }
        return $record['sha256']['win32-x64'].ToLowerInvariant()
    }

    function Expand-VerifiedImage {
        param([string] $Archive, [string] $Output, [string] $Digest)
        $inputStream = [IO.File]::OpenRead($Archive)
        try {
            if ($inputStream.Length -lt 18 -or $inputStream.ReadByte() -ne 0x1f -or $inputStream.ReadByte() -ne 0x8b -or $inputStream.ReadByte() -ne 8) { throw 'Invalid gzip header.' }
            $inputStream.Position = $inputStream.Length - 4
            $footer = New-Object byte[] 4
            if ($inputStream.Read($footer, 0, 4) -ne 4) { throw 'Incomplete gzip footer.' }
            $expectedSize = [BitConverter]::ToUInt32($footer, 0)
            $inputStream.Position = 0
        } catch { $inputStream.Dispose(); throw }
        $gzip = New-Object IO.Compression.GZipStream($inputStream, [IO.Compression.CompressionMode]::Decompress)
        $outputStream = [IO.File]::Open($Output, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $buffer = New-Object byte[] 65536
            [long] $total = 0
            while (($count = $gzip.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $total += $count
                if ($total -gt 536870912) { throw 'Executable exceeds 512 MiB.' }
                $outputStream.Write($buffer, 0, $count)
            }
            if ($total -ne $expectedSize) { throw 'Incomplete gzip payload.' }
            $outputStream.Flush($true)
        } finally {
            $outputStream.Dispose()
            $gzip.Dispose()
            $inputStream.Dispose()
        }
        if ((Get-FileHash -LiteralPath $Output -Algorithm SHA256).Hash -ine $Digest) { throw 'Executable SHA256 mismatch.' }
        $stream = [IO.File]::OpenRead($Output)
        $reader = New-Object IO.BinaryReader($stream)
        try {
            if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw 'Executable is not PE.' }
            $stream.Position = 0x3c
            $offset = $reader.ReadUInt32()
            if ($offset -lt 64 -or $offset -gt $stream.Length - 26) { throw 'Invalid PE header offset.' }
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Executable is not Windows x64.' }
            $stream.Position = $offset + 24
            if ($reader.ReadUInt16() -ne 0x20b) { throw 'Executable is not PE32+.' }
        } finally { $reader.Dispose(); $stream.Dispose() }
        Unblock-File -LiteralPath $Output -ErrorAction Stop
    }

    function Get-ImageVersion {
        param([string] $Path)
        $process = New-Object Diagnostics.Process
        $process.StartInfo.FileName = $Path
        $process.StartInfo.Arguments = '--version'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        try {
            if (-not $process.Start()) { throw "Version probe did not start: $Path" }
            # Open and retain the process handle before waiting.
            $handle = $process.Handle
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if (-not $process.WaitForExit(10000)) {
                $process.Kill()
                if (-not $process.WaitForExit(2000)) { throw "Version probe cleanup is unconfirmed: $Path" }
                throw "Version probe timed out: $Path"
            }
            if (-not $stdout.Wait(2000) -or -not $stderr.Wait(2000)) { throw "Version probe output did not close: $Path" }
            if ($process.ExitCode -ne 0) { throw "Version probe failed: $Path (exit $($process.ExitCode))" }
            $output = $stdout.Result.Trim()
            $number = '(?:0|[1-9][0-9]*)'
            $identifier = '(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
            $grammar = '^(?:openllmd? v)?(?<version>' + $number + '\.' + $number + '\.' + $number + '(?:-' + $identifier + '(?:\.' + $identifier + ')*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)\z'
            if ($output -cnotmatch $grammar) { throw "Invalid executable version: $Path" }
            return $Matches['version']
        } finally { $process.Dispose() }
    }

    function Compare-Version {
        param([string] $Left, [string] $Right)
        $leftParts = $Left.Split('+')[0].Split(@([char]'-'), 2)
        $rightParts = $Right.Split('+')[0].Split(@([char]'-'), 2)
        $leftCore = $leftParts[0].Split('.')
        $rightCore = $rightParts[0].Split('.')
        function Compare-Number {
            param([string] $A, [string] $B)
            if ($A.Length -ne $B.Length) { return [Math]::Sign($A.Length - $B.Length) }
            return [Math]::Sign([string]::CompareOrdinal($A, $B))
        }
        for ($i = 0; $i -lt 3; $i++) {
            $order = Compare-Number $leftCore[$i] $rightCore[$i]
            if ($order -ne 0) { return $order }
        }
        if ($leftParts.Count -ne $rightParts.Count) { return [Math]::Sign($rightParts.Count - $leftParts.Count) }
        if ($leftParts.Count -eq 1) { return 0 }
        $a = $leftParts[1].Split('.')
        $b = $rightParts[1].Split('.')
        for ($i = 0; $i -lt [Math]::Max($a.Count, $b.Count); $i++) {
            if ($i -ge $a.Count) { return -1 }
            if ($i -ge $b.Count) { return 1 }
            $aNumeric = $a[$i] -cmatch '^(0|[1-9][0-9]*)\z'
            $bNumeric = $b[$i] -cmatch '^(0|[1-9][0-9]*)\z'
            if ($aNumeric -and $bNumeric) { $order = Compare-Number $a[$i] $b[$i] }
            elseif ($aNumeric) { return -1 }
            elseif ($bNumeric) { return 1 }
            else { $order = [Math]::Sign([string]::CompareOrdinal($a[$i], $b[$i])) }
            if ($order -ne 0) { return $order }
        }
        return 0
    }

    function Enter-InstallLock {
        param([string] $Path)
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while ($true) {
            Assert-SafePath $Path
            try { return [IO.File]::Open($Path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
            catch [IO.IOException] {
                if ($timer.ElapsedMilliseconds -ge 10000) { throw 'Another installer holds the transaction lock. Rerun after it finishes.' }
                Start-Sleep -Milliseconds 100
            }
        }
    }

    function Add-ManagedPathEntry {
        param([AllowEmptyString()][string] $Value, [string] $Bin)
        $wanted = $Bin.TrimEnd('\', '/')
        foreach ($entry in $Value.Split(';')) {
            $candidate = [Environment]::ExpandEnvironmentVariables($entry.Trim().Trim('"')).TrimEnd('\', '/')
            if ([string]::Equals($candidate, $wanted, [StringComparison]::OrdinalIgnoreCase)) { return $Value }
        }
        if (-not $Value) { return $Bin }
        if ($Value.EndsWith(';')) { return "$Value$Bin" }
        return "$Value;$Bin"
    }

    function Send-EnvironmentNotification {
        $childScript = @'
# .NET uses SendMessageTimeout with flags 0 and a 1000 ms timeout.
# It does not expose SMTO_ABORTIFHUNG or report a recipient timeout.
# The parent treats a child deadline or a nonzero exit as failure.
try { [Environment]::SetEnvironmentVariable('OPENLLM_ENV_BROADCAST', $null, 'User'); exit 0 } catch { exit 1 }
'@
        $process = New-Object Diagnostics.Process
        $started = $false
        $notified = $false
        $process.StartInfo.FileName = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $process.StartInfo.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        try {
            $started = $process.Start()
            if ($started) {
                $handle = $process.Handle
                if ($process.WaitForExit(5000)) { $notified = $process.ExitCode -eq 0 }
            }
        } catch { $notified = $false }
        finally {
            try {
                if ($started -and -not $process.HasExited) {
                    $grace = [Diagnostics.Stopwatch]::StartNew()
                    # Keep the process handle until the child exits.
                    # Windows PowerShell 5.1 has no tree overload.
                    try {
                        if ($PSVersionTable.PSVersion.Major -ge 7) { $process.Kill($true) }
                        else { $process.Kill() }
                    } catch { if (-not $process.HasExited) { throw } }
                    if (-not $process.WaitForExit([int][Math]::Max(0, 2000 - $grace.ElapsedMilliseconds))) { throw 'Environment notification cleanup is unconfirmed.' }
                }
            } catch {
                # PATH and binaries are committed. Report failed cleanup as a warning.
                $notified = $false
            } finally { $process.Dispose() }
        }
        return $notified
    }

    function Set-ManagedPath {
        param([string] $Bin)
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
        try {
            $key.DeleteValue('OPENLLM_ENV_BROADCAST', $false)
            $value = $key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $kind = [Microsoft.Win32.RegistryValueKind]::ExpandString
            if ($null -ne $value) {
                $kind = $key.GetValueKind('Path')
                if ($kind -notin @([Microsoft.Win32.RegistryValueKind]::String, [Microsoft.Win32.RegistryValueKind]::ExpandString)) { throw 'HKCU Environment Path must be REG_SZ or REG_EXPAND_SZ.' }
            }
            $updated = Add-ManagedPathEntry ([string]$value) $Bin
            if ($updated -cne $value) { $key.SetValue('Path', $updated, $kind); $key.Flush() }
            if ($key.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) -cne $updated -or $key.GetValueKind('Path') -ne $kind) { throw 'The user PATH write could not be verified.' }
            $env:Path = Add-ManagedPathEntry $env:Path $Bin
            if (-not (Send-EnvironmentNotification)) {
                Write-Warning 'Environment notification failed or exceeded the child deadline. The install is complete. Open a new terminal to see the new PATH. Windows does not report recipient timeouts through this API. Sign out and sign in if the command is still unavailable.'
            } else {
                Write-Host 'The environment notification request finished. Windows does not report recipient timeouts through this API. Sign out and sign in if a new terminal cannot find the command.'
            }
        } finally {
            try { $key.DeleteValue('OPENLLM_ENV_BROADCAST', $false) }
            finally { $key.Dispose() }
        }
    }

    function Assert-ReplacementSupported {
        param([object[]] $Images, [string] $Diagnostic = '')
        foreach ($image in $Images) {
            if ($image.Exists -and $image.Replace) {
                # Integration point: P design section 8, replacement transaction.
                # Under the install lock, verify and save task and daemon state.
                # Disable task starts. Stop only the verified daemon.
                # W1b section 9.1: reap_unconfirmed must block replacement.
                # Keep durable sessions alive. Refuse locked images.
                # Retain backups until restart and task restoration succeed.
                # No public installer command is defined by the W1b design yet.
                # A throw preserves interactive callers. File and CMD entry exit 1.
                throw "$Diagnostic Replacement refused (exit code 1). Replacement requires the Windows installer lifecycle interface. This build does not provide it. Stop the running daemon and re-run with a build that provides this interface. The installed files and task state were kept."
            }
        }
    }

    function Install-ImagePair {
        param([object[]] $Images, [string] $Root)
        $journal = Join-Path $Root 'install-transaction.json'
        Assert-SafePath $journal
        if (Test-Path -LiteralPath $journal) { throw "An incomplete transaction exists. Keep its recovery files and repair it before a rerun: $journal" }
        $pending = @($Images | Where-Object { $_.Replace })
        if ($pending.Count -eq 0) { return }
        $record = @($pending | ForEach-Object { @{ Path = $_.Path; Backup = $_.Backup; HadOriginal = $_.Exists } }) | ConvertTo-Json -Depth 4
        $journalStream = [IO.File]::Open($journal, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes($record)
            $journalStream.Write($bytes, 0, $bytes.Length)
            $journalStream.Flush($true)
        } finally { $journalStream.Dispose() }
        $moved = New-Object 'Collections.Generic.List[object]'
        try {
            foreach ($image in $pending) {
                Assert-SafePath $image.Path
                Assert-SafePath $image.Backup
                if ($image.Exists) { [IO.File]::Move($image.Path, $image.Backup) }
                $moved.Add($image)
                [IO.File]::Move($image.Stage, $image.Path)
            }
        } catch {
            $failure = $_
            try {
                for ($i = $moved.Count - 1; $i -ge 0; $i--) {
                    $image = $moved[$i]
                    if ([IO.File]::Exists($image.Path)) { [IO.File]::Delete($image.Path) }
                    if ($image.Exists) { [IO.File]::Move($image.Backup, $image.Path) }
                }
                [IO.File]::Delete($journal)
            } catch { throw "Replacement and rollback failed. Keep recovery files listed in $journal. $($_.Exception.Message)" }
            throw $failure
        }
        # No running daemon is admitted until the lifecycle interface is available.
        [IO.File]::Delete($journal)
    }

    function Complete-Onboarding {
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet('started', 'cancelled', 'deferred', 'failed')]
            [string] $Status,
            [string] $Diagnostic = ''
        )
        # The runtime must report a distinct result after its credential gate.
        # A nonzero process exit does not identify cancellation.
        # This step cannot register tasks or change the installed files.
        switch ($Status) {
            'started' {
                Write-Output 'OpenLLM is installed. Startup is complete.'
                return
            }
            'cancelled' {
                Write-Output 'API key setup was cancelled.'
            }
            'failed' {
                if (-not $Diagnostic) { $Diagnostic = 'The runtime did not report the failed operation.' }
                throw "Startup failed. Verified binaries were kept. $Diagnostic Fix the error, then run openllm start."
            }
            'deferred' {
                if ($Diagnostic) { Write-Output $Diagnostic }
            }
        }
        Write-Output 'OpenLLM is installed. Startup is incomplete. Run openllm start when ready.'
        Write-Output 'Step 2: Run openllm start. Follow the sign-in instructions and enter your API key.'
    }

    try {
        $tag = Resolve-PrereleaseTag $OpenLlmPrereleaseTag $RequestedTag $HasRequestedTag
        $root = Get-InstallRoot
        $bin = Join-Path $root 'bin'
        Assert-SafePath $bin
        if (-not [IO.Directory]::Exists($root)) { New-PrivateDirectory $root }
        $stage = Join-Path $root ('.install-' + [Guid]::NewGuid().ToString('N'))
        New-PrivateDirectory $stage
        [Net.ServicePointManager]::SecurityProtocol = $savedTls -bor [Net.SecurityProtocolType]::Tls12
        Add-Type -AssemblyName System.Net.Http
        $images = @()
        foreach ($component in @('daemon', 'cli')) {
            $name = 'openllmd.exe'
            $asset = 'openllmd-win32-x64.exe.gz'
            if ($component -eq 'cli') { $name = 'openllm.exe'; $asset = 'openllm-win32-x64.gz' }
            $manifestPath = Join-Path $stage "$component.manifest"
            Receive-ReleaseFile "https://raw.githubusercontent.com/openllmsh/$component/$tag/manifest.ts" $manifestPath 60 65536
            $digest = Read-ReleaseManifest ([IO.File]::ReadAllText($manifestPath)) $component $tag
            $archive = Join-Path $stage "$name.gz"
            $imagePath = Join-Path $stage $name
            Receive-ReleaseFile "https://github.com/openllmsh/$component/releases/download/$tag/$asset" $archive 300 536870912
            Expand-VerifiedImage $archive $imagePath $digest
            $images += [pscustomobject]@{ Stage = $imagePath; Path = (Join-Path $bin $name); Backup = (Join-Path $root "$name.rollback"); Digest = $digest; Exists = $false; Replace = $true }
        }
        foreach ($image in $images) {
            if ((Get-ImageVersion $image.Stage) -cne $tag.Substring(1)) { throw 'Downloaded executable version does not match the selected tag.' }
        }
        $transactionLock = Enter-InstallLock (Join-Path $root 'install.lock')
        $journal = Join-Path $root 'install-transaction.json'
        Assert-SafePath $journal
        if (Test-Path -LiteralPath $journal) { throw "An incomplete transaction exists. Keep its recovery files: $journal" }
        foreach ($image in $images) {
            Assert-SafePath $image.Path
            Assert-SafePath $image.Backup
            if (Test-Path -LiteralPath $image.Backup) { throw "A recovery file exists: $($image.Backup)" }
            if (Test-Path -LiteralPath $image.Path -PathType Container) { throw "Executable path is a directory: $($image.Path)" }
            $image.Exists = [IO.File]::Exists($image.Path)
            if ($image.Exists) {
                try { $version = Get-ImageVersion $image.Path }
                catch {
                    Assert-ReplacementSupported @($image) -Diagnostic "Version probe failed for $($image.Path). $($_.Exception.Message)"
                    throw
                }
                if ((Compare-Version $version $tag.Substring(1)) -gt 0) { throw "Downgrade refused: $($image.Path) is $version." }
                $image.Replace = (Get-FileHash -LiteralPath $image.Path -Algorithm SHA256).Hash -ine $image.Digest
            }
        }
        Assert-ReplacementSupported $images
        if (-not [IO.Directory]::Exists($bin)) { New-PrivateDirectory $bin }
        Install-ImagePair $images $root
        try {
            $alias = Join-Path $bin 'ollm.cmd'
            Assert-SafePath $alias
            $aliasText = "@echo off`r`nsetlocal DisableDelayedExpansion`r`n`"%~dp0openllm.exe`" %*`r`nexit /b %errorlevel%`r`n"
            if ([IO.File]::Exists($alias) -and [IO.File]::ReadAllText($alias) -cne $aliasText) { throw "An unmanaged alias exists: $alias" }
            if (-not [IO.File]::Exists($alias)) {
                $aliasStage = Join-Path $stage 'ollm.cmd'
                [IO.File]::WriteAllText($aliasStage, $aliasText, [Text.Encoding]::ASCII)
                [IO.File]::Move($aliasStage, $alias)
            }
            Set-ManagedPath $bin
        } catch { throw "Managed setup failed. Verified binaries were kept. Fix this error and rerun the installer: $($_.Exception.Message)" }
        $transactionLock.Dispose()
        $transactionLock = $null
        # W1 must supply native input and distinct credential results first.
        # The current start command returns 1 for both cancellation and errors.
        Complete-Onboarding -Status 'deferred' -Diagnostic 'Native Windows credential setup is unavailable in this build.'
    } finally {
        if ($null -ne $transactionLock) { $transactionLock.Dispose() }
        [Net.ServicePointManager]::SecurityProtocol = $savedTls
        if ($null -ne $stage -and [IO.Directory]::Exists($stage)) {
            Assert-SafePath $stage
            [IO.Directory]::Delete($stage, $true)
        }
    }
} $Prerelease ($PSBoundParameters.ContainsKey('Prerelease'))
