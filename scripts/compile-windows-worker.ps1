param([Parameter(Mandatory=$true)][string]$Version, [string]$OutDir)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^\d+\.\d+\.\d+[-a-zA-Z0-9.]*$') { throw 'Invalid release version' }
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }
New-Item -ItemType Directory -Force $OutDir | Out-Null
$source = Join-Path $root 'native\windows-worker.cs'
$generated = Join-Path $OutDir 'windows-worker.generated.cs'
[IO.File]::WriteAllText($generated, [IO.File]::ReadAllText($source).Replace('__OPENLLM_NATIVE_VERSION__', $Version))
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$target = Join-Path $OutDir 'openllm-windows-worker.exe'
& $compiler /nologo /optimize+ /platform:x64 /target:exe /r:System.Web.Extensions.dll /r:System.ServiceProcess.dll "/out:$target" $generated (Join-Path $root 'native\windows-appcontainer.cs')
if ($LASTEXITCODE -ne 0) { throw 'Native Windows worker compilation failed' }
$start=New-Object Diagnostics.ProcessStartInfo
$start.FileName=$target;$start.Arguments='--version';$start.UseShellExecute=$false;$start.CreateNoWindow=$true
$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
$probe=New-Object Diagnostics.Process;$probe.StartInfo=$start
$null=$probe.Start();$probe.StandardInput.Close();$stdout=$probe.StandardOutput.ReadToEndAsync();$stderr=$probe.StandardError.ReadToEndAsync()
if(-not $probe.WaitForExit(5000)){$probe.Kill();$probe.WaitForExit(2000)|Out-Null;throw 'Native Windows worker version deadline'}
$null=$stdout.Wait(2000);$null=$stderr.Wait(2000)
if($probe.ExitCode -ne 0 -or -not $stdout.IsCompleted -or $stdout.Result.Trim() -ne "openllm-windows-worker v$Version"){throw 'Native Windows worker version probe failed'}
Write-Output $stdout.Result.Trim();$probe.Dispose()
Get-FileHash -Algorithm SHA256 $target | Select-Object Path,Hash | ConvertTo-Json -Compress
