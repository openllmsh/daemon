@echo off
setlocal DisableDelayedExpansion
set "OPENLLM_PRERELEASE_TAG="
if not "%~1"=="" (
  echo This wrapper takes no arguments. Use the tagged installer. 1>&2
  exit /b 1
)
if not defined OPENLLM_PRERELEASE_TAG (
  echo This wrapper has no release tag. Use the tagged prerelease command. 1>&2
  exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy Bypass -NoProfile -Command "$ErrorActionPreference='Stop'; $savedTls=[Net.ServicePointManager]::SecurityProtocol; try { $tag=$env:OPENLLM_PRERELEASE_TAG; if ($tag -cnotmatch '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[A-Za-z][A-Za-z0-9-]*\.(0|[1-9][0-9]*)\z') { throw 'Invalid wrapper tag.' }; [Net.ServicePointManager]::SecurityProtocol=$savedTls -bor [Net.SecurityProtocolType]::Tls12; $r=Invoke-WebRequest -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 60 -ErrorAction Stop -Uri ('https://raw.githubusercontent.com/openllmsh/daemon/'+$tag+'/install.ps1'); if ([int]$r.StatusCode -ne 200) { throw 'Installer download failed.' }; $text=[string]$r.Content; $prefix='$OpenLlmPrereleaseTag = '; $markers=@($text -split '\r?\n' | Where-Object { $_.Trim().StartsWith($prefix) }); if ($markers.Count -ne 1 -or $markers[0].Trim() -cne ($prefix+[char]39+$tag+[char]39)) { throw 'Installer tag does not match the wrapper.' }; iex $text } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 } finally { [Net.ServicePointManager]::SecurityProtocol=$savedTls }"
if errorlevel 1 exit /b %errorlevel%
set "OPENLLM_INSTALL_PATH="
for /f "usebackq delims=" %%P in (`"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$bin=[IO.Path]::Combine($env:USERPROFILE,'.openllm','bin'); $found=$false; foreach ($entry in $env:Path.Split(';')) { if ([string]::Equals([Environment]::ExpandEnvironmentVariables($entry.Trim().Trim([char]34)).TrimEnd([char]92,[char]47),$bin,[StringComparison]::OrdinalIgnoreCase)) { $found=$true; break } }; if ($found) { $env:Path } elseif ($env:Path.EndsWith(';')) { $env:Path+$bin } else { $env:Path+';'+$bin }"`) do set "OPENLLM_INSTALL_PATH=%%P"
if not defined OPENLLM_INSTALL_PATH (
  echo Installation finished. CMD PATH repair failed. Open a new terminal. 1>&2
  exit /b 1
)
endlocal & set "PATH=%OPENLLM_INSTALL_PATH%"
exit /b 0
