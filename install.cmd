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
set "OPENLLM_PATH_STATUS="
for /f "usebackq delims=" %%P in (`""%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$bin=[IO.Path]::Combine($env:USERPROFILE,'.openllm','bin'); $path=[string]$env:Path; if (($path+$bin).IndexOfAny([char[]]@(34,38,10,13)) -ge 0 -or $path.Length+$bin.Length+23 -gt 8191) { 'unsafe'; return }; foreach ($entry in $path.Split(';')) { if ([string]::Equals([Environment]::ExpandEnvironmentVariables($entry.Trim().Trim([char]34)).TrimEnd([char]92,[char]47),$bin,[StringComparison]::OrdinalIgnoreCase)) { 'found'; return } }; 'missing'""`) do set "OPENLLM_PATH_STATUS=%%P"
if "%OPENLLM_PATH_STATUS%"=="found" exit /b 0
if "%OPENLLM_PATH_STATUS%"=="missing" goto append_path
echo Installation finished. CMD PATH was not changed because the update is unsafe or too long. 1>&2
echo Open a new terminal. If needed, shorten PATH and remove quotes and ampersands in Environment Variables. 1>&2
echo Then add the .openllm\bin directory under your user profile to PATH. 1>&2
exit /b 0
:append_path
if not defined PATH goto empty_path
endlocal & set "PATH=%PATH%;%USERPROFILE%\.openllm\bin"
exit /b 0
:empty_path
endlocal & set "PATH=%USERPROFILE%\.openllm\bin"
exit /b 0
