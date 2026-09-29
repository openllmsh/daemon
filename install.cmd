@echo off
setlocal DisableDelayedExpansion
set "ERRORLEVEL="
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
set "OPENLLM_INSTALL_STATUS=%ERRORLEVEL%"
if not "%OPENLLM_INSTALL_STATUS%"=="0" exit /b %OPENLLM_INSTALL_STATUS%
set "OPENLLM_PATH_STATUS="
for /f "usebackq delims=" %%P in (`""%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -EncodedCommand JABiAGkAbgA9AFsASQBPAC4AUABhAHQAaABdADoAOgBDAG8AbQBiAGkAbgBlACgAJABlAG4AdgA6AFUAUwBFAFIAUABSAE8ARgBJAEwARQAsACcALgBvAHAAZQBuAGwAbABtACcALAAnAGIAaQBuACcAKQA7ACAAJABwAGEAdABoAD0AWwBzAHQAcgBpAG4AZwBdACQAZQBuAHYAOgBQAGEAdABoADsAIABpAGYAIAAoACQAYgBpAG4ALgBDAG8AbgB0AGEAaQBuAHMAKAAnADsAJwApACAALQBvAHIAIAAoACQAcABhAHQAaAArACQAYgBpAG4AKQAuAEkAbgBkAGUAeABPAGYAQQBuAHkAKABbAGMAaABhAHIAWwBdAF0AQAAoADMANAAsADMAOAAsADEAMAAsADEAMwAsADMAMwAsADMANwApACkAIAAtAGcAZQAgADAAIAAtAG8AcgAgACQAcABhAHQAaAAuAEwAZQBuAGcAdABoACsAJABiAGkAbgAuAEwAZQBuAGcAdABoACsAMgAzACAALQBnAHQAIAA4ADEAOQAxACkAIAB7ACAAJwB1AG4AcwBhAGYAZQAnADsAIAByAGUAdAB1AHIAbgAgAH0AOwAgAGYAbwByAGUAYQBjAGgAIAAoACQAZQBuAHQAcgB5ACAAaQBuACAAQAAoACQAcABhAHQAaAAuAFMAcABsAGkAdAAoACcAOwAnACkAKQApACAAewAgAGkAZgAgACgAWwBzAHQAcgBpAG4AZwBdADoAOgBFAHEAdQBhAGwAcwAoAFsARQBuAHYAaQByAG8AbgBtAGUAbgB0AF0AOgA6AEUAeABwAGEAbgBkAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABWAGEAcgBpAGEAYgBsAGUAcwAoACQAZQBuAHQAcgB5AC4AVAByAGkAbQAoACkALgBUAHIAaQBtACgAWwBjAGgAYQByAF0AMwA0ACkAKQAuAFQAcgBpAG0ARQBuAGQAKABbAGMAaABhAHIAXQA5ADIALABbAGMAaABhAHIAXQA0ADcAKQAsACQAYgBpAG4ALABbAFMAdAByAGkAbgBnAEMAbwBtAHAAYQByAGkAcwBvAG4AXQA6ADoATwByAGQAaQBuAGEAbABJAGcAbgBvAHIAZQBDAGEAcwBlACkAKQAgAHsAIAAnAGYAbwB1AG4AZAAnADsAIAByAGUAdAB1AHIAbgAgAH0AIAB9ADsAIAAnAG0AaQBzAHMAaQBuAGcAJwA="`) do set "OPENLLM_PATH_STATUS=%%P"
if "%OPENLLM_PATH_STATUS%"=="found" exit /b 0
if "%OPENLLM_PATH_STATUS%"=="missing" goto append_path
echo Installation finished. CMD PATH was not changed because the update is unsafe or too long. 1>&2
echo Open a new terminal. If needed, shorten PATH and remove quotes, ampersands, exclamation marks, and percent signs in Environment Variables. 1>&2
echo If your profile directory contains a semicolon, run the commands by their full paths or use a profile directory without a semicolon. 1>&2
echo Otherwise, add the .openllm\bin directory under your user profile to PATH. 1>&2
exit /b 0
:append_path
if not defined PATH goto empty_path
endlocal & set "PATH=%PATH%;%USERPROFILE%\.openllm\bin"
exit /b 0
:empty_path
endlocal & set "PATH=%USERPROFILE%\.openllm\bin"
exit /b 0
