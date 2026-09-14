import { spawnSync as admittedSpawnSync } from "./windows-process";
import { windowsWorkerPath } from '@openllmsh/protocol/local-runtime';
import { stateDir, serviceEnvFilePath } from './env';
import { DAEMON_VERSION } from './version';

const NAME = 'OpenLLMD';
// Bun's Windows execFileSync shim can hang before starting PowerShell in a
// compiled daemon. Use Bun's native process API with bounded execution.
const run = (executable: string, args: string[], timeout: number): string => {
  const result = admittedSpawnSync([executable, ...args], {
    stdin: 'ignore', stdout: 'pipe', stderr: 'pipe', windowsHide: true, timeout,
  });
  if (result.exitCode !== 0) throw new Error(`Windows service helper failed (${result.exitCode})`);
  return result.stdout.toString().trim();
};
const ps = (script: string): string => run('powershell.exe', [
  '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
], 10000);
const sc = (...args: string[]): void => { run('sc.exe', args, 15000); };
const quote = (value: string): string => '"' + value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1') + '"';
const literal = (value: string): string => "'" + value.replaceAll("'", "''") + "'";
const serviceCommand = (binary: string, worker: string): string =>
  [worker, '--service', binary, stateDir(), serviceEnvFilePath()].map(quote).join(' ');

const requireServiceOwnership = (command: string | undefined): void => {
  const worker = windowsWorkerPath(stateDir());
  if (!worker || command !== serviceCommand(process.execPath, worker))
    throw new Error('Existing OpenLLMD service has a different executable or state path');
};

export const windowsSupervisor = (): {registered:boolean;pid:number|null;state:string;command?:string} => {
  try {
    return JSON.parse(ps(`$s=Get-CimInstance Win32_Service -Filter "Name='${NAME}'"; if(-not $s){@{registered=$false;pid=$null;state='not registered'}|ConvertTo-Json -Compress;exit};$p=$null;if($s.ProcessId -gt 0){$p=Get-CimInstance Win32_Process -Filter ("ParentProcessId="+$s.ProcessId)|Where-Object {$_.ExecutablePath -eq ${literal(process.execPath)}}|Select-Object -First 1};@{registered=$true;pid=$(if($p){$p.ProcessId}else{$null});state=($s.State+'; start='+$s.StartMode);command=$s.PathName}|ConvertTo-Json -Compress`));
  } catch { throw new Error('Windows service query unavailable; registration state is unknown'); }
};

export const startWindowsService = (binary: string): void => {
  // This host already runs OpenLLM as SYSTEM. Never silently change a user's
  // security identity or request/store a service-account password.
  if(ps('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value') !== 'S-1-5-18')
    throw new Error('Windows persistent service registration currently requires the existing SYSTEM identity');
  const worker=windowsWorkerPath(stateDir());
  if(!worker)throw new Error('Native Windows worker is missing');
  const version=run(worker,['--version'],3000);
  if(version!==`openllm-windows-worker v${DAEMON_VERSION}`)throw new Error('Native worker release differs from daemon');
  const command=serviceCommand(binary,worker);
  const prior=windowsSupervisor();
  if(prior.registered && prior.command!==command)throw new Error('Existing OpenLLMD service has a different executable or state path');
  if(!prior.registered)sc('create',NAME,'binPath=',command,'start=','auto','obj=','LocalSystem','DisplayName=','OpenLLM Daemon');
  else sc('config',NAME,'start=','auto');
  sc('failure',NAME,'reset=','86400','actions=','restart/10000/restart/30000/restart/60000');
  sc('failureflag',NAME,'1');
  if(!prior.state.startsWith('Running'))sc('start',NAME);
};

export const stopWindowsService = (): void => {
  const prior=windowsSupervisor();if(!prior.registered)return;
  requireServiceOwnership(prior.command);
  sc('config',NAME,'start=','disabled');
  try {
    if(!prior.state.startsWith('Stopped'))sc('stop',NAME);
    const end=Date.now()+20000;
    while(Date.now()<end){if(windowsSupervisor().state.startsWith('Stopped'))return;Bun.sleepSync(100);}
    throw new Error('Windows service did not stop within its deadline');
  } catch (error) {
    // A failed stop must not silently disable automatic recovery.
    sc('config',NAME,'start=',prior.state.includes('start=Auto')?'auto':prior.state.includes('start=Disabled')?'disabled':'demand');
    throw error;
  }
};
export const uninstallWindowsService = (): string|null => {
  if(!windowsSupervisor().registered)return null;
  stopWindowsService();sc('delete',NAME);return NAME;
};
