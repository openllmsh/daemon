export type ScopeContext = { platform: string; cgroup: string; runner: string | null; major: number | null; nonce: string };
export type SessionHostLaunch = { command: string[]; scopeName?: string };
export const inServiceCgroup = (cgroup: string): boolean =>
  cgroup.split('\n').some(line => {
    const unit = line.split(':').slice(2).join(':').split('/').at(-1) ?? '';
    return unit.endsWith('.service') && !/^user@\d+\.service$/.test(unit);
  });

/** Ownership only: a device-session scope inherits the caller's restrictions. */
export const planSessionHostLaunch = (command: readonly string[], context: ScopeContext): SessionHostLaunch => {
  if (context.platform !== 'linux' || !inServiceCgroup(context.cgroup)) return { command: [...command] };
  if (!context.runner || context.major === null || context.major < 236 || !/^[a-f0-9]{32}$/.test(context.nonce)) {
    throw new Error('Durable session requires an available systemd user scope');
  }
  const scopeName = 'openllm-session-' + context.nonce + '.scope';
  return { scopeName, command: [context.runner, '--user', '--scope', '--quiet', '--collect',
    ...(context.major >= 254 ? ['--expand-environment=no'] : []), '--unit=' + scopeName, '--', ...command] };
};
