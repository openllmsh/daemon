export type TScmLifecycleHooks = {
  readonly onListening?: () => void;
  readonly onBootFailed?: (exitCode: number) => void;
  readonly onShutdownComplete?: (exitCode: number) => void;
};

let activeHooks: TScmLifecycleHooks | null = null;

export const setScmLifecycleHooks = (
  hooks: TScmLifecycleHooks | null,
): void => {
  activeHooks = hooks;
};

export const notifyScmListening = (): void => {
  activeHooks?.onListening?.();
};

export const notifyScmBootFailed = (exitCode: number): void => {
  activeHooks?.onBootFailed?.(exitCode);
};

export const notifyScmShutdownComplete = (exitCode: number): void => {
  activeHooks?.onShutdownComplete?.(exitCode);
};
