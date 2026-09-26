import { setScmLifecycleHooks } from "./scm-hooks";
import { loadScmBindings } from "./scm-native";

export const WINDOWS_SERVICE_RUN_FLAG = "--service-run";

const serviceRunMessage =
  "openllmd: --service-run must be started by the Windows Service Control Manager " +
  "(services.msc or `sc start OpenLLMD`), not from a console.\n";

let scmStopWake: (() => void) | null = null;

export const registerScmStopWake = (wake: () => void): void => {
  scmStopWake = wake;
};

/**
 * SCM entry: call StartServiceCtrlDispatcherW before any heavy daemon init.
 * Does not return on success (process exits from dispatch completion).
 */
export const enterWindowsScmServiceMode = (): void => {
  const scm = loadScmBindings();
  const notScmError = scm.scmErrorNotServiceController();
  let bootFailed = false;

  setScmLifecycleHooks({
    onListening: () => scm.scmReportRunning(),
    onBootFailed: (exitCode) => {
      bootFailed = true;
      scm.scmReportStartFailed(exitCode);
    },
    onShutdownComplete: (exitCode) => scm.scmReportStopped(exitCode),
  });

  const onStart = (): void => {
    void import("./daemon-runtime")
      .then(({ runDaemonMain }) =>
        runDaemonMain({
          scmControlled: true,
        }),
      )
      .catch((error: unknown) => {
        if (!bootFailed) {
          scm.scmReportStartFailed(1);
        }
        process.stderr.write(
          `openllmd: SCM service boot failed: ${
            error instanceof Error ? error.message : String(error)
          }\n`,
        );
      });
  };

  const onStop = (): void => {
    scmStopWake?.();
  };

  scm.scmBindCallbacks(onStart, onStop);
  const dispatchError = scm.scmDispatch();
  setScmLifecycleHooks(null);
  if (dispatchError === notScmError) {
    process.stderr.write(serviceRunMessage);
    process.exit(1);
  }
  if (dispatchError !== 0) {
    process.stderr.write(
      `openllmd: StartServiceCtrlDispatcherW failed (win32 error ${dispatchError}).\n`,
    );
    process.exit(1);
  }
  process.exit(0);
};
