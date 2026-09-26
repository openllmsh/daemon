import {
  enterWindowsScmServiceMode,
  WINDOWS_SERVICE_RUN_FLAG,
} from "./windows-scm";

const argv = process.argv.slice(2);

/** True when launched as the registered Windows service (`openllmd --service-run`). */
export const windowsScmServiceMode =
  process.platform === "win32" && argv[0] === WINDOWS_SERVICE_RUN_FLAG;

if (windowsScmServiceMode) {
  enterWindowsScmServiceMode();
}
