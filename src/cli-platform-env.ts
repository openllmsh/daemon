import { win32 } from "node:path";

/** Windows runtimes use TEMP/TMP rather than the POSIX TMPDIR selector. */
export const platformTempEnv = (
  tmp: string,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> =>
  platform === "win32" ? { TEMP: tmp, TMP: tmp } : {};

/** Keep native Windows home and app-data lookups inside the isolated CLI home. */
export const platformIsolatedHomeEnv = (
  home: string,
  platform: NodeJS.Platform = process.platform,
): Record<string, string> => {
  if (platform !== "win32") return {};
  return {
    USERPROFILE: home,
    APPDATA: win32.join(home, "AppData", "Roaming"),
    LOCALAPPDATA: win32.join(home, "AppData", "Local"),
    ...(/^[a-z]:[\\/]/i.test(home)
      ? { HOMEDRIVE: home.slice(0, 2), HOMEPATH: home.slice(2) }
      : {}),
  };
};
