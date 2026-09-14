import { ensureWindowsProcessAdmission } from "./windows-process";

// Loaded before the daemon's application imports: dependency-owned child
// launches inherit the same budget as our explicit public spawn wrappers.
ensureWindowsProcessAdmission();
