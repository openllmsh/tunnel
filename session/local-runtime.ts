/** OS primitives shared by the daemon and its independently compiled CLI. */

import { dlopen, FFIType, ptr } from "bun:ffi";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { observeDarwinProcess } from "./dir-lock-process";
import {
  createWindowsSessionDirectory,
  createWindowsSessionFile,
  secureAndVerifyWindowsSessionDirectory,
} from "./windows-session-pipe";

export const executableName = (
  name: string,
  platform = process.platform,
): string => (platform === "win32" ? `${name}.exe` : name);

export const SESSION_HOST_STARTUP_GRACE_MS = 10_000;

/**
 * Windows durable sessions use the current process, a per-user secured state
 * directory, and an in-process named pipe. There is no helper executable.
 */
export const sessionHostSupported = (
  platform = process.platform,
  architecture = process.arch,
): boolean =>
  platform === "linux" ||
  platform === "darwin" ||
  (platform === "win32" && architecture === "x64");

export const WINDOWS_SESSION_HOST_UNAVAILABLE =
  "windows-session-host-unavailable";

export const processStartCommand = (pid: number): string[] => {
  if (!Number.isSafeInteger(pid) || pid <= 0)
    throw new Error("invalid process id");
  if (process.platform === "win32")
    throw new Error("Windows process identity is read through Win32 FFI");
  return ["ps", "-o", "lstart=", "-p", String(pid)];
};

export type TProcessIdentity = "alive" | "dead" | "unknown";

export type TProcessStartIdentityReader = (
  pid: number,
) => string | null | undefined;

/**
 * The ONE canonical form for a `ps lstart`-style start identity. BSD `ps`
 * space-pads the day (`%e`: "Sep  6") while parsers that split on whitespace
 * collapse it to "Sep 6" — a raw-string compare then fails for the first nine
 * days of every month and a session teardown quietly matches no members
 * (DR-4). Every producer (ps output, /proc reconstruction, persisted
 * meta.json) and every comparison normalizes through this helper.
 */
export const normalizeProcessStartIdentity = (value: string): string =>
  value.trim().split(/\s+/).join(" ");

const PS_LSTART_WEEKDAYS = [
  "Sun",
  "Mon",
  "Tue",
  "Wed",
  "Thu",
  "Fri",
  "Sat",
] as const;
const PS_LSTART_MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
] as const;

const pad2 = (value: number): string => String(value).padStart(2, "0");

/**
 * Format a Date exactly like `ps -o lstart=` under LC_ALL=C TZ=UTC:
 * `%a %b %e %T %Y` ("Sun Sep  6 12:34:56 2026", day space-padded). Kept in
 * padded form so the raw output is byte-identical to ps; consumers normalize
 * through {@link normalizeProcessStartIdentity} before comparing.
 */
const formatPsLstartUtc = (date: Date): string =>
  `${PS_LSTART_WEEKDAYS[date.getUTCDay()]} ${
    PS_LSTART_MONTHS[date.getUTCMonth()]
  } ${String(date.getUTCDate()).padStart(2, " ")} ${pad2(
    date.getUTCHours(),
  )}:${pad2(date.getUTCMinutes())}:${pad2(
    date.getUTCSeconds(),
  )} ${date.getUTCFullYear()}`;

// /proc/<pid>/stat reports starttime in USER_HZ jiffies — a fixed 100 on every
// architecture Linux exposes /proc for, regardless of CONFIG_HZ.
const LINUX_USER_HZ = 100;

/**
 * Linux start identities are boot-scoped and monotonic (RT-1): the kernel
 * boot id plus the process's /proc/<pid>/stat starttime in USER_HZ ticks
 * since boot. Neither half moves on a wall-clock step, so a live owner can
 * never read as dead, and no `ps` helper is needed at all (SH-2).
 */
const BOOT_IDENTITY_PREFIX = "boot:";
const BOOT_IDENTITY_RE = /^boot:[0-9a-f-]{36}:\d+$/;

/** True when `value` is a post-RT-1 Linux boot-scoped start identity. */
export const isBootScopedStartIdentity = (value: string): boolean =>
  BOOT_IDENTITY_RE.test(value);

const procfsMounted = (): boolean => {
  try {
    statSync("/proc/self/stat");
    return true;
  } catch {
    return false;
  }
};

/**
 * The process's starttime in USER_HZ ticks since boot, from
 * /proc/<pid>/stat field 22 (index 19 once pid and comm are dropped).
 * `null` = confirmed dead, `undefined` = cannot determine.
 */
const linuxProcStartTicks = (pid: number): number | null | undefined => {
  let stat: string;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, "utf8");
  } catch (error) {
    const code = (error as { readonly code?: unknown }).code;
    if (code !== "ENOENT" && code !== "ENOTDIR") return undefined;
    // A missing per-pid stat means a dead pid only when procfs itself is
    // mounted — with no procfs at all every pid would read "dead".
    return procfsMounted() ? null : undefined;
  }
  const afterComm = stat.slice(stat.lastIndexOf(") ") + 2).split(" ");
  if (afterComm[0] === "Z" || afterComm[0] === "X") return null;
  const ticks = Number(afterComm[19]);
  return Number.isSafeInteger(ticks) && ticks > 0 ? ticks : undefined;
};

const linuxBootId = (): string | undefined => {
  try {
    const value = readFileSync("/proc/sys/kernel/random/boot_id", "utf8")
      .trim()
      .toLowerCase();
    return /^[0-9a-f-]{36}$/.test(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

/**
 * The canonical Linux start identity: `boot:<boot_id>:<starttime_ticks>`.
 * `null` = confirmed dead (stat vanished), `undefined` = cannot determine.
 */
const linuxBootScopedIdentity = (pid: number): string | null | undefined => {
  const ticks = linuxProcStartTicks(pid);
  if (ticks === null || ticks === undefined) return ticks;
  const bootId = linuxBootId();
  return bootId === undefined
    ? undefined
    : `${BOOT_IDENTITY_PREFIX}${bootId}:${ticks}`;
};

const linuxBootTimeSeconds = (): number | undefined => {
  try {
    const table = readFileSync("/proc/stat", "utf8");
    for (const line of table.split("\n")) {
      if (!line.startsWith("btime ")) continue;
      const btime = Number(line.slice(6).trim());
      return Number.isFinite(btime) && btime > 0 ? btime : undefined;
    }
    return undefined;
  } catch {
    return undefined;
  }
};

/**
 * The LEGACY Linux start identity without `ps` (procps is absent on
 * debian-slim, distroless, and some WSL images — EC-3). Reconstructs the
 * pre-RT-1 lstart string `ps` would print so records persisted by older
 * builds still compare: epoch = /proc/stat btime + starttime/HZ, matching
 * procps's own arithmetic (integer truncation), then lstart formatting.
 * `null` = confirmed dead (stat vanished), `undefined` = cannot determine.
 */
const linuxProcStartIdentity = (pid: number): string | null | undefined => {
  const ticks = linuxProcStartTicks(pid);
  if (ticks === null || ticks === undefined) return ticks;
  const bootTime = linuxBootTimeSeconds();
  if (bootTime === undefined) return undefined;
  const epochSeconds = bootTime + Math.floor(ticks / LINUX_USER_HZ);
  return formatPsLstartUtc(new Date(epochSeconds * 1000));
};

/**
 * Convert a `boot:<boot_id>:<ticks>` identity back to epoch milliseconds —
 * needed where a legacy wall-clock comparison (e.g. a legacy file lock's
 * recorded creation time) must still evaluate a post-RT-1 probe. Returns
 * null for a non-boot identity or when /proc/stat `btime` is unreadable.
 */
export const bootScopedStartIdentityMs = (identity: string): number | null => {
  const match = /^boot:[0-9a-f-]{36}:(\d+)$/.exec(identity);
  if (match === null) return null;
  const ticks = Number(match[1]);
  const bootTime = linuxBootTimeSeconds();
  if (bootTime === undefined || !Number.isSafeInteger(ticks)) return null;
  return (bootTime + Math.floor(ticks / LINUX_USER_HZ)) * 1000;
};

/**
 * POSIX probe fallback when `ps` cannot answer (missing binary, spawn error,
 * or timeout). Order: /proc reconstruction (full identity) → kill(pid,0)
 * (dead/alive only). Never returns a guess.
 */
const posixIdentityWithoutPs = (pid: number): string | null | undefined => {
  if (process.platform === "linux") {
    const fromProc = linuxProcStartIdentity(pid);
    if (fromProc !== undefined && fromProc !== null)
      return normalizeProcessStartIdentity(fromProc);
    if (fromProc === null) return null;
  }
  try {
    process.kill(pid, 0);
    return undefined;
  } catch (error) {
    const code = (error as { readonly code?: unknown }).code;
    return code === "ESRCH" ? null : undefined;
  }
};

type TWindowsKernel32 = {
  readonly OpenProcess: (
    desiredAccess: number,
    inheritHandle: number,
    processId: number,
  ) => number | null;
  readonly GetProcessTimes: (
    process: number,
    creation: number,
    exit: number,
    kernel: number,
    user: number,
  ) => number;
  readonly CloseHandle: (handle: number | null) => number;
  readonly WaitForSingleObject: (
    handle: number | null,
    milliseconds: number,
  ) => number;
  readonly GetLastError: () => number;
};

let windowsKernel32: TWindowsKernel32 | null = null;

const kernel32 = (): TWindowsKernel32 => {
  if (windowsKernel32 !== null) return windowsKernel32;
  const library = dlopen("kernel32.dll", {
    OpenProcess: {
      args: [FFIType.u32, FFIType.i32, FFIType.u32],
      returns: FFIType.ptr,
    },
    GetProcessTimes: {
      args: [FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.ptr],
      returns: FFIType.i32,
    },
    CloseHandle: { args: [FFIType.ptr], returns: FFIType.i32 },
    WaitForSingleObject: {
      args: [FFIType.ptr, FFIType.u32],
      returns: FFIType.u32,
    },
    GetLastError: { args: [], returns: FFIType.u32 },
  });
  windowsKernel32 = library.symbols as unknown as TWindowsKernel32;
  return windowsKernel32;
};

/** Read the Win32 creation FILETIME without launching a helper executable. */
const windowsProcessStartIdentity = (
  pid: number,
): string | null | undefined => {
  const api = kernel32();
  // PROCESS_QUERY_LIMITED_INFORMATION. Bun represents a NULL FFI pointer as
  // null; checking only zero lets a failed open reach GetProcessTimes.
  // SYNCHRONIZE is also required to distinguish a terminated-but-still-open
  // process object from a live PID that has the same creation FILETIME.
  const handle = api.OpenProcess(0x00101000, 0, pid);
  if (handle === null || handle === 0)
    return api.GetLastError() === 87 ? null : undefined;
  const times = new Uint8Array(32);
  try {
    const wait = api.WaitForSingleObject(handle, 0);
    if (wait === 0) return null;
    if (wait !== 258) return undefined;
    if (
      api.GetProcessTimes(
        handle,
        ptr(times.subarray(0, 8)),
        ptr(times.subarray(8, 16)),
        ptr(times.subarray(16, 24)),
        ptr(times.subarray(24, 32)),
      ) === 0
    )
      return undefined;
    return new DataView(times.buffer).getBigUint64(0, true).toString();
  } finally {
    api.CloseHandle(handle);
  }
};

/**
 * The canonical process-start identity this build persists. On Linux that is
 * the boot-scoped /proc pair — `boot:<boot_id>:<ticks>` — never the
 * wall-clock-sensitive `ps lstart` text (RT-1), so no `ps` helper is invoked
 * at all and a `ps` that rejects `lstart` cannot break session startup
 * (SH-2). Windows keeps the FILETIME creation time; other POSIX platforms
 * keep `ps lstart` with the same /proc-less liveness fallback as before.
 *
 * undefined is unavailable/unknown; null is a confirmed absent process.
 */
export const processStartIdentity = (
  pid: number,
  budgetMs = 1500,
): string | null | undefined => {
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  if (process.platform === "win32") return windowsProcessStartIdentity(pid);
  if (process.platform === "linux") return linuxBootScopedIdentity(pid);
  return posixPsStartIdentity(pid, budgetMs);
};

/**
 * The pre-RT-1 identity probe: `ps -o lstart=` text on POSIX (with the /proc
 * reconstruction when `ps` is missing, fails, or exits nonzero — SH-2), the
 * FILETIME creation time on Windows. Used to interpret records written by
 * older builds and by the installers' shared bash lock, which still stores
 * `ps lstart` text. Never use for NEW records — use {@link processStartIdentity}.
 */
export const legacyProcessStartIdentity = (
  pid: number,
  budgetMs = 1500,
): string | null | undefined => {
  if (!Number.isSafeInteger(pid) || pid <= 0) return undefined;
  if (process.platform === "win32") return windowsProcessStartIdentity(pid);
  return posixPsStartIdentity(pid, budgetMs);
};

const posixPsStartIdentity = (
  pid: number,
  budgetMs = 1500,
): string | null | undefined => {
  if (budgetMs <= 0) return undefined;
  let before: ReturnType<typeof observeDarwinProcess> | null = null;
  if (process.platform === "darwin") {
    try {
      before = observeDarwinProcess(pid);
    } catch {
      return undefined;
    }
  }
  if (before?.state === "dead") return null;
  if (before !== null && (before.state !== "live" || before.identity === null))
    return undefined;
  const [bin, ...args] = processStartCommand(pid);
  if (bin === undefined) return undefined;
  const result = spawnSync(bin, args, {
    encoding: "utf8",
    timeout: Math.max(1, Math.min(1500, budgetMs)),
    windowsHide: true,
    env: { ...process.env, LC_ALL: "C", LANG: "C", TZ: "UTC" },
  });
  if (before !== null) {
    let after: ReturnType<typeof observeDarwinProcess>;
    try {
      after = observeDarwinProcess(pid);
    } catch {
      return undefined;
    }
    if (after.state === "dead") return null;
    if (after.state !== "live" || after.identity !== before.identity)
      return undefined;
  }
  // ps missing/unspawnable/hung (EC-3) or a ps that exits nonzero — a
  // busybox-style build that rejects `lstart` (SH-2): degrade to /proc +
  // kill(pid,0) rather than reporting every pid — including dead ones — as
  // "unknown".
  if (result.error || result.status !== 0) return posixIdentityWithoutPs(pid);
  const value = normalizeProcessStartIdentity(result.stdout);
  return value || undefined;
};

/**
 * Compare a persisted identity without treating a failed probe as absence.
 * Records written before RT-1 (or by the bash installers) carry the `ps
 * lstart` text while a post-RT-1 build reads the boot-scoped Linux form —
 * and a custom reader can still hand back lstart text against a boot-scoped
 * record. On a format mismatch the live process is re-probed in the RECORD's
 * own format before death is declared, so an old record of a live process
 * still reads "alive" and a mismatched one still reads "dead".
 */
export const processIdentityStatus = (
  pid: number,
  expectedStartIdentity: string,
  readIdentity: TProcessStartIdentityReader = processStartIdentity,
  legacyReadIdentity: TProcessStartIdentityReader = legacyProcessStartIdentity,
): TProcessIdentity => {
  let actual: string | null | undefined;
  try {
    actual = readIdentity(pid);
  } catch {
    return "unknown";
  }
  if (actual === undefined) return "unknown";
  if (actual === null) return "dead";
  if (
    normalizeProcessStartIdentity(actual) ===
    normalizeProcessStartIdentity(expectedStartIdentity)
  )
    return "alive";
  if (
    isBootScopedStartIdentity(actual) ===
    isBootScopedStartIdentity(expectedStartIdentity)
  )
    return "dead"; // same format, different identity — proven not the owner
  // Mixed formats: re-probe in the record's format before convicting — the
  // caller's readers apply here too, so a bounded restore-lock wait never
  // outspends its remaining budget on a fixed-timeout legacy probe.
  let bridged: string | null | undefined;
  try {
    bridged = (
      isBootScopedStartIdentity(expectedStartIdentity)
        ? readIdentity
        : legacyReadIdentity
    )(pid);
  } catch {
    return "unknown";
  }
  if (bridged === undefined) return "unknown";
  if (bridged === null) return "dead";
  return normalizeProcessStartIdentity(bridged) ===
    normalizeProcessStartIdentity(expectedStartIdentity)
    ? "alive"
    : "dead";
};

/** Apply an owner-only Windows ACL to a newly created session directory. */
/** Apply a protected owner-only DACL to a newly created session directory. */
export const secureSessionDirectory = (path: string): void => {
  if (process.platform !== "win32") return;
  secureAndVerifyWindowsSessionDirectory(path);
};

/** Create a new private session directory using native Windows security attributes. */
export const createSessionDirectory = (path: string): void => {
  if (process.platform === "win32") createWindowsSessionDirectory(path);
  else mkdirSync(path, { mode: 0o700 });
};

/** Exclusively create a private session marker or metadata temp file. */
export const createSessionFile = (path: string, content: string): void => {
  if (process.platform === "win32")
    createWindowsSessionFile(path, new TextEncoder().encode(content));
  else writeFileSync(path, content, { mode: 0o600, flag: "wx" });
};

/** Stable per-session Win32 named-pipe path derived from the private directory. */
export const windowsSessionPipeName = (path: string): string =>
  `\\\\.\\pipe\\openllm-session-${createHash("sha256").update(path).digest("hex")}`;

/** POSIX uses Bun's unix WebSocket URL; Windows uses net's named-pipe path. */
export const localSessionEndpoint = (
  path: string,
  platform = process.platform,
): string => {
  if (platform !== "win32") return `ws+unix://${path}`;
  return windowsSessionPipeName(path);
};

export const localSessionEndpointPresent = (path: string): boolean => {
  try {
    const s = statSync(path);
    return process.platform === "win32" ? s.isFile() : s.isSocket();
  } catch {
    return false;
  }
};

/** Bun compiled argv[1] is a virtual $bunfs path, never a source entrypoint. */
export const sourceEntrypoint = (arg: string | undefined): string | null =>
  arg && !arg.includes("$bunfs") && /\.[cm]?[jt]s$/.test(arg) && existsSync(arg)
    ? arg
    : null;
