/**
 * Node-only directory lock core.
 *
 * A codec owns the record format. The core owns all generation, ownership,
 * quarantine, release, and wait rules. Keep this file out of tunnel/index.ts.
 */
import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import type {
  TProcessIdentity,
  TProcessStartIdentityReader,
} from "./local-runtime";
import {
  legacyProcessStartIdentity,
  processIdentityStatus,
  processStartIdentity,
} from "./local-runtime";

export type TDirLockOwner = {
  readonly kind: string;
  readonly pid: number;
  readonly start: string;
  readonly nonce: string;
};

export type TDirLockCodec = {
  readonly kind: string;
  readonly ownerFile: string;
  readonly markerInsideDir?: boolean;
  readonly readOwner: (dir: string) => TDirLockOwner | null;
  readonly serializeOwner: (owner: TDirLockOwner) => string;
  readonly parseOwner?: (value: string) => TDirLockOwner | null;
};

const ENV_LOCK_KIND = "openllm-env-lock/v1";
const parseEnvOwner = (value: string): TDirLockOwner | null => {
  const match = value
    .trim()
    .match(
      /^kind=openllm-env-lock\/v1 pid=([0-9]+) start=(.+) nonce=([0-9a-fA-F]+)$/,
    );
  if (match === null) return null;
  return {
    kind: ENV_LOCK_KIND,
    pid: Number(match[1]),
    start: match[2] ?? "",
    nonce: match[3] ?? "",
  };
};

/** The installer-compatible codec for `<env>.lock.d`. */
export const envDirLockCodec: TDirLockCodec = {
  kind: ENV_LOCK_KIND,
  ownerFile: "owner",
  markerInsideDir: true,
  readOwner: (dir: string): TDirLockOwner | null => {
    try {
      return parseEnvOwner(readFileSync(join(dir, "owner"), "utf8"));
    } catch {
      return null;
    }
  },
  serializeOwner: (owner: TDirLockOwner): string =>
    `kind=${ENV_LOCK_KIND} pid=${owner.pid} start=${owner.start} nonce=${owner.nonce}\n`,
};

export type TDirLockStep =
  | "before-mkdir"
  | "after-mkdir"
  | "before-publish"
  | "after-publish"
  | "after-legacy-pin"
  | "before-legacy-rename"
  | "after-legacy-rename"
  | "before-steal-marker"
  | "before-inside-steal-marker"
  | "after-steal-marker"
  | "before-steal-rename"
  | "after-steal-rename"
  | "before-steal-revalidate"
  | "before-restore-claim"
  | "after-restore-claim"
  | "before-restore-copy"
  | "before-release"
  | "after-release-rename"
  | "before-gc";

export type TDirLockOptions = {
  readonly waitMs: number;
  readonly reclaimMs: number;
  readonly pollMs?: number;
  readonly synchronous?: boolean;
  readonly now?: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly pidAlive?: (pid: number) => boolean;
  readonly startIdentity?: TProcessStartIdentityReader;
  readonly legacyStartIdentity?: TProcessStartIdentityReader;
  readonly ownerStartIdentity?: TProcessStartIdentityReader;
  readonly ownerlessMs?: number;
  readonly inode?: (path: string) => number | null | undefined;
  readonly isStale?: (path: string, asOfMtimeMs?: number) => boolean;
  readonly propagatePublishErrors?: boolean;
  readonly legacyHeld?: (deadline: number) => boolean;
  readonly onStep?: (step: TDirLockStep, path: string) => void;
  readonly onRestore?: (from: string, to: string) => void;
};

export type TDirLockRelease = () => void;

type TDirLockAttemptState = { unprovenInode: boolean };

const defaultPidAlive = (pid: number): boolean => {
  // kill(0, 0) probes the caller's own process group, not a lock owner.
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  // kill(pid, 0) reports a zombie as alive until its parent reaps it. A
  // killed contender must not leave its marker or owner record blocking the
  // next generation during that brief reaping window.
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const commEnd = stat.lastIndexOf(") ");
    if (commEnd >= 0 && stat[commEnd + 2] === "Z") return false;
  } catch {
    // Non-Linux hosts have no proc stat; kill(2) below is the portable probe.
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
};

const nonce = (): string => randomBytes(16).toString("hex");
const ino = (path: string): number | null => {
  try {
    return statSync(path).ino;
  } catch {
    return null;
  }
};
const sameIno = (path: string, expected: number | null): boolean =>
  expected !== null && ino(path) === expected;

const readIno = (path: string, options: TDirLockOptions): number | null => {
  if (options.inode !== undefined) return options.inode(path) ?? null;
  return ino(path);
};

const uniquePath = (
  lockDir: string,
  kind: "steal" | "rel",
  id: string,
): string => `${lockDir}.${kind}-${process.pid}-${id}`;

const markerPath = (lockDir: string, id: string): string =>
  `${lockDir}.stealing-${process.pid}-${id}`;

const releaseMarkerPath = (lockDir: string, id: string): string =>
  `${lockDir}.releasing-${process.pid}-${id}`;

const markerPid = (lockDir: string, name: string): number | null => {
  const prefix = `${basename(lockDir)}.stealing-`;
  if (!name.startsWith(prefix)) return null;
  const value = Number(name.slice(prefix.length).split("-")[0]);
  return Number.isSafeInteger(value) && value > 0 ? value : null;
};

const releaseMarkerOwner = (
  lockDir: string,
  name: string,
): { pid: number; nonce: string } | null => {
  const prefix = `${basename(lockDir)}.releasing-`;
  if (!name.startsWith(prefix)) return null;
  const match = /^(\d+)-([0-9a-f]{32})$/.exec(name.slice(prefix.length));
  if (match === null) return null;
  const pid = Number(match[1]);
  return Number.isSafeInteger(pid) && pid > 0
    ? { pid, nonce: match[2] ?? "" }
    : null;
};

const markerExists = (lockDir: string): boolean => {
  let names: string[];
  try {
    names = readdirSync(dirname(lockDir));
  } catch {
    return false;
  }
  return names.some((name) => markerPid(lockDir, name) !== null);
};

const insideMarkerExists = (lockDir: string, codec: TDirLockCodec): boolean => {
  if (!codec.markerInsideDir) return false;
  try {
    return readdirSync(lockDir).some((name) => name.startsWith("steal."));
  } catch {
    return true;
  }
};

const liveReleaseMarkerExists = (
  lockDir: string,
  opts: TDirLockOptions,
): boolean => {
  let names: string[];
  try {
    names = readdirSync(dirname(lockDir));
  } catch {
    return false;
  }
  return names.some((name) => {
    const owner = releaseMarkerOwner(lockDir, name);
    return owner !== null && (opts.pidAlive ?? defaultPidAlive)(owner.pid);
  });
};

const activeNonces = new Set<string>();
// Keep only releases that failed in this process. A retry removes the entry.
const interruptedReleases = new Set<string>();
const pendingClaims = new Map<
  string,
  {
    readonly codec: TDirLockCodec;
    readonly owner: TDirLockOwner;
    readonly ino: number;
    readonly opts: TDirLockOptions;
  }
>();

const recordTime = (dir: string, codec: TDirLockCodec): number | null => {
  let latest: number | null = null;
  try {
    latest = statSync(dir).mtimeMs;
  } catch {
    return null;
  }
  try {
    const stat = statSync(join(dir, codec.ownerFile));
    latest = Math.max(latest, stat.mtimeMs);
  } catch {
    // An empty generation is timed by its directory inode.
  }
  return latest;
};

const provenStatus = (
  owner: TDirLockOwner,
  opts: TDirLockOptions,
): TProcessIdentity => {
  if (owner.start.length === 0) return "unknown";
  return processIdentityStatus(
    owner.pid,
    owner.start,
    opts.startIdentity ?? processStartIdentity,
    opts.legacyStartIdentity ?? legacyProcessStartIdentity,
  );
};

const classify = (
  owner: TDirLockOwner | null,
  opts: TDirLockOptions,
): "live" | "dead" | "unknown" => {
  if (owner === null) return "unknown";
  if (owner.start.length === 0) {
    return (opts.pidAlive ?? defaultPidAlive)(owner.pid) ? "unknown" : "dead";
  }
  const status = provenStatus(owner, opts);
  if (status === "alive")
    return (opts.pidAlive ?? defaultPidAlive)(owner.pid) ? "live" : "dead";
  if (status === "dead") return "dead";
  return (opts.pidAlive ?? defaultPidAlive)(owner.pid) ? "unknown" : "dead";
};

const copyNoReplace = (
  from: string,
  to: string,
  codec: TDirLockCodec,
  onStep?: TDirLockOptions["onStep"],
): boolean => {
  try {
    mkdirSync(to, { mode: 0o700 });
  } catch {
    return false;
  }
  const copied: string[] = [];
  try {
    for (const name of readdirSync(from)) {
      if (codec.markerInsideDir && name.startsWith("steal.")) continue;
      const source = join(from, name);
      const target = join(to, name);
      let sourceStat: ReturnType<typeof statSync>;
      try {
        sourceStat = statSync(source);
      } catch {
        throw new Error("source disappeared during no-replace restore");
      }
      if (!sourceStat.isFile()) continue;
      const data = readFileSync(source);
      onStep?.("before-restore-copy", from);
      const fd = openSync(target, "wx", 0o600);
      try {
        writeFileSync(fd, data);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      if (!readFileSync(target).equals(data))
        throw new Error("no-replace restore verification failed");
      copied.push(name);
      // A release can remove the captured owner while this copy is in flight.
      // Do not publish a snapshot whose source has already been released.
      if (!readFileSync(source).equals(data))
        throw new Error("source changed during no-replace restore");
    }
  } catch {
    for (const name of copied) {
      try {
        unlinkSync(join(to, name));
      } catch {
        // Keep the destination if a competitor changed it.
      }
    }
    try {
      rmdirSync(to);
    } catch {
      // A competitor owns the destination now.
    }
    return false;
  }
  for (const name of copied) {
    try {
      unlinkSync(join(from, name));
    } catch {
      return false;
    }
  }
  if (codec.markerInsideDir) {
    for (const name of readdirSync(from)) {
      if (!name.startsWith("steal.")) continue;
      try {
        unlinkSync(join(from, name));
      } catch {
        return false;
      }
    }
  }
  try {
    rmdirSync(from);
  } catch {
    return false;
  }
  return true;
};

/** Restore a quarantine without ever renaming over a directory. */
export const moveDirNoReplace = (
  from: string,
  to: string,
  codec: TDirLockCodec,
  onStep?: TDirLockOptions["onStep"],
  onRestore?: TDirLockOptions["onRestore"],
): boolean => {
  onRestore?.(from, to);
  onStep?.("before-restore-claim", to);
  // The public options callback carries both paths. The step callback is kept
  // for simple fault injection and remains compatible with older adapters.
  const result = copyNoReplace(from, to, codec, onStep);
  onStep?.("after-restore-claim", to);
  return result;
};

export const publishDirLockOwner = (
  lockDir: string,
  expectedIno: number,
  owner: TDirLockOwner,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): boolean => {
  opts.onStep?.("before-publish", lockDir);
  if (!sameIno(lockDir, expectedIno) || owner.start.length === 0) return false;
  if (markerExists(lockDir) || insideMarkerExists(lockDir, codec)) return false;
  const tmp = join(lockDir, `${codec.ownerFile}.${owner.nonce}.tmp`);
  const target = join(lockDir, codec.ownerFile);
  const data = codec.serializeOwner(owner);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeFileSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  if (
    !sameIno(lockDir, expectedIno) ||
    existsSync(target) ||
    markerExists(lockDir) ||
    insideMarkerExists(lockDir, codec)
  ) {
    try {
      unlinkSync(tmp);
    } catch {
      // The generation may already be quarantined.
    }
    return false;
  }
  try {
    // A hard link is the portable no-replace publication primitive. It is
    // atomic, and unlinking the temp leaves the complete record in place.
    // A rename would replace an empty successor directory on POSIX.
    linkSync(tmp, target);
    unlinkSync(tmp);
  } catch {
    try {
      unlinkSync(tmp);
    } catch {
      // Best effort.
    }
    return false;
  }
  opts.onStep?.("after-publish", lockDir);
  const ok = sameIno(lockDir, expectedIno);
  if (codec.markerInsideDir && (!ok || insideMarkerExists(lockDir, codec))) {
    const current = codec.readOwner(lockDir);
    if (current?.pid === owner.pid && current.nonce === owner.nonce) {
      try {
        unlinkSync(target);
      } catch {
        // The generation may already be quarantined.
      }
    }
    return false;
  }
  return ok && codec.readOwner(lockDir)?.nonce === owner.nonce;
};

/** Finish a release only when the captured record proves ownership. */
export const finishDirLockRelease = (
  quarantine: string,
  lockDir: string,
  owner: Pick<TDirLockOwner, "pid" | "nonce">,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): boolean => {
  const parked = codec.readOwner(quarantine);
  // A failed read does not prove a foreign owner. Let GC retry the read.
  if (parked === null) return false;
  if (parked.pid !== owner.pid || parked.nonce !== owner.nonce)
    return moveDirNoReplace(
      quarantine,
      lockDir,
      codec,
      opts.onStep,
      opts.onRestore,
    );
  try {
    rmSync(quarantine, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
};

export const releaseDirLock = (
  lockDir: string,
  owner: TDirLockOwner,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): void => {
  opts.onStep?.("before-release", lockDir);
  let current = codec.readOwner(lockDir);
  if (current?.pid !== owner.pid || current.nonce !== owner.nonce) {
    // A competing steal can park our generation before its foreign-owner
    // check. Release our exact record there so the repair cannot revive it.
    const base = basename(lockDir);
    const prefixes = [`${base}.steal-`, `${base}.rel-`];
    if (codec.markerInsideDir && base.endsWith(".d")) {
      const stem = base.slice(0, -2);
      prefixes.push(`${stem}.stale.`, `${stem}.rel.`);
    }
    try {
      for (const name of readdirSync(dirname(lockDir))) {
        if (!prefixes.some((prefix) => name.startsWith(prefix))) continue;
        const path = join(dirname(lockDir), name);
        const parked = codec.readOwner(path);
        if (parked?.pid === owner.pid && parked.nonce === owner.nonce)
          finishDirLockRelease(path, lockDir, owner, codec, opts);
      }
    } catch {
      // A later sweep retains records whose ownership cannot be proved.
    }
    // A repair may have copied the record before its source was removed.
    current = codec.readOwner(lockDir);
    if (current?.pid !== owner.pid || current.nonce !== owner.nonce) return;
  }
  const quarantine = uniquePath(lockDir, "rel", owner.nonce);
  const releaseMarker = releaseMarkerPath(lockDir, owner.nonce);
  let markerCreated = false;
  let complete = false;
  try {
    mkdirSync(releaseMarker, { mode: 0o700 });
    markerCreated = true;
  } catch {
    return;
  }
  try {
    renameSync(lockDir, quarantine);
  } catch {
    try {
      if (markerCreated) rmdirSync(releaseMarker);
    } catch {
      // GC removes a marker once its releasing process is dead.
    }
    return;
  }
  try {
    opts.onStep?.("after-release-rename", quarantine);
    complete = finishDirLockRelease(quarantine, lockDir, owner, codec, opts);
  } finally {
    if (markerCreated && complete) {
      try {
        rmdirSync(releaseMarker);
      } catch {
        interruptedReleases.add(releaseMarker);
      }
    } else {
      interruptedReleases.add(releaseMarker);
    }
  }
};

const removeCreated = (lockDir: string): void => {
  try {
    // mkdir succeeded immediately before this path. It must still be empty
    // because publish has not started. rmdir cannot remove a live record.
    rmdirSync(lockDir);
  } catch {}
};

const tryAcquireDirLockAttempt = (
  lockDir: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
  state: TDirLockAttemptState,
): TDirLockRelease | null => {
  opts.onStep?.("before-mkdir", lockDir);
  const stealing = markerExists(lockDir);
  const releasing = liveReleaseMarkerExists(lockDir, opts);
  if (stealing || releasing) return null;
  const pending = pendingClaims.get(lockDir);
  if (
    pending !== undefined &&
    pending.codec.kind === codec.kind &&
    sameIno(lockDir, pending.ino) &&
    codec.readOwner(lockDir) === null &&
    !markerExists(lockDir) &&
    !liveReleaseMarkerExists(lockDir, opts)
  ) {
    if (publishDirLockOwner(lockDir, pending.ino, pending.owner, codec, opts)) {
      pendingClaims.delete(lockDir);
      let released = false;
      return (): void => {
        if (released) return;
        released = true;
        activeNonces.delete(pending.owner.nonce);
        releaseDirLock(lockDir, pending.owner, codec, opts);
      };
    }
  }
  try {
    mkdirSync(lockDir, { mode: 0o700 });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (opts.propagatePublishErrors && code !== "EEXIST") throw error;
    return null;
  }
  opts.onStep?.("after-mkdir", lockDir);
  const expectedIno = readIno(lockDir, opts);
  if (expectedIno === null) {
    state.unprovenInode = true;
    removeCreated(lockDir);
    return null;
  }
  if (markerExists(lockDir) || insideMarkerExists(lockDir, codec)) {
    removeCreated(lockDir);
    return null;
  }
  const owner: TDirLockOwner = {
    kind: codec.kind,
    pid: process.pid,
    start:
      (opts.ownerStartIdentity ?? opts.startIdentity ?? processStartIdentity)(
        process.pid,
      ) ?? "",
    nonce: nonce(),
  };
  if (owner.start.length === 0) {
    removeCreated(lockDir);
    return null;
  }
  activeNonces.add(owner.nonce);
  try {
    if (!publishDirLockOwner(lockDir, expectedIno, owner, codec, opts)) {
      const currentIno = ino(lockDir);
      if (
        codec.readOwner(lockDir) === null &&
        (currentIno === null || currentIno === expectedIno)
      ) {
        pendingClaims.set(lockDir, { codec, owner, ino: expectedIno, opts });
      } else {
        activeNonces.delete(owner.nonce);
      }
      if (
        opts.propagatePublishErrors &&
        currentIno !== null &&
        currentIno !== expectedIno
      )
        throw new Error("directory lock generation changed during publish");
      return null;
    }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      pendingClaims.set(lockDir, { codec, owner, ino: expectedIno, opts });
      return null;
    }
    if (sameIno(lockDir, expectedIno)) removeCreated(lockDir);
    activeNonces.delete(owner.nonce);
    if (opts.propagatePublishErrors && code !== "ENOENT" && code !== "ENOTDIR")
      throw error;
    return null;
  }
  const superseded = pendingClaims.get(lockDir);
  if (superseded !== undefined && superseded.owner.nonce !== owner.nonce) {
    activeNonces.delete(superseded.owner.nonce);
    pendingClaims.delete(lockDir);
  }
  let done = false;
  return (): void => {
    if (done) return;
    done = true;
    activeNonces.delete(owner.nonce);
    releaseDirLock(lockDir, owner, codec, opts);
  };
};

/** Retry immediately when our just-created generation cannot be pinned. */
export const tryAcquireDirLock = (
  lockDir: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): TDirLockRelease | null => {
  const state: TDirLockAttemptState = { unprovenInode: false };
  const first = tryAcquireDirLockAttempt(lockDir, codec, opts, state);
  if (first !== null || !state.unprovenInode) return first;
  state.unprovenInode = false;
  return tryAcquireDirLockAttempt(lockDir, codec, opts, state);
};

export const stealDirLock = (
  lockDir: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): boolean => {
  let originalStat: ReturnType<typeof statSync>;
  try {
    originalStat = statSync(lockDir);
  } catch {
    return false;
  }
  const originalIno = originalStat.ino;
  const sameGeneration = (path: string): boolean => {
    try {
      const current = statSync(path);
      return current.dev === originalStat.dev && current.ino === originalIno;
    } catch {
      return false;
    }
  };
  const originalOwner = codec.readOwner(lockDir);
  let originalMtime = Number.NaN;
  try {
    originalMtime = statSync(lockDir).mtimeMs;
  } catch {
    return false;
  }
  const id = nonce();
  const siblingMarker = markerPath(lockDir, id);
  const insideMarker = join(lockDir, `steal.${process.pid}.${id}`);
  let markerCreated = false;
  let insideMarkerCreated = false;
  const quarantine = uniquePath(lockDir, "steal", id);
  opts.onStep?.("before-steal-marker", lockDir);
  try {
    mkdirSync(siblingMarker, { mode: 0o700 });
    markerCreated = true;
    if (codec.markerInsideDir) {
      if (!sameGeneration(lockDir)) return false;
      opts.onStep?.("before-inside-steal-marker", lockDir);
      const fd = openSync(insideMarker, "wx", 0o600);
      insideMarkerCreated = true;
      closeSync(fd);
      // The path can change during open. Remove only our marker on abort.
      if (!sameGeneration(lockDir)) return false;
    }
    opts.onStep?.("after-steal-marker", lockDir);
    opts.onStep?.("before-steal-revalidate", lockDir);
    if (!sameGeneration(lockDir)) return false;
    const currentOwner = codec.readOwner(lockDir);
    const sameOwner =
      currentOwner?.kind === originalOwner?.kind &&
      currentOwner?.pid === originalOwner?.pid &&
      currentOwner?.start === originalOwner?.start &&
      currentOwner?.nonce === originalOwner?.nonce;
    const initialVerdict = classify(currentOwner, opts);
    const initialAge =
      currentOwner === null ? originalMtime : recordTime(lockDir, codec);
    const initiallyReclaimable =
      (opts.isStale?.(lockDir, originalMtime) ?? false) ||
      (opts.isStale === undefined &&
        (initialVerdict === "dead" ||
          (currentOwner === null &&
            initialAge !== null &&
            (opts.now ?? Date.now)() - initialAge >= opts.reclaimMs)));
    if (!sameOwner || !initiallyReclaimable) return false;
    opts.onStep?.("before-steal-rename", lockDir);
    renameSync(lockDir, quarantine);
    opts.onStep?.("after-steal-rename", quarantine);
    if (!sameGeneration(quarantine)) {
      moveDirNoReplace(quarantine, lockDir, codec, opts.onStep, opts.onRestore);
      return false;
    }
    opts.onStep?.("before-steal-revalidate", quarantine);
    const parked = codec.readOwner(quarantine);
    const verdict = classify(parked, opts);
    // The in-directory steal marker updates the directory mtime. For an
    // ownerless generation, age it from the pre-marker observation or
    // contenders can perpetually refresh the reclaim horizon and livelock.
    const age = parked === null ? originalMtime : recordTime(quarantine, codec);
    const reclaimable =
      (opts.isStale?.(quarantine, originalMtime) ?? false) ||
      (opts.isStale === undefined &&
        (verdict === "dead" ||
          (parked === null &&
            age !== null &&
            (opts.now ?? Date.now)() - age >= opts.reclaimMs)));
    if (!reclaimable) {
      moveDirNoReplace(quarantine, lockDir, codec, opts.onStep, opts.onRestore);
      return false;
    }
    rmSync(quarantine, { recursive: true, force: true });
    return true;
  } catch {
    try {
      if (existsSync(quarantine))
        moveDirNoReplace(
          quarantine,
          lockDir,
          codec,
          opts.onStep,
          opts.onRestore,
        );
    } catch {
      // Leave it for bounded GC.
    }
    return false;
  } finally {
    if (insideMarkerCreated) {
      for (const path of [
        insideMarker,
        join(quarantine, `steal.${process.pid}.${id}`),
      ]) {
        try {
          unlinkSync(path);
        } catch {
          // A moved or deleted generation leaves no marker at this path.
        }
      }
    }
    if (markerCreated) {
      try {
        rmdirSync(siblingMarker);
      } catch {
        // GC handles a stranded marker.
      }
    }
  }
};

export const sweepDirLockResidue = (
  lockDir: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
): void => {
  opts.onStep?.("before-gc", lockDir);
  let names: string[];
  try {
    names = readdirSync(dirname(lockDir));
  } catch {
    return;
  }
  const now = (opts.now ?? Date.now)();
  const base = basename(lockDir);
  for (const name of names) {
    const path = join(dirname(lockDir), name);
    const marker = markerPid(lockDir, name);
    if (marker !== null) {
      try {
        if (!(opts.pidAlive ?? defaultPidAlive)(marker)) rmdirSync(path);
      } catch {
        // Retry on the next bounded sweep.
      }
      continue;
    }
    const releaseMarker = releaseMarkerOwner(lockDir, name);
    if (releaseMarker !== null) {
      try {
        if (
          interruptedReleases.has(path) ||
          !(opts.pidAlive ?? defaultPidAlive)(releaseMarker.pid)
        ) {
          const quarantine = `${lockDir}.rel-${releaseMarker.pid}-${releaseMarker.nonce}`;
          // Complete a stopped release. A foreign record stays in quarantine
          // if another holder has already claimed the lock path.
          if (existsSync(quarantine))
            finishDirLockRelease(
              quarantine,
              lockDir,
              releaseMarker,
              codec,
              opts,
            );
          if (!existsSync(quarantine)) {
            rmdirSync(path);
            interruptedReleases.delete(path);
          } else {
            const parked = codec.readOwner(quarantine);
            if (
              parked !== null &&
              (parked.pid !== releaseMarker.pid ||
                parked.nonce !== releaseMarker.nonce)
            ) {
              rmdirSync(path);
              interruptedReleases.delete(path);
            }
          }
        }
      } catch {
        // Retry on the next bounded sweep.
      }
      continue;
    }
    if (!name.startsWith(`${base}.steal-`) && !name.startsWith(`${base}.rel-`))
      continue;
    const owner = codec.readOwner(path);
    const isRelease = name.startsWith(`${base}.rel-`);
    const suffix = name.slice(
      name.indexOf(isRelease ? ".rel-" : ".steal-") + 5,
    );
    const parts = suffix.split("-");
    const namePid = Number(parts[0]);
    const nameNonce = parts.slice(1).join("-");
    if (
      isRelease &&
      (owner === null || owner.pid !== namePid || owner.nonce !== nameNonce)
    ) {
      // A same-pid different-nonce release residue is foreign.
      if (owner !== null && classify(owner, opts) === "live")
        moveDirNoReplace(path, lockDir, codec, opts.onStep, opts.onRestore);
      continue;
    }
    if (isRelease && liveReleaseMarkerExists(lockDir, opts)) continue;
    // A matching release name proves that this record was released. Never
    // restore it: the releaser can remove its marker after we read the record.
    if (!isRelease && owner !== null && classify(owner, opts) === "live") {
      if (!existsSync(lockDir))
        moveDirNoReplace(path, lockDir, codec, opts.onStep, opts.onRestore);
      continue;
    }
    // Keep foreign files and unreadable owner records. A stale directory name
    // alone does not prove that its contents belong to the lock protocol.
    try {
      if (!lstatSync(path).isDirectory()) continue;
      const names = readdirSync(path);
      const escapedOwnerFile = codec.ownerFile.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&",
      );
      const temporaryOwner = new RegExp(
        `^${escapedOwnerFile}(?:\\.tmp\\.\\d+|\\.(?:[0-9a-f]{32}|\\d+)\\.tmp)$`,
      );
      if (
        names.some((name) => {
          if (!lstatSync(join(path, name)).isFile()) return true;
          if (name === codec.ownerFile) return owner === null;
          return (
            !temporaryOwner.test(name) &&
            !(codec.markerInsideDir && /^steal\.\d+\.[0-9a-f]+$/.test(name))
          );
        })
      )
        continue;
    } catch {
      continue;
    }
    const age = recordTime(path, codec);
    if (age === null || now - age < opts.reclaimMs) continue;
    try {
      rmSync(path, { recursive: true, force: true });
    } catch {
      // Bounded best effort.
    }
  }
};

const defaultNow = (): number => Date.now();
const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const migrateLegacyFile = (
  lockDir: string,
  codec: TDirLockCodec,
  opts: TDirLockOptions,
  deadline: number,
): "migrated" | "retry" | null => {
  if (opts.legacyHeld === undefined) return null;
  let renamed = false;
  try {
    const pinned = lstatSync(lockDir);
    if (!pinned.isFile()) return null;
    opts.onStep?.("after-legacy-pin", lockDir);
    if (opts.legacyHeld(deadline)) return null;
    // Keep foreign files outside the directory residue sweep.
    const parked = `${lockDir}.legacy-${process.pid}-${nonce()}`;
    opts.onStep?.("before-legacy-rename", lockDir);
    renameSync(lockDir, parked);
    renamed = true;
    opts.onStep?.("after-legacy-rename", parked);
    const moved = lstatSync(parked);
    if (moved.dev === pinned.dev && moved.ino === pinned.ino) {
      unlinkSync(parked);
      return "migrated";
    }
    if (moved.isDirectory()) {
      moveDirNoReplace(parked, lockDir, codec, opts.onStep, opts.onRestore);
    } else {
      // A hard link cannot replace a file or an empty directory.
      linkSync(parked, lockDir);
      unlinkSync(parked);
    }
  } catch {
    // Keep any foreign quarantine when the destination is occupied.
    return renamed ? "retry" : null;
  }
  return "retry";
};

export const acquireDirLock = async (
  lockDir: string,
  codec: TDirLockCodec,
  options: TDirLockOptions,
): Promise<TDirLockRelease | null> => {
  const opts: TDirLockOptions = {
    ...options,
    now: options.now ?? defaultNow,
  };
  const now = opts.now ?? defaultNow;
  const deadline = now() + Math.max(0, opts.waitMs);
  for (;;) {
    sweepDirLockResidue(lockDir, codec, opts);
    if (opts.legacyHeld?.(deadline) === true) {
      if (now() >= deadline) return null;
      await (opts.sleep ?? defaultSleep)(
        Math.min(opts.pollMs ?? 50, deadline - now()),
      );
      continue;
    }
    const release = tryAcquireDirLock(lockDir, codec, opts);
    if (release !== null) return release;
    const migration = migrateLegacyFile(lockDir, codec, opts, deadline);
    if (migration !== null) {
      if (migration === "retry" && now() >= deadline) return null;
      continue;
    }
    const owner = codec.readOwner(lockDir);
    if (owner !== null && activeNonces.has(owner.nonce)) return null;
    const verdict = classify(owner, opts);
    const age = recordTime(lockDir, codec);
    const policyStale = opts.isStale?.(lockDir);
    const reclaimable =
      (verdict === "dead" && (policyStale ?? true)) ||
      (owner === null &&
        (policyStale ?? (age !== null && now() - age >= opts.reclaimMs)));
    if (reclaimable && stealDirLock(lockDir, codec, opts)) continue;
    if (now() >= deadline) return null;
    await (opts.sleep ?? defaultSleep)(
      Math.min(opts.pollMs ?? 50, deadline - now()),
    );
  }
};

export const acquireDirLockSync = (
  lockDir: string,
  codec: TDirLockCodec,
  options: TDirLockOptions,
): TDirLockRelease | null => {
  const opts: TDirLockOptions = { ...options, now: options.now ?? defaultNow };
  const now = opts.now ?? defaultNow;
  const deadline = now() + Math.max(0, opts.waitMs);
  const wait = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    sweepDirLockResidue(lockDir, codec, opts);
    if (opts.legacyHeld?.(deadline) === true) {
      if (now() >= deadline) return null;
      Atomics.wait(wait, 0, 0, Math.min(opts.pollMs ?? 10, deadline - now()));
      continue;
    }
    const release = tryAcquireDirLock(lockDir, codec, opts);
    if (release !== null) return release;
    const migration = migrateLegacyFile(lockDir, codec, opts, deadline);
    if (migration !== null) {
      if (migration === "retry" && now() >= deadline) return null;
      continue;
    }
    const owner = codec.readOwner(lockDir);
    const verdict = classify(owner, opts);
    const age = recordTime(lockDir, codec);
    const policyStale = opts.isStale?.(lockDir);
    const reclaimable =
      (verdict === "dead" && (policyStale ?? true)) ||
      (owner === null &&
        (policyStale ?? (age !== null && now() - age >= opts.reclaimMs)));
    if (reclaimable && stealDirLock(lockDir, codec, opts)) continue;
    if (now() >= deadline) return null;
    Atomics.wait(wait, 0, 0, Math.min(opts.pollMs ?? 10, deadline - now()));
  }
};
