import { randomBytes } from "node:crypto";
import {
  fsyncSync,
  lstatSync,
  readlinkSync,
  readSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, resolve, sep } from "node:path";
import type { TDirLockKind } from "./dir-lock-format";
import {
  formatDirLockControlName,
  formatDirLockGeneration,
} from "./dir-lock-format";
import type { TDirectoryHandle, TFileHandle } from "./dir-lock-fs";
import {
  close,
  linkChild,
  listDirectory,
  mkdirChild,
  openChild,
  openDirectory,
  openDirectoryChild,
  posixOpenFlags,
  removeEmptyChild,
  statDescriptor,
  tryLockGate,
  unlinkChild,
  unlockGate,
} from "./dir-lock-fs";

export const LEGACY_LOCK_MESSAGE =
  "an older openllm installer or daemon is running or left a lock; close it, or run `openllmd doctor --clear-legacy-locks` once it has finished";
export class LegacyLockError extends Error {
  readonly code = "LEGACY_LOCK_HELD";
  constructor(
    readonly path: string,
    readonly reason: string,
  ) {
    super(
      `${LEGACY_LOCK_MESSAGE}. Lock: ${path}. Reason: ${reason}.${
        basename(path) === ".openllm-restore.lock"
          ? ` For a custom client directory, add --restore-dir ${JSON.stringify(dirname(path))}.`
          : ""
      }`,
    );
    this.name = "LegacyLockError";
  }
}
export class LockUnknownError extends Error {
  readonly code = "LOCK_UNKNOWN";
}
/**
 * The open metadata gate is no longer the named gate file. Another process
 * collected the empty control directory after its last claim ended. The
 * caller must open the control again before its next operation.
 */
export class GateVanishedError extends Error {
  readonly code = "LOCK_GATE_VANISHED";
}
/** Bounded reopen attempts when a control directory is collected under us. */
export const GATE_REOPEN_LIMIT = 8;
export type TLockKind = TDirLockKind;
export type TLockControl = {
  readonly path: string;
  readonly base: string;
  readonly kind: TLockKind;
  readonly parent: TDirectoryHandle;
  readonly control: TDirectoryHandle;
  readonly gate: TFileHandle;
};
export const errorCode = (error: unknown): string | undefined =>
  (error as NodeJS.ErrnoException | undefined)?.code;
export const lockNonce = (): string => randomBytes(16).toString("hex");
export const lockGeneration = (handle: TDirectoryHandle): string => {
  const { dev, ino } = statDescriptor(handle.fd);
  return formatDirLockGeneration(dev, ino);
};
export const childDirectory = openDirectoryChild;
export const childExists = (
  parent: TDirectoryHandle,
  name: string,
): boolean => {
  try {
    const fd = openChild(parent, name, posixOpenFlags().O_RDONLY, 0);
    close(fd);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
};
export const checkedNames = (
  dir: TDirectoryHandle,
  limit: number,
): string[] => {
  const names = listDirectory(dir, limit);
  if (names.length > limit)
    throw new LockUnknownError("lock listing exceeds the protocol bound");
  return names;
};
export const withFileHandle = <TResult>(
  handle: TFileHandle,
  operation: () => TResult,
): TResult => {
  let result: TResult;
  try {
    result = operation();
  } catch (error) {
    try {
      close(handle);
    } catch {
      /* Preserve the first error. */
    }
    throw error;
  }
  close(handle);
  return result;
};
export const readRecord = (
  dir: TDirectoryHandle,
  name: string,
  limit: number,
): Buffer => {
  const fd = openChild(dir, name, posixOpenFlags().O_RDONLY, 0);
  return withFileHandle(fd, () => {
    const stat = statDescriptor(fd.fd);
    if (
      !stat.isFile() ||
      stat.size > BigInt(limit) ||
      stat.uid !== BigInt(process.getuid?.() ?? -1)
    )
      throw new LockUnknownError(
        "lock record has an unsafe type, size, or owner",
      );
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    for (;;) {
      const size = readSync(
        fd.fd,
        buffer,
        length,
        buffer.length - length,
        length,
      );
      if (size === 0) break;
      length += size;
      if (length > limit)
        throw new LockUnknownError("lock record exceeds the protocol bound");
    }
    return buffer.subarray(0, length);
  });
};
export const writeRecord = (
  dir: TDirectoryHandle,
  temp: string,
  name: string,
  bytes: string | Buffer,
): void => {
  const fd = openChild(
    dir,
    temp,
    posixOpenFlags().O_WRONLY |
      posixOpenFlags().O_CREAT |
      posixOpenFlags().O_EXCL,
    0o600,
  );
  withFileHandle(fd, () => {
    writeFileSync(fd.fd, bytes);
    fsyncSync(fd.fd);
  });
  const expected = Buffer.from(bytes);
  if (!readRecord(dir, temp, expected.length).equals(expected))
    throw new LockUnknownError("lock record verification failed");
  linkChild(dir, temp, dir, name);
  unlinkChild(dir, temp);
};
export const removeLinkedRecordTemp = (
  dir: TDirectoryHandle,
  temp: string,
  name: string,
  limit: number,
): void => {
  if (!childExists(dir, temp)) return;
  readRecord(dir, temp, limit);
  readRecord(dir, name, limit);
  const source = openChild(dir, temp, posixOpenFlags().O_RDONLY, 0);
  withFileHandle(source, () => {
    const published = openChild(dir, name, posixOpenFlags().O_RDONLY, 0);
    withFileHandle(published, () => {
      const a = statDescriptor(source.fd);
      const b = statDescriptor(published.fd);
      if (a.dev !== b.dev || a.ino !== b.ino)
        throw new LockUnknownError("plan temp is not the published hard link");
      unlinkChild(dir, temp);
    });
  });
};
export const ensureDirectory = (
  parent: TDirectoryHandle,
  name: string,
): TDirectoryHandle => {
  try {
    mkdirChild(parent, name);
  } catch (error) {
    if (errorCode(error) !== "EEXIST") throw error;
  }
  const child = childDirectory(parent, name);
  const stat = statDescriptor(child.fd);
  if (
    stat.uid !== BigInt(process.getuid?.() ?? -1) ||
    (stat.mode & 0o077n) !== 0n
  ) {
    close(child);
    throw new LockUnknownError(
      "lock control is not private to the current user",
    );
  }
  return child;
};
const physicalSystemPath = (path: string): string => {
  const normalized = resolve(path);
  if (process.platform !== "darwin") return normalized;
  for (const alias of ["var", "tmp", "etc"]) {
    const prefix = `/${alias}`;
    if (normalized !== prefix && !normalized.startsWith(`${prefix}/`)) continue;
    const physical = `/private/${alias}`;
    const link = lstatSync(prefix, { bigint: true });
    const target = lstatSync(physical, { bigint: true });
    const linkText = readlinkSync(prefix);
    if (
      !link.isSymbolicLink() ||
      link.uid !== 0n ||
      ![physical, `private/${alias}`].includes(linkText) ||
      !target.isDirectory() ||
      target.uid !== 0n
    )
      throw new LockUnknownError("untrusted system directory alias");
    // Only these root-owned macOS aliases are permitted; later components stay O_NOFOLLOW.
    return `${physical}${normalized.slice(prefix.length)}`;
  }
  return normalized;
};
export const openPinnedPath = (path: string): TDirectoryHandle => {
  if (!isAbsolute(path))
    throw new LockUnknownError("lock path must be absolute");
  let current = openDirectory(sep);
  try {
    for (const name of physicalSystemPath(path).split(sep).filter(Boolean)) {
      const next = childDirectory(current, name);
      close(current);
      current = next;
    }
    return current;
  } catch (error) {
    close(current);
    throw error;
  }
};
export const openLockControl = (
  path: string,
  kind: TLockKind,
): TLockControl => {
  const base = basename(path);
  if (
    !isAbsolute(path) ||
    Buffer.byteLength(base) > 160 ||
    base === "." ||
    base === ".."
  )
    throw new LockUnknownError("unsupported lock path");
  const parent = openPinnedPath(dirname(path));
  try {
    const parentStat = statDescriptor(parent.fd);
    if (
      parentStat.uid !== BigInt(process.getuid?.() ?? -1) ||
      (parentStat.mode & 0o022n) !== 0n
    )
      throw new LockUnknownError("lock parent is writable by another user");
    // A concurrent final release can collect the empty control directory
    // between our steps. Each such collection is one completed cycle of
    // another process, so a small fixed number of reopen attempts is enough.
    for (let attempt = 1; ; attempt++) {
      try {
        return openControlOnce(path, base, kind, parent);
      } catch (error) {
        if (
          !(error instanceof GateVanishedError) ||
          attempt >= GATE_REOPEN_LIMIT
        )
          throw error;
      }
    }
  } catch (error) {
    close(parent);
    throw error;
  }
};
const openControlOnce = (
  path: string,
  base: string,
  kind: TLockKind,
  parent: TDirectoryHandle,
): TLockControl => {
  let control: TDirectoryHandle | undefined;
  let gate: TFileHandle | undefined;
  try {
    control = ensureDirectory(parent, formatDirLockControlName(base));
    try {
      gate = openChild(
        control,
        "meta.v3.lock",
        posixOpenFlags().O_RDWR |
          posixOpenFlags().O_CREAT |
          posixOpenFlags().O_EXCL,
        0o600,
      );
    } catch (error) {
      if (errorCode(error) === "ENOENT")
        throw new GateVanishedError("control directory was collected");
      if (errorCode(error) !== "EEXIST") throw error;
      try {
        gate = openChild(control, "meta.v3.lock", posixOpenFlags().O_RDWR, 0);
      } catch (inner) {
        if (errorCode(inner) === "ENOENT")
          throw new GateVanishedError("metadata gate was collected");
        throw inner;
      }
    }
    const stat = statDescriptor(gate.fd);
    if (stat.nlink === 0n)
      throw new GateVanishedError("metadata gate was collected");
    if (
      !stat.isFile() ||
      stat.uid !== BigInt(process.getuid?.() ?? -1) ||
      (stat.mode & 0o077n) !== 0n ||
      stat.nlink !== 1n
    )
      throw new LockUnknownError("unsafe metadata gate");
    return { path, base, kind, parent, control, gate };
  } catch (error) {
    if (gate !== undefined) close(gate);
    if (control !== undefined) close(control);
    if (
      error instanceof GateVanishedError ||
      (errorCode(error) === "ENOENT" && control === undefined)
    )
      throw new GateVanishedError("control directory was collected");
    throw error;
  }
};
export const closeLockControl = (ctx: TLockControl): void => {
  try {
    close(ctx.gate);
  } finally {
    try {
      close(ctx.control);
    } finally {
      close(ctx.parent);
    }
  }
};
export const withLockGate = <TResult>(
  ctx: TLockControl,
  operation: () => TResult,
): TResult | null => {
  if (!tryLockGate(ctx.gate)) return null;
  try {
    let gate: TFileHandle;
    try {
      gate = openChild(
        ctx.control,
        "meta.v3.lock",
        posixOpenFlags().O_RDONLY,
        0,
      );
    } catch (error) {
      if (errorCode(error) === "ENOENT")
        throw new GateVanishedError("metadata gate was collected");
      throw error;
    }
    try {
      const held = statDescriptor(ctx.gate.fd);
      const named = statDescriptor(gate.fd);
      if (held.dev !== named.dev || held.ino !== named.ino)
        throw new GateVanishedError("metadata gate changed");
    } finally {
      close(gate);
    }
    return operation();
  } finally {
    unlockGate(ctx.gate);
  }
};
export const sameChildGeneration = (
  parent: TDirectoryHandle,
  name: string,
  generation: string,
): boolean => {
  try {
    const child = childDirectory(parent, name);
    try {
      return lockGeneration(child) === generation;
    } finally {
      close(child);
    }
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
};
export const removeEmptyGeneration = (
  parent: TDirectoryHandle,
  name: string,
  generation: string,
): boolean => {
  if (!sameChildGeneration(parent, name, generation))
    return !childExists(parent, name);
  try {
    removeEmptyChild(parent, name);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOTEMPTY" || errorCode(error) === "EEXIST")
      return false;
    throw error;
  }
};
