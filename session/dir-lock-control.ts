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
  parseDirLockControlName,
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
  let control: TDirectoryHandle | undefined;
  let gate: TFileHandle | undefined;
  try {
    const parentStat = statDescriptor(parent.fd);
    if (
      parentStat.uid !== BigInt(process.getuid?.() ?? -1) ||
      (parentStat.mode & 0o022n) !== 0n
    )
      throw new LockUnknownError("lock parent is writable by another user");
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
      if (errorCode(error) !== "EEXIST") throw error;
      gate = openChild(control, "meta.v3.lock", posixOpenFlags().O_RDWR, 0);
    }
    const stat = statDescriptor(gate.fd);
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
    close(parent);
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
    const gate = openChild(
      ctx.control,
      "meta.v3.lock",
      posixOpenFlags().O_RDONLY,
      0,
    );
    try {
      const held = statDescriptor(ctx.gate.fd);
      const named = statDescriptor(gate.fd);
      if (held.dev !== named.dev || held.ino !== named.ino)
        throw new LockUnknownError("metadata gate changed");
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

/**
 * Remove idle control directories so a product uninstall can delete an empty
 * state root. The lock protocol does not call this. A control is idle when
 * it holds only the gate. Any other parent entry or control entry stays.
 * Returns true when the parent is empty or already absent.
 */
export const removeIdleLockControls = (parentPath: string): boolean => {
  let parent: TDirectoryHandle;
  try {
    parent = openPinnedPath(parentPath);
  } catch (error) {
    return errorCode(error) === "ENOENT";
  }
  try {
    let names: string[];
    try {
      names = checkedNames(parent, 4096);
    } catch {
      return false;
    }
    if (names.length === 0) return true;
    if (names.some((name) => parseDirLockControlName(name) === null))
      return false;
    for (const name of names) {
      if (!idleGateOnly(parent, name)) return false;
    }
    for (const name of names) {
      const dir = childDirectory(parent, name);
      try {
        const children = checkedNames(dir, 8);
        if (children.length !== 1 || children[0] !== "meta.v3.lock")
          return false;
        unlinkChild(dir, "meta.v3.lock");
      } finally {
        close(dir);
      }
      try {
        removeEmptyChild(parent, name);
      } catch {
        // A crash or a failed rmdir can leave a control with no gate.
        return false;
      }
    }
    try {
      return checkedNames(parent, 4096).length === 0;
    } catch {
      return false;
    }
  } finally {
    close(parent);
  }
};

/** True when this control directory holds only a private gate file. */
const idleGateOnly = (parent: TDirectoryHandle, name: string): boolean => {
  let dir: TDirectoryHandle;
  try {
    dir = childDirectory(parent, name);
  } catch {
    return false;
  }
  try {
    const children = checkedNames(dir, 8);
    if (children.length !== 1 || children[0] !== "meta.v3.lock") return false;
    const gate = openChild(dir, "meta.v3.lock", posixOpenFlags().O_RDONLY, 0);
    try {
      const stat = statDescriptor(gate.fd);
      const uid = BigInt(process.getuid?.() ?? -1);
      return (
        stat.isFile() &&
        stat.nlink === 1n &&
        stat.uid === uid &&
        (stat.mode & 0o077n) === 0n
      );
    } finally {
      close(gate);
    }
  } catch {
    return false;
  } finally {
    close(dir);
  }
};
