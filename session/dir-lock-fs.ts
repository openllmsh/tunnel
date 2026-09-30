import type { BigIntStats } from "node:fs";
import { closeSync, fstatSync } from "node:fs";
import { join } from "node:path";

export type TDirectoryGeneration = Readonly<{ dev: bigint; ino: bigint }>;
export type TDirectoryHandle = {
  readonly fd: number;
  readonly generation: TDirectoryGeneration;
  closed: boolean;
};
export type TFileHandle = { readonly fd: number; closed: boolean };
export type TNativeHandle = TDirectoryHandle | TFileHandle;
export type TDirLockFsEvent = Readonly<{
  phase: "before" | "after";
  operation:
    | "openDirectory"
    | "openDirectoryChild"
    | "openChild"
    | "mkdirChild"
    | "linkChild"
    | "unlinkChild"
    | "removeEmptyChild"
    | "listDirectory"
    | "flockGate";
  path?: string;
  name?: string;
  dirFd?: number;
  fd?: number;
}>;
let testHook: ((event: TDirLockFsEvent) => void) | null = null;
let unlockFaultForTests: (() => string | null) | null = null;
const fdPaths = new Map<number, string>();
export function setDirLockFsHookForTests(
  hook: ((event: TDirLockFsEvent) => void) | null,
): void {
  testHook = hook;
}
/**
 * Test seam. When set, the hook runs before each LOCK_UN attempt and returns
 * an errno code to fail that attempt, or null for the real call. An injected
 * failure does not touch the descriptor: the gate stays locked, as a real
 * interrupted call would leave it. Clear with setDirLockUnlockFaultForTests(null).
 */
export function setDirLockUnlockFaultForTests(
  fault: (() => string | null) | null,
): void {
  unlockFaultForTests = fault;
}
const injectedFault = (code: string): Error & { code: string } =>
  Object.assign(new Error(`dir-lock-fs: injected fault: ${code}`), { code });
function emit(event: TDirLockFsEvent): void {
  testHook?.(event);
}
function childPath(dir: TDirectoryHandle, name: string): string | undefined {
  const parent = fdPaths.get(dir.fd);
  return parent === undefined ? undefined : join(parent, name);
}

type TNativeFlags = Readonly<{
  O_RDONLY: number;
  O_WRONLY: number;
  O_RDWR: number;
  O_NONBLOCK: number;
  O_CREAT: number;
  O_EXCL: number;
  O_DIRECTORY: number;
  O_NOFOLLOW: number;
  O_CLOEXEC: number;
  AT_REMOVEDIR: number;
}>;

const linuxX64: TNativeFlags = {
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_NONBLOCK: 0x800,
  O_CREAT: 0x40,
  O_EXCL: 0x80,
  O_DIRECTORY: 0x10000,
  O_NOFOLLOW: 0x20000,
  O_CLOEXEC: 0x80000,
  AT_REMOVEDIR: 0x200,
};
const linuxArm64: TNativeFlags = {
  ...linuxX64,
  O_DIRECTORY: 0x4000,
  O_NOFOLLOW: 0x8000,
};
const darwin: TNativeFlags = {
  O_RDONLY: 0,
  O_WRONLY: 1,
  O_RDWR: 2,
  O_NONBLOCK: 0x4,
  O_CREAT: 0x200,
  O_EXCL: 0x800,
  O_DIRECTORY: 0x100000,
  O_NOFOLLOW: 0x100,
  O_CLOEXEC: 0x1000000,
  AT_REMOVEDIR: 0x80,
};

function target(): {
  flags: TNativeFlags;
  library: string;
  readSymbol: string;
  openSymbol: string;
  errnoSymbol: string;
  darwin: boolean;
} {
  if (process.platform === "linux" && process.arch === "x64")
    return {
      flags: linuxX64,
      library: "libc.so.6",
      readSymbol: "readdir64",
      openSymbol: "fdopendir",
      errnoSymbol: "__errno_location",
      darwin: false,
    };
  if (process.platform === "linux" && process.arch === "arm64")
    return {
      flags: linuxArm64,
      library: "libc.so.6",
      readSymbol: "readdir64",
      openSymbol: "fdopendir",
      errnoSymbol: "__errno_location",
      darwin: false,
    };
  if (process.platform === "darwin" && process.arch === "x64")
    return {
      flags: darwin,
      library: "/usr/lib/libSystem.B.dylib",
      readSymbol: "readdir$INODE64",
      openSymbol: "fdopendir$INODE64",
      errnoSymbol: "__error",
      darwin: true,
    };
  if (process.platform === "darwin" && process.arch === "arm64")
    return {
      flags: darwin,
      library: "/usr/lib/libSystem.B.dylib",
      readSymbol: "readdir",
      openSymbol: "fdopendir",
      errnoSymbol: "__error",
      darwin: true,
    };
  throw new Error(
    `dir-lock-fs: unsupported POSIX target ${process.platform}/${process.arch}`,
  );
}

export function posixOpenFlags(): TNativeFlags {
  return target().flags;
}

type TNative = ReturnType<typeof loadNative>;
let native: TNative | undefined;

function loadNative() {
  const abi = target(); // Guard before even loading bun:ffi on Windows.
  const ffi = require("bun:ffi") as typeof import("bun:ffi");
  const { FFIType } = ffi;
  const lib = ffi.dlopen(abi.library, {
    open: {
      args: [FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    openat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    mkdirat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    linkat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    unlinkat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32],
      returns: FFIType.i32,
    },
    fcntl: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
    flock: { args: [FFIType.i32, FFIType.i32], returns: FFIType.i32 },
    getpgrp: { args: [], returns: FFIType.i32 },
    closedir: { args: [FFIType.ptr], returns: FFIType.i32 },
    memset: {
      args: [FFIType.ptr, FFIType.i32, FFIType.u64],
      returns: FFIType.ptr,
    },
    [abi.openSymbol]: { args: [FFIType.i32], returns: FFIType.ptr },
    [abi.readSymbol]: { args: [FFIType.ptr], returns: FFIType.ptr },
    [abi.errnoSymbol]: { args: [], returns: FFIType.ptr },
  });
  return { ffi, symbols: lib.symbols, abi };
}

function n(): TNative {
  native ??= loadNative();
  return native;
}

export const currentProcessGroup = (): number => {
  const pid = n().symbols.getpgrp();
  if (pid <= 1 || pid > 2147483647)
    throw new Error("dir-lock-fs: invalid process group");
  return pid;
};

function cString(value: string): Uint8Array {
  return Buffer.from(`${value}\0`, "utf8");
}

function basename(name: string): Uint8Array {
  if (
    !name ||
    name === "." ||
    name === ".." ||
    name.includes("/") ||
    name.includes("\0")
  )
    throw new TypeError("dir-lock-fs: expected one nonempty basename");
  return cString(name);
}

function ensureOpen(handle: TNativeHandle): void {
  if (handle.closed) throw new Error("dir-lock-fs: descriptor already closed");
}

function errno(): number {
  const v = n();
  const pointer = v.symbols[v.abi.errnoSymbol]();
  if (!pointer) throw new Error("dir-lock-fs: errno accessor returned null");
  return v.ffi.read.i32(pointer);
}

const errnoCodes: Record<number, string> = {
  1: "EPERM",
  2: "ENOENT",
  4: "EINTR",
  5: "EIO",
  9: "EBADF",
  11: "EAGAIN",
  13: "EACCES",
  17: "EEXIST",
  20: "ENOTDIR",
  21: "EISDIR",
  22: "EINVAL",
  24: "EMFILE",
  28: "ENOSPC",
  30: "EROFS",
  39: "ENOTEMPTY",
  40: "ELOOP",
  95: "ENOTSUP",
};

function nativeError(
  operation: string,
): Error & { errno: number; code: string } {
  const number = errno();
  const darwinCode = n().abi.darwin
    ? { 35: "EAGAIN", 45: "ENOTSUP", 62: "ELOOP", 66: "ENOTEMPTY" }[number]
    : undefined;
  const code = darwinCode ?? errnoCodes[number] ?? `ERRNO_${number}`;
  return Object.assign(
    new Error(`dir-lock-fs: ${operation} failed: ${code} (${number})`),
    { errno: number, code },
  );
}

function checkCloexec(fd: number): void {
  const value = n().symbols.fcntl(fd, 1); // F_GETFD
  if (value < 0) throw nativeError("fcntl(F_GETFD)");
  if ((value & 1) === 0) throw new Error("dir-lock-fs: FD_CLOEXEC missing");
}

function withNewFd<T>(fd: number, operation: (fd: number) => T): T {
  if (fd < 0) throw nativeError("open");
  try {
    return operation(fd);
  } catch (error) {
    fdPaths.delete(fd);
    try {
      closeSync(fd);
    } catch {
      /* Preserve first error. */
    }
    throw error;
  }
}

export function statDescriptor(fd: number): BigIntStats {
  return fstatSync(fd, { bigint: true });
}

function directoryGeneration(fd: number): TDirectoryGeneration {
  const stat = fstatSync(fd, { bigint: true });
  if (!stat.isDirectory())
    throw new Error("dir-lock-fs: descriptor is not a directory");
  return { dev: stat.dev, ino: stat.ino };
}

function sameGeneration(
  a: TDirectoryGeneration,
  b: TDirectoryGeneration,
): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

export function openDirectory(path: string): TDirectoryHandle {
  if (path.includes("\0")) throw new TypeError("dir-lock-fs: NUL path");
  const v = n();
  const f = v.abi.flags;
  const bytes = cString(path);
  emit({ phase: "before", operation: "openDirectory", path });
  return withNewFd(
    v.symbols.open(
      v.ffi.ptr(bytes),
      f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
      0,
    ),
    (fd) => {
      checkCloexec(fd);
      const generation = directoryGeneration(fd);
      fdPaths.set(fd, path);
      emit({ phase: "after", operation: "openDirectory", path, fd });
      return { fd, generation, closed: false };
    },
  );
}

export function openChild(
  dir: TDirectoryHandle,
  name: string,
  flags: number,
  mode = 0o600,
): TFileHandle {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  const path = childPath(dir, name);
  emit({ phase: "before", operation: "openChild", path, name, dirFd: dir.fd });
  return withNewFd(
    v.symbols.openat(
      dir.fd,
      v.ffi.ptr(bytes),
      flags |
        v.abi.flags.O_NONBLOCK |
        v.abi.flags.O_NOFOLLOW |
        v.abi.flags.O_CLOEXEC,
      mode,
    ),
    (fd) => {
      checkCloexec(fd);
      if (path !== undefined) fdPaths.set(fd, path);
      emit({
        phase: "after",
        operation: "openChild",
        path,
        name,
        dirFd: dir.fd,
        fd,
      });
      return { fd, closed: false };
    },
  );
}

export function openDirectoryChild(
  dir: TDirectoryHandle,
  name: string,
): TDirectoryHandle {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  const f = v.abi.flags;
  const path = childPath(dir, name);
  emit({
    phase: "before",
    operation: "openDirectoryChild",
    path,
    name,
    dirFd: dir.fd,
  });
  return withNewFd(
    v.symbols.openat(
      dir.fd,
      v.ffi.ptr(bytes),
      f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
      0,
    ),
    (fd) => {
      checkCloexec(fd);
      const generation = directoryGeneration(fd);
      if (path !== undefined) fdPaths.set(fd, path);
      emit({
        phase: "after",
        operation: "openDirectoryChild",
        path,
        name,
        dirFd: dir.fd,
        fd,
      });
      return { fd, generation, closed: false };
    },
  );
}

export function mkdirChild(dir: TDirectoryHandle, name: string): void {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  const path = childPath(dir, name);
  emit({ phase: "before", operation: "mkdirChild", path, name, dirFd: dir.fd });
  if (v.symbols.mkdirat(dir.fd, v.ffi.ptr(bytes), 0o700) < 0)
    throw nativeError("mkdirat");
  emit({ phase: "after", operation: "mkdirChild", path, name, dirFd: dir.fd });
}

export function linkChild(
  sourceDir: TDirectoryHandle,
  source: string,
  targetDir: TDirectoryHandle,
  targetName: string,
): void {
  ensureOpen(sourceDir);
  ensureOpen(targetDir);
  const v = n();
  const sourceBytes = basename(source);
  const targetBytes = basename(targetName);
  const path = childPath(targetDir, targetName);
  emit({
    phase: "before",
    operation: "linkChild",
    path,
    name: targetName,
    dirFd: targetDir.fd,
  });
  if (
    v.symbols.linkat(
      sourceDir.fd,
      v.ffi.ptr(sourceBytes),
      targetDir.fd,
      v.ffi.ptr(targetBytes),
      0,
    ) < 0
  )
    throw nativeError("linkat");
  emit({
    phase: "after",
    operation: "linkChild",
    path,
    name: targetName,
    dirFd: targetDir.fd,
  });
}

export function unlinkChild(dir: TDirectoryHandle, name: string): void {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  const path = childPath(dir, name);
  emit({
    phase: "before",
    operation: "unlinkChild",
    path,
    name,
    dirFd: dir.fd,
  });
  if (v.symbols.unlinkat(dir.fd, v.ffi.ptr(bytes), 0) < 0)
    throw nativeError("unlinkat");
  emit({ phase: "after", operation: "unlinkChild", path, name, dirFd: dir.fd });
}

export function removeEmptyChild(parent: TDirectoryHandle, name: string): void {
  ensureOpen(parent);
  const v = n();
  const bytes = basename(name);
  const path = childPath(parent, name);
  emit({
    phase: "before",
    operation: "removeEmptyChild",
    path,
    name,
    dirFd: parent.fd,
  });
  if (
    v.symbols.unlinkat(parent.fd, v.ffi.ptr(bytes), v.abi.flags.AT_REMOVEDIR) <
    0
  )
    throw nativeError("unlinkat(AT_REMOVEDIR)");
  emit({
    phase: "after",
    operation: "removeEmptyChild",
    path,
    name,
    dirFd: parent.fd,
  });
}

export function listDirectory(
  dir: TDirectoryHandle,
  maxEntries = 4096,
): string[] {
  ensureOpen(dir);
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 0)
    throw new RangeError("dir-lock-fs: invalid listing limit");
  const v = n();
  const f = v.abi.flags;
  const path = fdPaths.get(dir.fd);
  emit({ phase: "before", operation: "listDirectory", path, dirFd: dir.fd });
  const dot = cString(".");
  const fd = v.symbols.openat(
    dir.fd,
    v.ffi.ptr(dot),
    f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
    0,
  );
  if (fd < 0) throw nativeError("openat(.)");
  if (path !== undefined) fdPaths.set(fd, path);
  let ownedByStream = false;
  try {
    checkCloexec(fd);
    if (!sameGeneration(dir.generation, directoryGeneration(fd)))
      throw new Error("dir-lock-fs: directory generation changed");
    const stream = v.symbols[v.abi.openSymbol](fd);
    if (!stream) throw nativeError(v.abi.openSymbol);
    ownedByStream = true;
    // fdopendir transfers ownership of fd to the stream.
    let firstError: unknown;
    const names: string[] = [];
    try {
      while (true) {
        const errnoPointer = v.symbols[v.abi.errnoSymbol]();
        if (!errnoPointer)
          throw new Error("dir-lock-fs: errno accessor returned null");
        v.symbols.memset(errnoPointer, 0, 4);
        const record = v.symbols[v.abi.readSymbol](stream);
        if (!record) {
          if (errno() !== 0) throw nativeError(v.abi.readSymbol);
          break;
        }
        const reclen = v.ffi.read.u16(record, 16);
        const nameOffset = v.abi.darwin ? 21 : 19;
        if (reclen <= nameOffset || reclen > 4096)
          throw new Error("dir-lock-fs: invalid directory record length");
        const bytes = new Uint8Array(
          v.ffi.toArrayBuffer(
            record as ReturnType<typeof v.ffi.ptr>,
            0,
            reclen,
          ),
        );
        let length: number;
        if (v.abi.darwin) {
          length = new DataView(bytes.buffer).getUint16(18, true);
          if (
            length < 1 ||
            nameOffset + length >= reclen ||
            bytes[nameOffset + length] !== 0
          )
            throw new Error("dir-lock-fs: invalid Darwin directory name");
        } else {
          length = bytes.indexOf(0, nameOffset) - nameOffset;
          if (length < 1)
            throw new Error("dir-lock-fs: unterminated Linux directory name");
        }
        const name = new TextDecoder("utf-8", { fatal: true }).decode(
          bytes.subarray(nameOffset, nameOffset + length),
        );
        if (name.includes("/") || name.includes("\0"))
          throw new Error("dir-lock-fs: invalid directory name");
        if (name !== "." && name !== "..") {
          if (names.length >= maxEntries)
            throw new Error("dir-lock-fs: directory listing limit exceeded");
          names.push(name);
        }
      }
    } catch (error) {
      firstError = error;
    }
    const closed = v.symbols.closedir(stream as ReturnType<typeof v.ffi.ptr>);
    fdPaths.delete(fd);
    const closeError = closed < 0 ? nativeError("closedir") : undefined;
    if (firstError) throw firstError;
    if (closeError) throw closeError;
    emit({
      phase: "after",
      operation: "listDirectory",
      path,
      dirFd: dir.fd,
      fd,
    });
    return names;
  } catch (error) {
    if (!ownedByStream) {
      fdPaths.delete(fd);
      try {
        closeSync(fd);
      } catch {
        /* Preserve first error. */
      }
    }
    throw error;
  }
}

// A signal interrupt is transient. Retry it a bounded number of times. A
// gate that stays interrupted reports busy so the caller retries inside its
// own deadline.
const gateInterruptRetries = 4;
const interrupted = (error: unknown): boolean =>
  (error as NodeJS.ErrnoException | undefined)?.code === "EINTR";

export function tryLockGate(handle: TFileHandle): boolean {
  ensureOpen(handle);
  const v = n();
  for (let attempt = 0; ; attempt++) {
    let locked = false;
    try {
      emit({ phase: "before", operation: "flockGate", fd: handle.fd });
      locked = v.symbols.flock(handle.fd, 2 | 4) === 0; // LOCK_EX | LOCK_NB
    } catch (error) {
      if (!interrupted(error)) throw error;
      if (attempt < gateInterruptRetries - 1) continue;
      return false;
    }
    if (locked) return true;
    const error = nativeError("flock(LOCK_EX|LOCK_NB)");
    if (error.code === "EAGAIN") return false;
    if (error.code === "EINTR") {
      if (attempt < gateInterruptRetries - 1) continue;
      return false;
    }
    throw error;
  }
}

export function unlockGate(handle: TFileHandle): void {
  ensureOpen(handle);
  // LOCK_UN never waits on another process. An interrupted call did not run,
  // so the lock stays held and the retry is safe. Retry until the call is
  // not interrupted: a thrown EINTR here would leave a granted claim with no
  // way to release it. Other errors are real faults and propagate.
  for (;;) {
    const injected = unlockFaultForTests?.() ?? null;
    if (injected !== null) {
      if (injected !== "EINTR") throw injectedFault(injected);
      continue;
    }
    if (n().symbols.flock(handle.fd, 8) >= 0) return; // LOCK_UN
    const error = nativeError("flock(LOCK_UN)");
    if (error.code !== "EINTR") throw error;
  }
}

export function close(handle: TNativeHandle): void {
  if (handle.closed) return;
  handle.closed = true;
  fdPaths.delete(handle.fd);
  closeSync(handle.fd);
}
