import type { BigIntStats } from "node:fs";
import { closeSync, fstatSync } from "node:fs";

export type TDirectoryGeneration = Readonly<{ dev: bigint; ino: bigint }>;
export type TDirectoryHandle = {
  readonly fd: number;
  readonly generation: TDirectoryGeneration;
  closed: boolean;
};
export type TFileHandle = { readonly fd: number; closed: boolean };
export type TNativeHandle = TDirectoryHandle | TFileHandle;

type TNativeFlags = Readonly<{
  O_RDONLY: number;
  O_WRONLY: number;
  O_RDWR: number;
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
  return withNewFd(
    v.symbols.open(
      v.ffi.ptr(bytes),
      f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
      0,
    ),
    (fd) => {
      checkCloexec(fd);
      return { fd, generation: directoryGeneration(fd), closed: false };
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
  return withNewFd(
    v.symbols.openat(
      dir.fd,
      v.ffi.ptr(bytes),
      flags | v.abi.flags.O_NOFOLLOW | v.abi.flags.O_CLOEXEC,
      mode,
    ),
    (fd) => {
      checkCloexec(fd);
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
  return withNewFd(
    v.symbols.openat(
      dir.fd,
      v.ffi.ptr(bytes),
      f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
      0,
    ),
    (fd) => {
      checkCloexec(fd);
      return { fd, generation: directoryGeneration(fd), closed: false };
    },
  );
}

export function mkdirChild(dir: TDirectoryHandle, name: string): void {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  if (v.symbols.mkdirat(dir.fd, v.ffi.ptr(bytes), 0o700) < 0)
    throw nativeError("mkdirat");
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
}

export function unlinkChild(dir: TDirectoryHandle, name: string): void {
  ensureOpen(dir);
  const v = n();
  const bytes = basename(name);
  if (v.symbols.unlinkat(dir.fd, v.ffi.ptr(bytes), 0) < 0)
    throw nativeError("unlinkat");
}

export function removeEmptyChild(parent: TDirectoryHandle, name: string): void {
  ensureOpen(parent);
  const v = n();
  const bytes = basename(name);
  if (
    v.symbols.unlinkat(parent.fd, v.ffi.ptr(bytes), v.abi.flags.AT_REMOVEDIR) <
    0
  )
    throw nativeError("unlinkat(AT_REMOVEDIR)");
}

export function listDirectory(
  dir: TDirectoryHandle,
  maxEntries = 4096,
): string[] {
  ensureOpen(dir);
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1)
    throw new RangeError("dir-lock-fs: invalid listing limit");
  const v = n();
  const f = v.abi.flags;
  const dot = cString(".");
  const fd = v.symbols.openat(
    dir.fd,
    v.ffi.ptr(dot),
    f.O_RDONLY | f.O_DIRECTORY | f.O_NOFOLLOW | f.O_CLOEXEC,
    0,
  );
  if (fd < 0) throw nativeError("openat(.)");
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
    const closeError = closed < 0 ? nativeError("closedir") : undefined;
    if (firstError) throw firstError;
    if (closeError) throw closeError;
    return names;
  } catch (error) {
    if (!ownedByStream)
      try {
        closeSync(fd);
      } catch {
        /* Preserve first error. */
      }
    throw error;
  }
}

export function tryLockGate(handle: TFileHandle): boolean {
  ensureOpen(handle);
  if (n().symbols.flock(handle.fd, 2 | 4) === 0) return true; // LOCK_EX | LOCK_NB
  const error = nativeError("flock(LOCK_EX|LOCK_NB)");
  if (error.code === "EAGAIN") return false;
  throw error;
}

export function unlockGate(handle: TFileHandle): void {
  ensureOpen(handle);
  if (n().symbols.flock(handle.fd, 8) < 0) throw nativeError("flock(LOCK_UN)");
}

export function close(handle: TNativeHandle): void {
  if (handle.closed) return;
  handle.closed = true;
  closeSync(handle.fd);
}
