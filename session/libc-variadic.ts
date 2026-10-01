import {
  closeSync,
  existsSync,
  mkdtempSync,
  rmdirSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import source from "./libc-variadic.c" with { type: "text" };

type TPointer = ReturnType<typeof import("bun:ffi").ptr>;

/**
 * Fixed-signature wrappers over the variadic libc calls, compiled from the
 * embedded TinyCC source (see libc-variadic.c). Every wrapper returns the
 * libc result when >= 0 and `-errno` otherwise, so callers never read errno
 * after the fact. `libcSyscall`/`libcPrctl` exist on Linux only (prctl has
 * no Darwin counterpart).
 */
export type TLibcVariadic = {
  readonly libcOpen: (path: TPointer, flags: number, mode: number) => number;
  readonly libcOpenat: (
    dirfd: number,
    path: TPointer,
    flags: number,
    mode: number,
  ) => number;
  readonly libcFcntl: (fd: number, command: number, arg: bigint) => number;
  readonly libcFchmodat: (
    dirfd: number,
    path: TPointer,
    mode: number,
    flag: number,
  ) => number;
  readonly libcSyscall?: (
    number: bigint,
    a: bigint,
    b: bigint,
    c: bigint,
    d: bigint,
    e: bigint,
    f: bigint,
  ) => bigint;
  readonly libcPrctl?: (
    option: number,
    a: bigint,
    b: bigint,
    c: bigint,
    d: bigint,
  ) => number;
};

type TFfi = typeof import("bun:ffi");
type TLibraries = { symbols: TLibcVariadic } & { close(): void };

const ffi = (): TFfi => require("bun:ffi") as TFfi;

const isSupportedLinux = (): boolean =>
  process.platform === "linux" && ["x64", "arm64"].includes(process.arch);
const isSupportedDarwin = (): boolean =>
  process.platform === "darwin" && ["x64", "arm64"].includes(process.arch);

/** Write the embedded source to an anonymous memfd and return its /proc path. */
const linuxSourcePath = (): { path: string; release: () => void } => {
  const { dlopen, FFIType, ptr } = ffi();
  const exports = {
    memfd_create: { args: [FFIType.ptr, FFIType.u32], returns: FFIType.i32 },
  } as const;
  const libc = (() => {
    for (const name of [
      "libc.so.6",
      `libc.musl-${process.arch === "arm64" ? "aarch64" : "x86_64"}.so.1`,
      "libc.so",
    ]) {
      try {
        return dlopen(name, exports);
      } catch {
        /* Try the next libc name. */
      }
    }
    throw new Error("libc-variadic: no loadable libc found");
  })();
  const name = Buffer.from("openllm-libc-variadic-source\0");
  let fd = -1;
  try {
    fd = libc.symbols.memfd_create(ptr(name), 1);
    if (fd < 0) throw new Error("libc-variadic: memfd_create failed");
    writeFileSync(fd, source);
    const path = `/proc/self/fd/${fd}`;
    return {
      path,
      release: (): void => {
        closeSync(fd);
        fd = -1;
        libc.close();
      },
    };
  } catch (error) {
    if (fd >= 0) closeSync(fd);
    libc.close();
    throw error;
  }
};

/**
 * TinyCC resolves `-lc` through `libc.so`/`libc.a`, which only exist with
 * libc6-dev/musl-dev installed — a stock Ubuntu server has neither and the
 * bare compile fails `library 'c' not found`. Point `-L` at a private dir
 * holding `libc.so` → the real runtime soname instead.
 */
const linuxLibcLink = (): { dir: string; release: () => void } | null => {
  const multiarch =
    process.arch === "arm64" ? "aarch64-linux-gnu" : "x86_64-linux-gnu";
  const musl = `libc.musl-${process.arch === "arm64" ? "aarch64" : "x86_64"}.so.1`;
  const candidates = [
    `/lib/${multiarch}/libc.so.6`,
    `/usr/lib/${multiarch}/libc.so.6`,
    "/lib/libc.so.6",
    "/usr/lib/libc.so.6",
    `/lib/${musl}`,
    `/usr/lib/${musl}`,
  ];
  const realLibc = candidates.find((path) => existsSync(path));
  if (realLibc === undefined) return null;
  const dir = mkdtempSync(join(tmpdir(), "openllm-libc-link-"));
  symlinkSync(realLibc, join(dir, "libc.so"));
  return {
    dir,
    release: (): void => {
      unlinkSync(join(dir, "libc.so"));
      rmdirSync(dir);
    },
  };
};

/** Stage the embedded source in a private tmpdir; removed by `release`. */
const darwinSourcePath = (): { path: string; release: () => void } => {
  const directory = mkdtempSync(join(tmpdir(), "openllm-libc-variadic-"));
  const path = join(directory, "libc-variadic.c");
  try {
    writeFileSync(path, source, { mode: 0o600 });
  } catch (error) {
    rmdirSync(directory);
    throw error;
  }
  return {
    path,
    release: (): void => {
      unlinkSync(path);
      rmdirSync(directory);
    },
  };
};

let compiled: TLibraries | null = null;

/** Compile the shim once per process and return its symbol table. */
export const libcVariadic = (): TLibcVariadic => {
  if (compiled !== null) return compiled.symbols;
  const linux = isSupportedLinux();
  if (!linux && !isSupportedDarwin())
    throw new Error(
      `libc-variadic: unsupported POSIX target ${process.platform}/${process.arch}`,
    );
  const { cc, FFIType } = ffi();
  const symbols = {
    libcOpen: {
      args: [FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    libcOpenat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    libcFcntl: {
      args: [FFIType.i32, FFIType.i32, FFIType.i64],
      returns: FFIType.i32,
    },
    libcFchmodat: {
      args: [FFIType.i32, FFIType.ptr, FFIType.i32, FFIType.i32],
      returns: FFIType.i32,
    },
    ...(linux
      ? {
          libcSyscall: {
            args: [
              FFIType.i64,
              FFIType.i64,
              FFIType.i64,
              FFIType.i64,
              FFIType.i64,
              FFIType.i64,
              FFIType.i64,
            ],
            returns: FFIType.i64,
          },
          libcPrctl: {
            args: [
              FFIType.i32,
              FFIType.u64,
              FFIType.u64,
              FFIType.u64,
              FFIType.u64,
            ],
            returns: FFIType.i32,
          },
        }
      : {}),
  };
  const staged = linux ? linuxSourcePath() : darwinSourcePath();
  const define: Record<string, string> = linux
    ? { LIBC_LINUX: "1" }
    : { LIBC_DARWIN: "1" };
  try {
    try {
      compiled = cc({
        source: staged.path,
        symbols,
        define,
      }) as unknown as TLibraries;
    } catch (error) {
      if (!linux) throw error;
      const link = linuxLibcLink();
      if (link === null) throw error;
      try {
        compiled = cc({
          source: staged.path,
          symbols,
          define,
          flags: [`-L${link.dir}`],
        }) as unknown as TLibraries;
      } finally {
        link.release();
      }
    }
  } finally {
    staged.release();
  }
  return compiled.symbols;
};
