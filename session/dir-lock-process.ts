import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import source from "./dir-lock-process.c" with { type: "text" };
import { processStartIdentity } from "./local-runtime";

export type TDarwinProcessSnapshot = {
  readonly state: "live" | "dead" | "unknown";
  readonly uid: number | null;
  readonly parentPid: number | null;
  readonly identity: string | null;
  readonly comm: string | null;
  readonly argv: readonly string[] | null;
};

type TBindings = {
  readonly dl_list_pids: (
    out: ReturnType<typeof import("bun:ffi").ptr>,
    capacity: number,
  ) => number;
  readonly dl_proc_snapshot: (
    pid: number,
    out: ReturnType<typeof import("bun:ffi").ptr>,
    capacity: number,
  ) => number;
  readonly dl_proc_argv: (
    pid: number,
    out: ReturnType<typeof import("bun:ffi").ptr>,
    capacity: number,
  ) => number;
};
const pointer = (bytes: Uint8Array): ReturnType<typeof import("bun:ffi").ptr> =>
  (require("bun:ffi") as typeof import("bun:ffi")).ptr(bytes);
let bindings: TBindings | null = null;
const load = (): TBindings => {
  if (bindings !== null) return bindings;
  if (process.platform !== "darwin")
    throw new Error("Darwin process adapter requires macOS");
  const { cc, FFIType } = require("bun:ffi") as typeof import("bun:ffi");
  const directory = mkdtempSync(join(tmpdir(), "openllm-lock-proc-"));
  const path = join(directory, "dir-lock-process.c");
  writeFileSync(path, source, { mode: 0o600 });
  try {
    const library = cc({
      source: path,
      library: ["proc"],
      symbols: {
        dl_list_pids: {
          args: [FFIType.ptr, FFIType.i32],
          returns: FFIType.i32,
        },
        dl_proc_snapshot: {
          args: [FFIType.i32, FFIType.ptr, FFIType.i32],
          returns: FFIType.i32,
        },
        dl_proc_argv: {
          args: [FFIType.i32, FFIType.ptr, FFIType.i32],
          returns: FFIType.i32,
        },
      },
    });
    bindings = library.symbols as unknown as TBindings;
    return bindings;
  } finally {
    unlinkSync(path);
    rmdirSync(directory);
  }
};
export const listDarwinPids = (): number[] => {
  const buffer = new Uint8Array(32769 * 4);
  const count = load().dl_list_pids(pointer(buffer), 32769);
  if (count < 0 || count >= 32769)
    throw new Error("incomplete Darwin process enumeration");
  const view = new DataView(buffer.buffer);
  const pids: number[] = [];
  for (let index = 0; index < count; index++) {
    const pid = view.getInt32(index * 4, true);
    if (pid > 0) pids.push(pid);
  }
  return pids;
};
const utf8 = new TextDecoder("utf-8", { fatal: true });
export const observeDarwinProcess = (pid: number): TDarwinProcessSnapshot => {
  const unknown: TDarwinProcessSnapshot = {
    state: "unknown",
    uid: null,
    parentPid: null,
    identity: null,
    comm: null,
    argv: null,
  };
  if (process.platform !== "darwin") return unknown;
  const first = new Uint8Array(44);
  const size = load().dl_proc_snapshot(pid, pointer(first), first.length);
  if (size === 0) return { ...unknown, state: "dead" };
  if (size !== 44) return unknown;
  const view = new DataView(first.buffer);
  const uid = view.getUint32(0, true);
  const parentPid = view.getUint32(4, true);
  const status = view.getUint32(8, true);
  if (status === 5)
    return { ...unknown, state: "dead", uid, parentPid };
  let comm: string | null = null;
  try {
    comm = utf8.decode(first.subarray(28, 44)).split("\0")[0] || null;
  } catch {
    /* Unknown kind. */
  }
  const data = new Uint8Array(1048576);
  const length = load().dl_proc_argv(pid, pointer(data), data.length);
  let argv: string[] | null = null;
  if (length > 0 && data[length - 1] === 0) {
    try {
      argv = utf8.decode(data.subarray(0, length - 1)).split("\0");
    } catch {
      /* Unknown kind. */
    }
  }
  const second = new Uint8Array(44);
  if (
    load().dl_proc_snapshot(pid, pointer(second), second.length) !== 44 ||
    !first.subarray(0, 28).every((byte, index) => byte === second[index])
  )
    return { ...unknown, uid, parentPid };
  const identity = processStartIdentity(pid);
  return {
    state: "live",
    uid,
    parentPid,
    identity: typeof identity === "string" ? identity : null,
    comm,
    argv,
  };
};
