/** In-process Win32 named-pipe server with an explicit owner-only DACL. */

import { cc, dlopen, FFIType } from "bun:ffi";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import nativeSource from "./windows-session-native.c" with { type: "text" };

export type TWindowsSessionPipeConnection = {
  onData(handler: (chunk: Uint8Array) => void): () => void;
  onClose(handler: () => void): () => void;
  onDrain(handler: () => void): () => void;
  /** Returns -1 while bytes remain queued, otherwise 1. */
  write(chunk: Uint8Array): number;
  close(timeoutMs?: number): void;
};

export type TWindowsSessionPipeServer = {
  close(timeoutMs?: number): Promise<void>;
};

type TWindowsSessionPipeClient = {
  onData(handler: (chunk: Uint8Array) => void): () => void;
  onClose(handler: () => void): () => void;
  write(chunk: Uint8Array): void;
  close(): void;
};

type TNativeClientBindings = {
  readonly ws_build_pipe_security: (
    attributes: Uint8Array,
    descriptor: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_create_named_pipe: (
    name: Uint8Array,
    openMode: number,
    pipeMode: number,
    maxInstances: number,
    outSize: number,
    inSize: number,
    timeout: number,
    attributes: Uint8Array,
    handle: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_pipe_open: (
    name: Uint8Array,
    pid: number,
    creation: bigint,
    outHandle: Uint8Array,
    outError: Uint8Array,
  ) => number;
  readonly ws_pipe_read: (
    handle: bigint,
    buffer: Uint8Array,
    capacity: number,
    read: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_pipe_connect: (handle: bigint, error: Uint8Array) => number;
  readonly ws_pipe_disconnect: (handle: bigint, error: Uint8Array) => number;
  readonly ws_pipe_write: (
    handle: bigint,
    buffer: Uint8Array,
    length: number,
    written: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_pipe_close: (handle: bigint, error: Uint8Array) => number;
  readonly ws_verify_directory_owner: (
    path: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_verify_session_file: (
    path: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_secure_directory: (path: Uint8Array, error: Uint8Array) => number;
  readonly ws_create_session_directory: (
    path: Uint8Array,
    error: Uint8Array,
  ) => number;
  readonly ws_create_session_file: (
    path: Uint8Array,
    content: Uint8Array,
    length: number,
    error: Uint8Array,
  ) => number;
};

type TCompiledNative = {
  readonly symbols: TNativeClientBindings;
  readonly close: () => void;
};

let nativeBindings: TNativeClientBindings | null = null;
let nativeLibrary: TCompiledNative | null = null;

const loadNativeBindings = (): TNativeClientBindings => {
  if (nativeBindings !== null) {
    if (nativeLibrary === null)
      throw new Error("Windows session native library was released");
    return nativeBindings;
  }
  if (process.platform !== "win32")
    throw new Error("Windows session native bindings require Windows");
  const directory = mkdtempSync(join(tmpdir(), "openllm-session-native-"));
  const source = join(directory, "windows-session-native.c");
  writeFileSync(source, nativeSource, { mode: 0o600 });
  try {
    const library = cc({
      source,
      library: ["advapi32"],
      symbols: {
        ws_build_pipe_security: {
          args: [FFIType.ptr, FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_create_named_pipe: {
          args: [
            FFIType.ptr,
            FFIType.u32,
            FFIType.u32,
            FFIType.u32,
            FFIType.u32,
            FFIType.u32,
            FFIType.u32,
            FFIType.ptr,
            FFIType.ptr,
            FFIType.ptr,
          ],
          returns: FFIType.i32,
        },
        ws_pipe_open: {
          args: [
            FFIType.ptr,
            FFIType.u32,
            FFIType.u64,
            FFIType.ptr,
            FFIType.ptr,
          ],
          returns: FFIType.i32,
        },
        ws_pipe_connect: {
          args: [FFIType.u64, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_pipe_disconnect: {
          args: [FFIType.u64, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_pipe_read: {
          args: [
            FFIType.u64,
            FFIType.ptr,
            FFIType.u32,
            FFIType.ptr,
            FFIType.ptr,
          ],
          returns: FFIType.i32,
        },
        ws_pipe_write: {
          args: [
            FFIType.u64,
            FFIType.ptr,
            FFIType.u32,
            FFIType.ptr,
            FFIType.ptr,
          ],
          returns: FFIType.i32,
        },
        ws_pipe_close: {
          args: [FFIType.u64, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_verify_session_file: {
          args: [FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_verify_directory_owner: {
          args: [FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_secure_directory: {
          args: [FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_create_session_directory: {
          args: [FFIType.ptr, FFIType.ptr],
          returns: FFIType.i32,
        },
        ws_create_session_file: {
          args: [FFIType.ptr, FFIType.ptr, FFIType.u32, FFIType.ptr],
          returns: FFIType.i32,
        },
      },
    }) as unknown as TCompiledNative;
    nativeLibrary = library;
    nativeBindings = library.symbols;
    return library.symbols;
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

const winError = (result: Uint8Array): number =>
  new DataView(result.buffer).getUint32(0, true);

const pipeFrameError = (operation: string, code: number): Error =>
  new Error(`${operation} failed with Win32 error ${code}`);

/** Poll idle pipes less often. Use one timer. Reset the delay on I/O. */
const createWindowsPipePoller = (
  poll: () => void,
): { wake(): void; stop(): void } => {
  let delayMs = 4;
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | null = null;
  const schedule = (): void => {
    if (stopped) return;
    timer = setTimeout(() => {
      timer = null;
      poll();
      if (timer === null) {
        delayMs = Math.min(100, delayMs * 2);
        schedule();
      }
    }, delayMs);
    timer.unref?.();
  };
  schedule();
  return {
    wake: (): void => {
      if (stopped) return;
      if (delayMs === 4 && timer !== null) return;
      delayMs = 4;
      if (timer !== null) clearTimeout(timer);
      schedule();
    },
    stop: (): void => {
      stopped = true;
      if (timer !== null) clearTimeout(timer);
      timer = null;
    },
  };
};

/** Dial and authenticate the same native pipe handle that carries all traffic. */
export const openVerifiedWindowsSessionPipe = (
  endpoint: string,
  expectedPid: number,
  expectedCreationIdentity: string,
): TWindowsSessionPipeClient => {
  if (
    !Number.isSafeInteger(expectedPid) ||
    expectedPid <= 0 ||
    expectedPid > 0xffff_ffff
  )
    throw new Error("invalid expected Windows session-host pid");
  if (!/^\d+$/.test(expectedCreationIdentity))
    throw new Error("invalid expected Windows session-host creation identity");
  const expectedCreation = BigInt(expectedCreationIdentity);
  if (expectedCreation <= 0n || expectedCreation > 0xffff_ffff_ffff_ffffn)
    throw new Error("invalid expected Windows session-host creation identity");
  const api = loadNativeBindings();
  const handleOut = new Uint8Array(8);
  const errorOut = new Uint8Array(4);
  if (
    api.ws_pipe_open(
      wide(endpoint),
      expectedPid,
      expectedCreation,
      handleOut,
      errorOut,
    ) === 0
  )
    throw pipeFrameError(
      "CreateFileW / named-pipe identity verification",
      winError(errorOut),
    );
  const handle = new DataView(handleOut.buffer).getBigUint64(0, true);
  const readBuffer = new Uint8Array(PIPE_BUFFER_BYTES);
  const readOut = new Uint8Array(4);
  const error = new Uint8Array(4);
  const writeOut = new Uint8Array(4);
  const writes: Uint8Array[] = [];
  let queuedBytes = 0;
  let writeOffset = 0;
  let ended = false;
  let closeRequested = false;
  let closeTimer: ReturnType<typeof setTimeout> | null = null;
  const dataHandlers = new Set<(chunk: Uint8Array) => void>();
  const closeHandlers = new Set<() => void>();
  const finish = (): void => {
    if (ended) return;
    ended = true;
    poller.stop();
    if (closeTimer !== null) clearTimeout(closeTimer);
    writes.length = 0;
    queuedBytes = 0;
    api.ws_pipe_close(handle, error);
    for (const handler of closeHandlers) {
      try {
        handler();
      } catch {
        /* Handle cleanup is already complete. */
      }
    }
  };
  const flush = (): void => {
    while (!ended && writes.length > 0) {
      const current = writes[0];
      if (current === undefined) return;
      const remaining = current.subarray(writeOffset);
      writeOut.fill(0);
      if (
        api.ws_pipe_write(
          handle,
          remaining,
          remaining.byteLength,
          writeOut,
          error,
        ) === 0
      ) {
        const code = winError(error);
        if (code === ERROR_NO_DATA) {
          finish();
          return;
        }
        finish();
        return;
      }
      const count = winError(writeOut);
      if (count === 0) return;
      poller.wake();
      writeOffset += count;
      queuedBytes -= count;
      if (writeOffset >= current.byteLength) {
        writes.shift();
        writeOffset = 0;
      }
    }
    if (!ended && closeRequested && writes.length === 0) finish();
  };
  const poll = (): void => {
    if (ended) return;
    flush();
    if (ended) return;
    for (let index = 0; index < 4 && !ended; index += 1) {
      readOut.fill(0);
      if (
        api.ws_pipe_read(
          handle,
          readBuffer,
          readBuffer.byteLength,
          readOut,
          error,
        ) === 0
      ) {
        const code = winError(error);
        if (code === ERROR_NO_DATA) return;
        finish();
        return;
      }
      const count = winError(readOut);
      if (count === 0) return;
      poller.wake();
      const chunk = readBuffer.slice(0, count);
      for (const handler of dataHandlers) {
        try {
          handler(chunk);
        } catch {
          finish();
          return;
        }
      }
    }
  };
  const poller = createWindowsPipePoller(poll);
  const stop = (): void => {
    finish();
  };
  return {
    onData: (handler): (() => void) => {
      dataHandlers.add(handler);
      return () => dataHandlers.delete(handler);
    },
    onClose: (handler): (() => void) => {
      closeHandlers.add(handler);
      return () => closeHandlers.delete(handler);
    },
    write: (chunk): void => {
      if (ended || closeRequested)
        throw new Error("named-pipe connection is closed");
      if (queuedBytes + chunk.byteLength > PIPE_QUEUE_LIMIT_BYTES) {
        stop();
        throw new Error("named-pipe output queue exceeded its limit");
      }
      writes.push(chunk.slice());
      queuedBytes += chunk.byteLength;
      poller.wake();
      flush();
    },
    close: (): void => {
      if (ended || closeRequested) return;
      closeRequested = true;
      closeTimer = setTimeout(finish, 1_000);
      flush();
    },
  };
};

/** Existing roots must already be private; never repair their ownership or ACL. */
export const secureAndVerifyWindowsSessionDirectory = (path: string): void => {
  verifyWindowsSessionDirectory(path);
};

/** Create a new private directory with current-user ownership and child ACLs. */
export const createWindowsSessionDirectory = (path: string): void => {
  const error = new Uint8Array(4);
  if (loadNativeBindings().ws_create_session_directory(wide(path), error) === 0)
    throw pipeFrameError(
      "create current-user session directory",
      winError(error),
    );
  verifyWindowsSessionDirectory(path);
};

/** Create an exclusive, current-user-owned private file with a bounded payload. */
export const createWindowsSessionFile = (
  path: string,
  content: Uint8Array,
): void => {
  verifyWindowsSessionDirectory(dirname(path));
  const error = new Uint8Array(4);
  if (
    loadNativeBindings().ws_create_session_file(
      wide(path),
      content,
      content.byteLength,
      error,
    ) === 0
  )
    throw pipeFrameError("create current-user session file", winError(error));
  verifyWindowsSessionFile(path);
};

/** Check an existing session directory before reading any marker or metadata. */
export const verifyWindowsSessionDirectory = (path: string): void => {
  const error = new Uint8Array(4);
  if (loadNativeBindings().ws_verify_directory_owner(wide(path), error) === 0)
    throw pipeFrameError(
      "verify session-directory owner/reparse status",
      winError(error),
    );
};

/** Reject reparse files or foreign-owned markers before reading session metadata. */
export const verifyWindowsSessionFile = (path: string): void => {
  const error = new Uint8Array(4);
  if (loadNativeBindings().ws_verify_session_file(wide(path), error) === 0)
    throw pipeFrameError(
      "verify session metadata/marker file",
      winError(error),
    );
};

type TKernelPipeApi = {
  readonly CloseHandle: (handle: bigint) => number;
  readonly LocalFree: (memory: bigint) => number | null;
};

type TPipeInstance = {
  readonly handle: bigint;
  readonly statusBuffer: Uint8Array;
  connection: TPipeConnection | null;
};

const PIPE_CONNECTED = 535;
const PIPE_LISTENING = 536;
const ERROR_NO_DATA = 232;
const ERROR_BROKEN_PIPE = 109;
const ERROR_PIPE_NOT_CONNECTED = 233;
const PIPE_ACCESS_DUPLEX = 0x00000003;
const FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000;
const PIPE_NOWAIT = 0x00000001;
const PIPE_REJECT_REMOTE_CLIENTS = 0x00000008;
const INVALID_HANDLE_VALUE = 0xffff_ffff_ffff_ffffn;
const PIPE_BUFFER_BYTES = 64 * 1024;
const PIPE_INSTANCE_COUNT = 8;
const PIPE_QUEUE_LIMIT_BYTES = 16 * 1024 * 1024;

let apiCache: TKernelPipeApi | null = null;

const api = (): TKernelPipeApi => {
  if (apiCache !== null) return apiCache;
  const kernel = dlopen("kernel32.dll", {
    CloseHandle: { args: [FFIType.u64], returns: FFIType.i32 },
    LocalFree: { args: [FFIType.u64], returns: FFIType.u64 },
  });
  apiCache = {
    CloseHandle: kernel.symbols
      .CloseHandle as unknown as TKernelPipeApi["CloseHandle"],
    LocalFree: kernel.symbols
      .LocalFree as unknown as TKernelPipeApi["LocalFree"],
  };
  return apiCache;
};

const wide = (value: string): Uint8Array => {
  const bytes = new Uint8Array((value.length + 1) * 2);
  const view = new DataView(bytes.buffer);
  for (let index = 0; index < value.length; index += 1)
    view.setUint16(index * 2, value.charCodeAt(index), true);
  return bytes;
};

const makeSecurityAttributes = (): {
  readonly attributes: Uint8Array;
  readonly descriptor: bigint;
} => {
  const native = loadNativeBindings();
  const attributes = new Uint8Array(24);
  const descriptorOut = new Uint8Array(8);
  const error = new Uint8Array(4);
  if (native.ws_build_pipe_security(attributes, descriptorOut, error) === 0)
    throw pipeFrameError("build current-user named-pipe ACL", winError(error));
  const descriptor = new DataView(descriptorOut.buffer).getBigUint64(0, true);
  if (descriptor === 0n)
    throw new Error("Windows returned an empty named-pipe ACL");
  return { attributes, descriptor };
};

class TPipeConnection implements TWindowsSessionPipeConnection {
  private readonly dataHandlers = new Set<(chunk: Uint8Array) => void>();
  private readonly closeHandlers = new Set<() => void>();
  private readonly drainHandlers = new Set<() => void>();
  private readonly writes: Uint8Array[] = [];
  private readonly readBuffer = new Uint8Array(PIPE_BUFFER_BYTES);
  private readonly readResult = new Uint8Array(4);
  private readonly writeResult = new Uint8Array(4);
  private readonly nativeError = new Uint8Array(4);
  private writeOffset = 0;
  private queuedBytes = 0;
  private ended = false;
  private closeRequested = false;
  private closeTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly shim: TNativeClientBindings,
    private readonly handle: bigint,
    private readonly onEnd: () => void,
    private readonly onActivity: () => void,
  ) {}

  onData(handler: (chunk: Uint8Array) => void): () => void {
    this.dataHandlers.add(handler);
    return () => this.dataHandlers.delete(handler);
  }

  onClose(handler: () => void): () => void {
    this.closeHandlers.add(handler);
    return () => this.closeHandlers.delete(handler);
  }

  onDrain(handler: () => void): () => void {
    this.drainHandlers.add(handler);
    return () => this.drainHandlers.delete(handler);
  }

  write(chunk: Uint8Array): number {
    if (this.ended || this.closeRequested)
      throw new Error("named-pipe connection is closed");
    if (this.queuedBytes + chunk.byteLength > PIPE_QUEUE_LIMIT_BYTES) {
      this.close();
      throw new Error("named-pipe output queue exceeded its limit");
    }
    this.writes.push(chunk.slice());
    this.queuedBytes += chunk.byteLength;
    this.onActivity();
    this.flushWrites();
    return this.ended ? 0 : this.writes.length === 0 ? 1 : -1;
  }

  close(timeoutMs = 1_000): void {
    if (this.ended || this.closeRequested) return;
    this.closeRequested = true;
    const boundedTimeout = Number.isFinite(timeoutMs)
      ? Math.min(1_000, Math.max(0, timeoutMs))
      : 1_000;
    this.closeTimer = setTimeout(() => this.finish(), boundedTimeout);
    this.flushWrites();
    if (this.writes.length === 0) this.finish();
  }

  poll(): void {
    if (this.ended) return;
    this.flushWrites();
    if (this.ended) return;
    if (this.closeRequested && this.writes.length === 0) {
      this.finish();
      return;
    }
    for (let count = 0; count < 4; count += 1) {
      this.readResult.fill(0);
      if (
        this.shim.ws_pipe_read(
          this.handle,
          this.readBuffer,
          this.readBuffer.byteLength,
          this.readResult,
          this.nativeError,
        ) === 0
      ) {
        const error = winError(this.nativeError);
        if (error === ERROR_NO_DATA) return;
        if (error === ERROR_BROKEN_PIPE || error === ERROR_PIPE_NOT_CONNECTED) {
          this.finish();
          return;
        }
        this.finish();
        return;
      }
      const bytesRead = new DataView(this.readResult.buffer).getUint32(0, true);
      if (bytesRead === 0) return;
      this.onActivity();
      const chunk = this.readBuffer.slice(0, bytesRead);
      for (const handler of this.dataHandlers) {
        try {
          handler(chunk);
        } catch {
          this.close();
          return;
        }
      }
    }
  }

  private flushWrites(): void {
    const hadQueuedWrites = this.writes.length > 0;
    while (this.writes.length > 0) {
      const current = this.writes[0];
      if (current === undefined) return;
      const remaining = current.subarray(this.writeOffset);
      this.writeResult.fill(0);
      if (
        this.shim.ws_pipe_write(
          this.handle,
          remaining,
          remaining.byteLength,
          this.writeResult,
          this.nativeError,
        ) === 0
      ) {
        const error = winError(this.nativeError);
        if (error === ERROR_NO_DATA) {
          this.finish();
          return;
        }
        this.finish();
        return;
      }
      const count = new DataView(this.writeResult.buffer).getUint32(0, true);
      if (count === 0) return;
      this.onActivity();
      this.writeOffset += count;
      this.queuedBytes -= count;
      if (this.writeOffset >= current.byteLength) {
        this.writes.shift();
        this.writeOffset = 0;
      }
    }
    if (hadQueuedWrites && this.writes.length === 0 && !this.ended) {
      for (const handler of this.drainHandlers) {
        try {
          handler();
        } catch {
          // Drain observers cannot interrupt pipe progress.
        }
      }
    }
  }

  private finish(): void {
    if (this.ended) return;
    this.ended = true;
    if (this.closeTimer !== null) clearTimeout(this.closeTimer);
    this.writes.length = 0;
    this.queuedBytes = 0;
    try {
      this.shim.ws_pipe_disconnect(this.handle, this.nativeError);
    } catch {
      // Close observers still run if the native disconnect call fails.
    }
    try {
      this.onEnd();
    } catch {
      // Every registered close handler must still be notified.
    }
    for (const handler of this.closeHandlers) {
      try {
        handler();
      } catch {
        // Closing the native handle must complete despite consumer cleanup errors.
      }
    }
    this.drainHandlers.clear();
  }

  /** Force completion after the server's bounded drain deadline. */
  forceClose(): void {
    this.finish();
  }
}

/** Create a poll-driven server; all pipe I/O stays in this Bun process. */
export const createWindowsSessionPipeServer = (
  name: string,
  onConnection: (connection: TWindowsSessionPipeConnection) => void,
): TWindowsSessionPipeServer => {
  if (process.platform !== "win32")
    throw new Error("Windows session pipes are only available on Windows");
  const nativeApi = api();
  const shim = loadNativeBindings();
  const security = makeSecurityAttributes();
  const instances: TPipeInstance[] = [];
  let closing = false;
  let closed = false;
  let closeResolve: (() => void) | null = null;
  let closeTimer: ReturnType<typeof setTimeout> | null = null;

  const createInstance = (first: boolean): TPipeInstance => {
    const handleOut = new Uint8Array(8);
    const error = new Uint8Array(4);
    if (
      loadNativeBindings().ws_create_named_pipe(
        wide(name),
        PIPE_ACCESS_DUPLEX | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
        PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_INSTANCE_COUNT,
        PIPE_BUFFER_BYTES,
        PIPE_BUFFER_BYTES,
        0,
        security.attributes,
        handleOut,
        error,
      ) === 0
    )
      throw pipeFrameError("CreateNamedPipeW", winError(error));
    const handle = new DataView(handleOut.buffer).getBigUint64(0, true);
    if (handle === 0n || handle === INVALID_HANDLE_VALUE)
      throw new Error("CreateNamedPipeW returned an invalid handle");
    return { handle, statusBuffer: new Uint8Array(4), connection: null };
  };

  try {
    for (let index = 0; index < PIPE_INSTANCE_COUNT; index += 1)
      instances.push(createInstance(index === 0));
  } catch (error) {
    for (const instance of instances) nativeApi.CloseHandle(instance.handle);
    throw error;
  } finally {
    nativeApi.LocalFree(security.descriptor);
  }

  const poll = (): void => {
    if (closed) return;
    for (const instance of instances) {
      if (instance.connection !== null) {
        instance.connection.poll();
        continue;
      }
      if (closing) continue;
      const connectErrorOut = instance.statusBuffer;
      const connected = shim.ws_pipe_connect(instance.handle, connectErrorOut);
      const connectError = connected === 0 ? winError(connectErrorOut) : 0;
      if (connected !== 0 || connectError === PIPE_CONNECTED) {
        poller.wake();
        const connection = new TPipeConnection(
          shim,
          instance.handle,
          () => {
            instance.connection = null;
            poller.wake();
          },
          () => poller.wake(),
        );
        instance.connection = connection;
        onConnection(connection);
        continue;
      }
      if (connectError === PIPE_LISTENING) continue;
      shim.ws_pipe_disconnect(instance.handle, connectErrorOut);
    }
    if (closing && instances.every((instance) => instance.connection === null))
      finishClose();
  };
  const poller = createWindowsPipePoller(poll);

  const finishClose = (): void => {
    if (closed) return;
    closed = true;
    poller.stop();
    if (closeTimer !== null) clearTimeout(closeTimer);
    for (const instance of instances) {
      instance.connection?.forceClose();
      shim.ws_pipe_disconnect(instance.handle, new Uint8Array(4));
      nativeApi.CloseHandle(instance.handle);
    }
    instances.length = 0;
    closeResolve?.();
    closeResolve = null;
  };

  return {
    close: (timeoutMs = 1_000): Promise<void> => {
      if (closed) return Promise.resolve();
      closing = true;
      const settled = new Promise<void>((resolve) => {
        closeResolve = resolve;
      });
      if (instances.every((instance) => instance.connection === null))
        finishClose();
      else if (timeoutMs <= 0) finishClose();
      else closeTimer = setTimeout(finishClose, timeoutMs);
      return settled;
    },
  };
};
