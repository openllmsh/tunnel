import type {
  TDeviceSessionCli,
  TRealtimeClientEvent,
  TRealtimeModel,
  TRealtimeProvider,
  TRealtimeServerEvent,
  TRealtimeStreamOpenPayload,
  TRealtimeVoice,
  TSessionStreamOpenPayload,
  TStreamResetCode,
  TTunnelForwardHeaders,
  TTunnelResponseHeaders,
  TTunnelStreamOpenPayload,
  TTunnelSurface,
} from "@openllmsh/protocol";
import {
  applyTunnelResponseHeadersToHttp,
  decodeRealtimeLine,
  encodeRealtimeEventLine,
  parseRealtimeServerEvent,
  parseStreamCtrlPayload,
  parseStreamOpenPayload,
  parseStreamResetPayload,
  REALTIME_HEARTBEAT_INTERVAL_MS,
  REALTIME_HEARTBEAT_TIMEOUT_MS,
  REALTIME_SESSION_MAX_LIFETIME_MS,
  StreamResetCode,
  splitRealtimeLines,
  TUNNEL_MEDIA_MAX_BODY_BYTES,
} from "@openllmsh/protocol";
import { Schema } from "effect";
import {
  decodeJsonPayload,
  encodeJsonPayload,
  MAX_PAYLOAD_BYTES,
} from "./codec";
import type { TMuxChannel, TMuxStream } from "./mux";
import { StreamResetError } from "./stream-reset-error";

/** Default wait for the serving end's `res_head` CTRL (matches legacy tunnel). */
export const TUNNEL_RESPONSE_HEAD_TIMEOUT_MS = 120_000;

export { TUNNEL_MEDIA_MAX_BODY_BYTES };

/**
 * Concatenate a request body under a hard byte cap. Honors abort. Used when
 * FormData/Blob must become mux DATA frames without UTF-8 round-trips.
 */
export const collectBoundedBytes = async (
  body: ReadableStream<Uint8Array> | Uint8Array | null,
  maxBytes: number = TUNNEL_MEDIA_MAX_BODY_BYTES,
  signal?: AbortSignal,
): Promise<Uint8Array> => {
  if (body === null) return new Uint8Array();
  if (body instanceof Uint8Array) {
    if (body.byteLength > maxBytes) {
      throw new Error("tunnel request body too large");
    }
    return body;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const onAbort = (): void => {
    void reader.cancel().catch(() => {});
  };
  if (signal?.aborted) {
    onAbort();
    reader.releaseLock();
    throw new DOMException("Aborted", "AbortError");
  }
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
      const next = await reader.read();
      if (next.done) {
        // `onAbort`'s `reader.cancel()` resolves a PENDING read as done —
        // indistinguishable from a natural end of stream unless we re-check
        // here. Without this, an abort racing an in-flight `read()` silently
        // returns the bytes collected so far instead of rejecting.
        if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
        break;
      }
      total += next.value.byteLength;
      if (total > maxBytes) {
        throw new Error("tunnel request body too large");
      }
      chunks.push(next.value);
    }
  } finally {
    signal?.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
  if (chunks.length === 0) return new Uint8Array();
  if (chunks.length === 1) {
    const only = chunks[0];
    return only === undefined ? new Uint8Array() : only;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
};

const streamReset = (code: TStreamResetCode, message?: string): Uint8Array =>
  encodeJsonPayload({ code, ...(message === undefined ? {} : { message }) });

const resetCode = (payload: Uint8Array): TStreamResetCode | null => {
  const decoded = parseStreamResetPayload(decodeJsonPayload(payload));
  return decoded?.code ?? null;
};

/**
 * Classify a RESET payload. Empty / unparseable bytes are expected peer or
 * channel teardown (`peer_gone`), never a default `protocol_error` — abrupt
 * mux/RTC close mass-resets live streams with `new Uint8Array()`.
 */
export const unknownReset = (payload: Uint8Array): StreamResetError => {
  const parsed = parseStreamResetPayload(decodeJsonPayload(payload));
  return new StreamResetError(
    parsed?.code ?? "peer_gone",
    parsed?.message ?? parsed?.code ?? "stream reset",
  );
};

const isStreamResetCode = (value: unknown): value is TStreamResetCode =>
  Schema.is(StreamResetCode)(value);

/**
 * True when an `AbortSignal`'s `.reason` is TIMEOUT-shaped rather than a
 * genuine caller cancellation — mirrors the `name`/message heuristic
 * `packages/daemon/src/net-error.ts`'s `classifyOriginThrow` already uses
 * for origin-fetch failures (kept as a small local copy, not an import: the
 * dependency graph is `daemon → tunnel`, never the reverse). Recognizes
 * `AbortSignal.timeout(ms)`'s own `TimeoutError`-named reason, so a signal
 * built as `AbortSignal.any([callerSignal, AbortSignal.timeout(ms)])` — the
 * shape `openRealtimeVoiceOverMux`'s per-rung budget uses — still resolves
 * correctly to "timeout" when the internal timer is what actually fired,
 * even though `realtimeStream` only ever sees the ONE merged signal.
 */
const isTimeoutAbortReason = (reason: unknown): boolean => {
  if (typeof reason !== "object" || reason === null) return false;
  const name = (reason as { name?: unknown }).name;
  if (name === "TimeoutError") return true;
  if (name === "AbortError") {
    const message = (reason as { message?: unknown }).message;
    const lower = typeof message === "string" ? message.toLowerCase() : "";
    return lower.includes("timeout") || lower.includes("timed out");
  }
  return false;
};

/**
 * Build the rejection for a genuine caller-driven abort (NOT a
 * timeout-shaped reason — see {@link isTimeoutAbortReason}), carrying the
 * ORIGINAL abort reason when the signal provides one. This is what lets a
 * caller — or a retry policy like `openOverMuxLadder` — tell "I cancelled
 * this" apart from "this genuinely timed out" instead of both surfacing as
 * an identical `StreamResetError("timeout", ...)`.
 */
const callerAbortError = (signal: AbortSignal | undefined): Error => {
  const reason: unknown = signal?.reason;
  if (reason instanceof Error) return reason;
  if (typeof reason === "object" && reason !== null) {
    const message = (reason as { message?: unknown }).message;
    const name = (reason as { name?: unknown }).name;
    if (typeof message === "string") {
      return new DOMException(
        message,
        typeof name === "string" ? name : "AbortError",
      );
    }
  }
  return new DOMException("Aborted", "AbortError");
};

/**
 * Mirror a mux stream as a ReadableStream. Cancelling a response body RESETs
 * the remote stream so the peer can abort its work. Request-body cancellation
 * only detaches the local reader: the peer may already have sent a response.
 */
const bodyFromStream = (
  stream: TMuxStream,
  onReset?: () => void,
  resetOnCancel = true,
): ReadableStream<Uint8Array> => {
  let offData: (() => void) | undefined;
  let offEnd: (() => void) | undefined;
  let offReset: (() => void) | undefined;
  const delivered: number[] = [];
  let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
  const cleanup = (): void => {
    offData?.();
    offEnd?.();
    offReset?.();
    offData = undefined;
    offEnd = undefined;
    offReset = undefined;
  };
  return new ReadableStream<Uint8Array>({
    start(nextController) {
      controller = nextController;
      offData = stream.onData((bytes) => {
        // `pull` runs when the queued chunk is read; defer mux credit until then.
        delivered.push(bytes.byteLength);
        nextController.enqueue(bytes);
        return false;
      });
      offEnd = stream.onEnd(() => {
        cleanup();
        nextController.close();
      });
      offReset = stream.onReset((payload) => {
        cleanup();
        onReset?.();
        controller?.error(unknownReset(payload));
      });
    },
    pull() {
      const bytes = delivered.shift();
      if (bytes !== undefined) stream.consume(bytes);
    },
    cancel() {
      cleanup();
      if (resetOnCancel) {
        stream.reset(streamReset("peer_gone", "consumer cancelled"));
      }
    },
  });
};

const pumpBody = async (
  stream: TMuxStream,
  body: ReadableStream<Uint8Array> | Uint8Array | null,
  signal?: AbortSignal,
): Promise<void> => {
  if (body === null) {
    stream.end();
    return;
  }
  if (body instanceof Uint8Array) {
    if (signal?.aborted) {
      stream.reset(streamReset("peer_gone", "aborted"));
      return;
    }
    // Brief write window — still honor abort so a pre-end cancel reaches the peer.
    const onAbort = (): void => {
      stream.reset(streamReset("peer_gone", "aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      if (body.byteLength > 0) await stream.write(body);
      if (!signal?.aborted) stream.end();
    } catch (error) {
      stream.reset(
        streamReset(
          "peer_gone",
          error instanceof Error ? error.message : undefined,
        ),
      );
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
    return;
  }
  const reader = body.getReader();
  // Cancel the reader on abort so a pending read() unblocks and finally runs.
  const onAbort = (): void => {
    stream.reset(streamReset("peer_gone", "aborted"));
    void reader.cancel().catch(() => {});
  };
  if (signal?.aborted) {
    onAbort();
    reader.releaseLock();
    return;
  }
  signal?.addEventListener("abort", onAbort, { once: true });
  try {
    for (;;) {
      if (signal?.aborted) return;
      const next = await reader.read();
      if (next.done) break;
      if (next.value.byteLength > 0) await stream.write(next.value);
    }
    if (!signal?.aborted) stream.end();
  } catch (error) {
    stream.reset(
      streamReset(
        "peer_gone",
        error instanceof Error ? error.message : undefined,
      ),
    );
  } finally {
    signal?.removeEventListener("abort", onAbort);
    reader.releaseLock();
  }
};

export type TTunnelStreamOptions = {
  readonly surface: TTunnelSurface;
  readonly headers?: TTunnelForwardHeaders;
  readonly body: ReadableStream<Uint8Array> | Uint8Array | null;
  readonly signal?: AbortSignal;
  /**
   * Max wait for the serving end's `res_head` CTRL before rejecting with
   * `"tunnel response timed out"` and RESETing the stream. Defaults to
   * {@link TUNNEL_RESPONSE_HEAD_TIMEOUT_MS} (legacy tunnel parity).
   */
  readonly headTimeoutMs?: number;
  /**
   * Who opened this stream. Daemon fleet hops set `"daemon"` so the serving
   * end can stamp the walker loop-guard (`x-openllm-tunneled`). Browser
   * omits this (or sets `"browser"`) so the selected device may still
   * `tryFleetTunnel` once. See browser-selected-device-tunnel-contract.
   */
  readonly consumer?: "browser" | "daemon";
};

export type TTunnelStreamResult = {
  readonly status: number;
  readonly headers: Headers;
  readonly body: ReadableStream<Uint8Array>;
};

/** Open a request stream and begin writing the body before the serving head arrives. */
export const tunnelStream = (
  channel: TMuxChannel,
  options: TTunnelStreamOptions,
): Promise<TTunnelStreamResult> =>
  new Promise<TTunnelStreamResult>((resolve, reject) => {
    const stream = channel.openStream(
      encodeJsonPayload({
        kind: "tunnel",
        method: "POST",
        surface: options.surface,
        ...(options.headers === undefined ? {} : { headers: options.headers }),
        ...(options.consumer === undefined
          ? {}
          : { consumer: options.consumer }),
      }),
    );
    let settled = false;
    let offCtrl = (): void => {};
    let offReset = (): void => {};
    const headTimeoutMs =
      options.headTimeoutMs ?? TUNNEL_RESPONSE_HEAD_TIMEOUT_MS;

    const settle = (result: TTunnelStreamResult | Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(headTimer);
      options.signal?.removeEventListener("abort", onAbort);
      offCtrl();
      offReset();
      if (result instanceof Error) reject(result);
      else resolve(result);
    };

    // Settle FIRST so the local onReset from stream.reset() cannot
    // overwrite AbortError / timeout with unknownReset(payload).
    const onAbort = (): void => {
      settle(new DOMException("Aborted", "AbortError"));
      stream.reset(streamReset("peer_gone", "aborted"));
    };

    const headTimer = setTimeout(() => {
      settle(new Error("tunnel response timed out"));
      stream.reset(streamReset("timeout", "tunnel response timed out"));
    }, headTimeoutMs);

    offCtrl = stream.onCtrl((payload) => {
      const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
      if (ctrl?.t !== "res_head") return;
      const headers = new Headers();
      if (ctrl.res_headers !== undefined) {
        applyTunnelResponseHeadersToHttp(headers, ctrl.res_headers);
      }
      settle({ status: ctrl.status, headers, body: bodyFromStream(stream) });
    });
    offReset = stream.onReset((payload) => settle(unknownReset(payload)));

    // Arm abort before pumping the body so AbortError wins the settle race
    // against pumpBody's own reset → onReset(unknownReset) path.
    if (options.signal?.aborted) {
      onAbort();
      return;
    }
    options.signal?.addEventListener("abort", onAbort, { once: true });
    void pumpBody(stream, options.body, options.signal);
  });

export type TSessionStreamOptions = {
  readonly sessionId: string;
  readonly cli: TDeviceSessionCli;
  readonly cols: number;
  readonly rows: number;
  readonly mode: "spawn" | "attach" | "continue";
  readonly title?: string;
  /** Maps to `openllm -d <client>` for CLIs that support skip-approvals. */
  readonly dangerous?: boolean;
  /** Vendor session id for cold resume (`spawn` only). */
  readonly resumeSessionId?: string;
  /** Absolute cwd for spawn/continue; daemon-validated. Omitted → `$HOME`. */
  readonly cwd?: string;
  /**
   * Abort cancels an in-flight open (RESET + reject) so callers can time out
   * without leaving a dangling mux stream that later races a retry.
   */
  readonly signal?: AbortSignal;
};

export type TSessionCloseResult = TStreamResetCode | "done" | "detach";
export type TSessionStreamResult = {
  readonly live: boolean;
  readonly stdout: ReadableStream<Uint8Array>;
  readonly write: (bytes: Uint8Array) => Promise<void>;
  readonly resize: (cols: number, rows: number) => void;
  /** Claim primary (active-viewer) status without typing. Skew-safe. */
  readonly focus: () => void;
  readonly detach: () => void;
  readonly kill: () => void;
  readonly onReplayDone: (callback: () => void) => () => void;
  readonly closed: Promise<TSessionCloseResult>;
};

/**
 * Open a long-lived PTY session stream over a mux channel. Resolves once the
 * serving daemon acks (`open_ack`); rejects with the nack code/message when
 * the open is refused (`cli_not_installed`, `session_busy`, …).
 */
export const sessionStream = (
  channel: TMuxChannel,
  options: TSessionStreamOptions,
): Promise<TSessionStreamResult> => {
  const stream = channel.openStream(
    encodeJsonPayload({
      kind: "session",
      session_id: options.sessionId,
      cli: options.cli,
      cols: options.cols,
      rows: options.rows,
      mode: options.mode,
      ...(options.title === undefined ? {} : { title: options.title }),
      ...(options.dangerous === true ? { dangerous: true } : {}),
      ...(options.resumeSessionId === undefined
        ? {}
        : { resume_session_id: options.resumeSessionId }),
      ...(options.cwd === undefined ? {} : { cwd: options.cwd }),
    }),
  );
  const replayHandlers = new Set<() => void>();
  // replay_done can arrive in the same delivery batch as open_ack — before the
  // caller has had a microtask to register a listener. Latch it so a late
  // registration still observes the marker exactly once.
  let replayDoneSeen = false;
  let resolveClosed: (result: TSessionCloseResult) => void = () => {};
  const closed = new Promise<TSessionCloseResult>((resolve) => {
    resolveClosed = resolve;
  });
  let closedResult = false;
  const finish = (result: TSessionCloseResult): void => {
    if (closedResult) return;
    closedResult = true;
    resolveClosed(result);
  };

  return new Promise<TSessionStreamResult>((resolve, reject) => {
    let settled = false;
    const settleReject = (error: Error): void => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    };
    const onAbort = (): void => {
      // Pre-ack abort: RESET so the daemon detaches and a retry can re-open
      // the same session id without session_busy from a dangling stream.
      stream.reset(streamReset("timeout", "session open timed out"));
      finish("timeout");
      settleReject(new StreamResetError("timeout", "session open timed out"));
    };
    const offReset = stream.onReset((payload) => {
      const code = resetCode(payload) ?? "peer_gone";
      finish(code);
      settleReject(unknownReset(payload));
    });
    const offEnd = stream.onEnd(() => finish("done"));
    const _offCtrl = stream.onCtrl((payload) => {
      const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
      if (ctrl === null) return;
      if (ctrl.t === "replay_done") {
        if (replayDoneSeen) return;
        replayDoneSeen = true;
        for (const handler of replayHandlers) handler();
        return;
      }
      if (ctrl.t !== "open_ack" || settled) return;
      if (!ctrl.ok) {
        // Prefer the nack code/message when present so the UI can show
        // cli_not_installed / session_busy / overloaded / etc. instead of a
        // generic "session refused".
        const detail =
          (typeof ctrl.message === "string" && ctrl.message.length > 0
            ? ctrl.message
            : undefined) ??
          (typeof ctrl.error === "string" && ctrl.error.length > 0
            ? ctrl.error
            : undefined) ??
          "session refused";
        const nackCode = isStreamResetCode(ctrl.error)
          ? ctrl.error
          : "protocol_error";
        // Settle first so the local onReset from stream.reset() cannot replace
        // the daemon's typed nack code with the wire-close protocol_error.
        settleReject(new StreamResetError(nackCode, detail));
        stream.reset(streamReset("protocol_error", detail));
        // Settle `closed` so callers waiting on it don't hang after a nack.
        finish("protocol_error");
        return;
      }
      settled = true;
      options.signal?.removeEventListener("abort", onAbort);
      resolve({
        live: ctrl.live ?? false,
        stdout: bodyFromStream(stream),
        write: stream.write,
        resize: (cols, rows) =>
          stream.sendCtrl(encodeJsonPayload({ t: "resize", cols, rows })),
        focus: () => stream.sendCtrl(encodeJsonPayload({ t: "focus" })),
        detach: () => {
          stream.end();
          finish("detach");
        },
        kill: () => {
          stream.sendCtrl(encodeJsonPayload({ t: "close", intent: "kill" }));
          stream.end();
          // Settle `closed` locally so a caller awaiting it never hangs if the
          // daemon never sends a terminal END. `finish` is idempotent, so the
          // daemon's own END (→ "done") later is harmless.
          finish("done");
        },
        onReplayDone: (callback) => {
          if (replayDoneSeen) {
            callback();
            return () => {};
          }
          replayHandlers.add(callback);
          return () => {
            replayHandlers.delete(callback);
          };
        },
        closed,
      });
    });
    if (options.signal?.aborted) {
      onAbort();
    } else {
      options.signal?.addEventListener("abort", onAbort, { once: true });
    }
    // Keep reset/end subscriptions live after open; only the open-ack listener is one-shot.
    void offReset;
    void offEnd;
    void _offCtrl;
  });
};

/**
 * Wrap a mux stream's DATA channel as an NDJSON realtime-event pump: each
 * inbound chunk is split on `\n` (carrying a remainder across calls), every
 * complete line is decoded + schema-validated by `parse`, and mux receive
 * credit is replenished immediately (events are consumed synchronously here,
 * never deferred). An oversized/never-terminated line calls `onOverflow`
 * instead of growing the buffer — the caller decides how to RESET.
 *
 * Shared by the CONSUMER side (`realtimeStream` below) and the SERVING side
 * (a daemon's `kind:"realtime"` dispatch), so both directions get the same
 * framing and the same bounded-line behavior.
 */
export const pumpRealtimeEvents = <T>(
  stream: TMuxStream,
  parse: (value: unknown) => T | null,
  onEvent: (event: T) => void,
  onOverflow: () => void,
): (() => void) => {
  let remainder: Uint8Array = new Uint8Array(0);
  return stream.onData((bytes) => {
    const split = splitRealtimeLines(remainder, bytes);
    if (split === null) {
      onOverflow();
      return;
    }
    remainder = split.remainder;
    // Events are decoded + dispatched synchronously in this callback, so
    // receive credit is safe to replenish immediately (never deferred to a
    // later `consume()`).
    stream.consume(bytes.byteLength);
    for (const line of split.lines) {
      if (line.byteLength === 0) continue;
      const decoded = decodeRealtimeLine(line);
      const event = decoded === undefined ? null : parse(decoded);
      if (event !== null) onEvent(event);
    }
    return false;
  });
};

/** A single realtime event, JSON-encoded + newline-terminated, written to the
 *  stream's DATA channel. Returns the underlying `write()` promise so a
 *  SERVING-side caller can track backpressure (a CONSUMER-side caller may
 *  ignore it — `realtimeStream`'s `send` does). Silently drops an event that
 *  fails to encode (oversized/non-serializable) rather than desyncing the
 *  NDJSON framing with a truncated line. */
export const sendRealtimeEvent = (
  stream: TMuxStream,
  event: unknown,
): Promise<void> => {
  const line = encodeRealtimeEventLine(event);
  if (line === null) return Promise.resolve();
  return stream.write(line).catch(() => {});
};

export type TRealtimeStreamOptions = {
  readonly provider: TRealtimeProvider;
  readonly model: TRealtimeModel;
  readonly voice: TRealtimeVoice;
  readonly signal?: AbortSignal;
  /**
   * Max wait for the serving end's `open_ack` CTRL before rejecting and
   * RESETing the stream with `timeout`. Defaults to
   * {@link TUNNEL_RESPONSE_HEAD_TIMEOUT_MS} — mirrors `tunnelStream`'s own
   * `headTimeoutMs` default and, like it, applies UNCONDITIONALLY: an
   * absent `options.signal` must not leave a peer that never acks hanging
   * forever.
   */
  readonly headTimeoutMs?: number;
  /** Test/override seams — production defaults to the shared protocol bounds. */
  readonly heartbeatIntervalMs?: number;
  readonly heartbeatTimeoutMs?: number;
  readonly maxLifetimeMs?: number;
};

export type TRealtimeStreamResult = {
  readonly send: (event: TRealtimeClientEvent) => void;
  readonly onServerEvent: (
    handler: (event: TRealtimeServerEvent) => void,
  ) => () => void;
  readonly close: () => void;
  readonly closed: Promise<TStreamResetCode | "done">;
};

/**
 * Open a realtime duplex session over a mux channel (the browser/fleet
 * CONSUMER side). Resolves once the serving daemon acks (`open_ack`);
 * rejects with the nack code/message when refused (`realtime_refused`,
 * `realtime_busy`, `realtime_unsupported`).
 *
 * Events ride NDJSON-framed over the stream's flow-controlled DATA channel
 * (real mux backpressure, unlike CTRL) via `pumpRealtimeEvents` /
 * `sendRealtimeEvent`. A `{t:"heartbeat"}` CTRL keeps the session alive
 * through natural silence; missing ALL inbound traffic for
 * `heartbeatTimeoutMs`, or exceeding `maxLifetimeMs` total, RESETs with
 * `timeout`. Callers MUST check `hasRealtimeDuplexCap` on the peer's
 * capabilities before calling this — an old peer that doesn't understand
 * `kind:"realtime"` should never receive the OPEN in the first place.
 */
export const realtimeStream = (
  channel: TMuxChannel,
  options: TRealtimeStreamOptions,
): Promise<TRealtimeStreamResult> => {
  const stream = channel.openStream(
    encodeJsonPayload({
      kind: "realtime",
      provider: options.provider,
      model: options.model,
      voice: options.voice,
    }),
  );
  const heartbeatIntervalMs =
    options.heartbeatIntervalMs ?? REALTIME_HEARTBEAT_INTERVAL_MS;
  const heartbeatTimeoutMs =
    options.heartbeatTimeoutMs ?? REALTIME_HEARTBEAT_TIMEOUT_MS;
  const maxLifetimeMs =
    options.maxLifetimeMs ?? REALTIME_SESSION_MAX_LIFETIME_MS;
  const headTimeoutMs =
    options.headTimeoutMs ?? TUNNEL_RESPONSE_HEAD_TIMEOUT_MS;

  const serverEventHandlers = new Set<(event: TRealtimeServerEvent) => void>();
  let resolveClosed: (result: TStreamResetCode | "done") => void = () => {};
  const closed = new Promise<TStreamResetCode | "done">((resolve) => {
    resolveClosed = resolve;
  });
  let closedResult = false;
  const finish = (result: TStreamResetCode | "done"): void => {
    if (closedResult) return;
    closedResult = true;
    resolveClosed(result);
  };

  let lastInboundAt = Date.now();
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  let lifetimeTimer: ReturnType<typeof setTimeout> | undefined;
  const stopTimers = (): void => {
    if (heartbeatTimer !== undefined) clearInterval(heartbeatTimer);
    if (lifetimeTimer !== undefined) clearTimeout(lifetimeTimer);
    heartbeatTimer = undefined;
    lifetimeTimer = undefined;
  };

  return new Promise<TRealtimeStreamResult>((resolve, reject) => {
    let settled = false;
    const settleReject = (error: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(headTimer);
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    };
    const onAbort = (): void => {
      // `options.signal` may itself be a MERGED signal (e.g. the mux ladder's
      // `AbortSignal.any([callerSignal, AbortSignal.timeout(rungBudgetMs)])`)
      // — a timeout-shaped reason keeps producing the exact same
      // `StreamResetError("timeout", ...)` as before (so `isTransportFailure`
      // keeps treating it as retryable and rung failover is unaffected), but
      // any OTHER reason is a genuine caller cancellation and must reject as
      // a distinguishable AbortError, never mislabeled as a timeout.
      //
      // Settle FIRST, exactly like `tunnelStream`'s own `onAbort` — a
      // `stream.reset()` below can synchronously fire this SAME stream's
      // local `onReset` handler, which would otherwise overwrite the
      // AbortError / distinguishing timeout rejection below with a generic
      // `unknownReset(payload)` (`settleReject` is a no-op once `settled`).
      if (isTimeoutAbortReason(options.signal?.reason)) {
        finish("timeout");
        settleReject(
          new StreamResetError("timeout", "realtime session open timed out"),
        );
        stream.reset(streamReset("timeout", "realtime session open timed out"));
        return;
      }
      // No dedicated "cancelled" code exists in the closed `StreamResetCode`
      // wire vocabulary (adding one is a protocol change, out of scope here)
      // — "timeout" is still the peer-facing teardown signal, but the LOCAL
      // rejection below (what `openOverMuxLadder`/callers actually observe)
      // is a real AbortError carrying the original abort reason, so it can
      // never be confused with a genuine internal timeout.
      finish("timeout");
      settleReject(callerAbortError(options.signal));
      stream.reset(
        streamReset("timeout", "realtime session aborted by caller"),
      );
    };
    // Handshake budget, independent of `options.signal`: a caller that opens
    // with no signal at all (or one that never fires) must not wait forever
    // on a peer that swallows the OPEN and never sends `open_ack` — mirrors
    // `tunnelStream`'s own unconditional `headTimer`.
    const headTimer = setTimeout(() => {
      stream.reset(streamReset("timeout", "realtime session open timed out"));
      finish("timeout");
      settleReject(
        new StreamResetError("timeout", "realtime session open timed out"),
      );
    }, headTimeoutMs);
    const offReset = stream.onReset((payload) => {
      stopTimers();
      const code = resetCode(payload) ?? "peer_gone";
      finish(code);
      settleReject(unknownReset(payload));
    });
    const offEnd = stream.onEnd(() => {
      stopTimers();
      finish("done");
      // A stream that ends before `open_ack` ever arrived must REJECT the
      // opening promise, not leave it pending forever — `settleReject` is a
      // no-op once `open_ack` already resolved it, so this is safe to call
      // unconditionally on every END.
      settleReject(
        new StreamResetError("peer_gone", "stream ended before open_ack"),
      );
    });
    const offData = pumpRealtimeEvents(
      stream,
      (value) => {
        // Any successfully decoded JSON line is inbound traffic — refresh
        // BEFORE schema parse so unrecognized vendor events still keep the
        // heartbeat alive. Silence (no DATA / CTRL) still times out.
        lastInboundAt = Date.now();
        return parseRealtimeServerEvent(value);
      },
      (event) => {
        for (const handler of serverEventHandlers) handler(event);
      },
      () =>
        stream.reset(streamReset("lagging", "realtime event line too large")),
    );
    const offCtrl = stream.onCtrl((payload) => {
      const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
      if (ctrl === null) return;
      if (ctrl.t === "heartbeat") {
        lastInboundAt = Date.now();
        return;
      }
      if (ctrl.t !== "open_ack" || settled) return;
      if (!ctrl.ok) {
        const detail =
          (typeof ctrl.message === "string" && ctrl.message.length > 0
            ? ctrl.message
            : undefined) ??
          (typeof ctrl.error === "string" && ctrl.error.length > 0
            ? ctrl.error
            : undefined) ??
          "realtime session refused";
        const nackCode = isStreamResetCode(ctrl.error)
          ? ctrl.error
          : "protocol_error";
        settleReject(new StreamResetError(nackCode, detail));
        stream.reset(streamReset("protocol_error", detail));
        finish("protocol_error");
        return;
      }
      settled = true;
      clearTimeout(headTimer);
      lastInboundAt = Date.now();
      options.signal?.removeEventListener("abort", onAbort);
      lifetimeTimer = setTimeout(() => {
        stream.reset(
          streamReset("timeout", "realtime session max lifetime reached"),
        );
      }, maxLifetimeMs);
      heartbeatTimer = setInterval(() => {
        if (Date.now() - lastInboundAt > heartbeatTimeoutMs) {
          stream.reset(streamReset("timeout", "realtime heartbeat timed out"));
          return;
        }
        stream.sendCtrl(encodeJsonPayload({ t: "heartbeat" }));
      }, heartbeatIntervalMs);
      resolve({
        send: (event) => {
          void sendRealtimeEvent(stream, event);
        },
        onServerEvent: (handler) => {
          serverEventHandlers.add(handler);
          return () => serverEventHandlers.delete(handler);
        },
        close: () => {
          stopTimers();
          stream.end();
          finish("done");
        },
        closed,
      });
    });
    if (options.signal?.aborted) {
      onAbort();
    } else {
      options.signal?.addEventListener("abort", onAbort, { once: true });
    }
    void offReset;
    void offEnd;
    void offData;
    void offCtrl;
  });
};

export type TServeTunnelResponse = {
  readonly status: number;
  readonly headers?: TTunnelResponseHeaders;
  readonly body: ReadableStream<Uint8Array> | Uint8Array | null;
  /** Runs after the response body completes, errors, or the peer resets. */
  readonly onComplete?: () => void;
};

export type TServeTunnel = (
  open: TTunnelStreamOpenPayload,
  body: ReadableStream<Uint8Array>,
  signal: AbortSignal,
) => Promise<TServeTunnelResponse>;

export type TServeSession = (
  stream: TMuxStream,
  open: TSessionStreamOpenPayload,
) => void | Promise<void>;

/** Serving-side `kind:"realtime"` dispatch — given the raw stream, the
 *  handler owns admission (nack via `stream.reset`), the `open_ack` CTRL,
 *  and pumping events both ways (typically via `pumpRealtimeEvents` /
 *  `sendRealtimeEvent`). Mirrors `TServeSession`'s shape: unlike
 *  `TServeTunnel` (one request/response), a realtime session is long-lived
 *  and duplex. */
export type TServeRealtime = (
  stream: TMuxStream,
  open: TRealtimeStreamOpenPayload,
) => void | Promise<void>;

export type TServeStreamsOptions = {
  readonly tunnel: TServeTunnel;
  readonly session?: TServeSession;
  readonly realtime?: TServeRealtime;
  /** Reject a valid tunnel OPEN before dispatch, using host-specific wire semantics. */
  readonly admitTunnel?: (
    open: TTunnelStreamOpenPayload,
  ) => TStreamResetCode | null;
  /** Hosts that preserve a legacy malformed-OPEN code can override the default. */
  readonly invalidOpenCode?: TStreamResetCode;
};

const sendResponse = async (
  stream: TMuxStream,
  response: TServeTunnelResponse,
  signal: AbortSignal,
): Promise<void> => {
  try {
    if (signal.aborted) return;
    stream.sendCtrl(
      encodeJsonPayload({
        t: "res_head",
        status: response.status,
        ...(response.headers === undefined
          ? {}
          : { res_headers: response.headers }),
      }),
    );
    if (response.body instanceof Uint8Array) {
      if (response.body.byteLength > 0 && !signal.aborted) {
        await stream.write(response.body);
      }
    } else if (response.body !== null) {
      const reader = response.body.getReader();
      const cancel = (): void => {
        void reader.cancel().catch(() => {});
      };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        for (;;) {
          const next = await reader.read();
          if (next.done || signal.aborted) break;
          for (
            let offset = 0;
            offset < next.value.byteLength;
            offset += MAX_PAYLOAD_BYTES
          ) {
            if (signal.aborted) break;
            await stream.write(
              next.value.subarray(offset, offset + MAX_PAYLOAD_BYTES),
            );
          }
        }
      } finally {
        signal.removeEventListener("abort", cancel);
        reader.releaseLock();
      }
    }
    if (!signal.aborted) stream.end();
  } finally {
    response.onComplete?.();
  }
};

/** Bind application-level OPEN payloads to a serving mux channel. */
export const serveStreams = (
  channel: TMuxChannel,
  options: TServeStreamsOptions,
): (() => void) => channel.onStream(serveStream(options));

/** Application handler for `createChannel({ onStream })`, exported for hosts. */
export const serveStream =
  (
    options: TServeStreamsOptions,
  ): ((stream: TMuxStream, payload: Uint8Array) => void) =>
  (stream, payload) => {
    const open = parseStreamOpenPayload(decodeJsonPayload(payload));
    if (open === null) {
      stream.reset(
        streamReset(
          options.invalidOpenCode ?? "protocol_error",
          "invalid OPEN payload",
        ),
      );
      return;
    }
    if (open.kind === "session") {
      if (options.session === undefined) {
        stream.reset(streamReset("pty_unsupported"));
        return;
      }
      // Defer invoke so both sync throws and rejected promises hit the same
      // catch (Promise.resolve(fn()) does not catch sync throws from fn).
      const dispatch = options.session;
      void (async () => dispatch(stream, open))().catch(() => {
        stream.reset(streamReset("dispatch_failed"));
      });
      return;
    }
    if (open.kind === "realtime") {
      if (options.realtime === undefined) {
        stream.reset(streamReset("realtime_unsupported"));
        return;
      }
      const dispatch = options.realtime;
      void (async () => dispatch(stream, open))().catch(() => {
        stream.reset(streamReset("dispatch_failed"));
      });
      return;
    }
    const rejected = options.admitTunnel?.(open);
    if (rejected !== undefined && rejected !== null) {
      stream.reset(streamReset(rejected));
      return;
    }
    const abort = new AbortController();
    const offReset = stream.onReset(() => abort.abort());
    const body = bodyFromStream(stream, () => abort.abort(), false);
    void options
      .tunnel(open, body, abort.signal)
      .then((response) => sendResponse(stream, response, abort.signal))
      .catch(() => {
        if (!abort.signal.aborted) stream.reset(streamReset("dispatch_failed"));
      })
      .finally(offReset);
  };
