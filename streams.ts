import type {
  TSessionStreamOpenPayload,
  TStreamResetCode,
  TSubscriptionProviderSlug,
  TTunnelForwardHeaders,
  TTunnelResponseHeaders,
  TTunnelStreamOpenPayload,
  TTunnelSurface,
} from "@openllmsh/protocol";
import {
  parseStreamCtrlPayload,
  parseStreamOpenPayload,
  parseStreamResetPayload,
} from "@openllmsh/protocol";
import {
  decodeJsonPayload,
  encodeJsonPayload,
  MAX_PAYLOAD_BYTES,
} from "./codec";
import type { TMuxChannel, TMuxStream } from "./mux";

const streamReset = (code: TStreamResetCode, message?: string): Uint8Array =>
  encodeJsonPayload({ code, ...(message === undefined ? {} : { message }) });

const resetCode = (payload: Uint8Array): TStreamResetCode | null => {
  const decoded = parseStreamResetPayload(decodeJsonPayload(payload));
  return decoded?.code ?? null;
};

const unknownReset = (payload: Uint8Array): Error => {
  const parsed = parseStreamResetPayload(decodeJsonPayload(payload));
  return new Error(parsed?.message ?? parsed?.code ?? "stream reset");
};

const bodyFromStream = (
  stream: TMuxStream,
  onReset?: () => void,
): ReadableStream<Uint8Array> =>
  new ReadableStream<Uint8Array>({
    start(controller) {
      const offData = stream.onData((bytes) => controller.enqueue(bytes));
      const offEnd = stream.onEnd(() => {
        offData();
        offEnd();
        offReset();
        controller.close();
      });
      const offReset = stream.onReset((payload) => {
        offData();
        offEnd();
        offReset();
        onReset?.();
        controller.error(unknownReset(payload));
      });
    },
  });

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
    if (body.byteLength > 0) await stream.write(body);
    stream.end();
    return;
  }
  const reader = body.getReader();
  const onAbort = (): void => stream.reset(streamReset("peer_gone", "aborted"));
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
): Promise<TTunnelStreamResult> => {
  const stream = channel.openStream(
    encodeJsonPayload({
      kind: "tunnel",
      method: "POST",
      surface: options.surface,
      ...(options.headers === undefined ? {} : { headers: options.headers }),
    }),
  );
  void pumpBody(stream, options.body, options.signal);

  return new Promise<TTunnelStreamResult>((resolve, reject) => {
    let settled = false;
    const settle = (result: TTunnelStreamResult | Error): void => {
      if (settled) return;
      settled = true;
      offCtrl();
      offReset();
      if (result instanceof Error) reject(result);
      else resolve(result);
    };
    const offCtrl = stream.onCtrl((payload) => {
      const ctrl = parseStreamCtrlPayload(decodeJsonPayload(payload));
      if (ctrl?.t !== "res_head") return;
      const headers = new Headers();
      if (ctrl.res_headers?.content_type !== undefined) {
        headers.set("content-type", ctrl.res_headers.content_type);
      }
      settle({ status: ctrl.status, headers, body: bodyFromStream(stream) });
    });
    const offReset = stream.onReset((payload) => settle(unknownReset(payload)));
  });
};

export type TSessionStreamOptions = {
  readonly sessionId: string;
  readonly cli: TSubscriptionProviderSlug;
  readonly cols: number;
  readonly rows: number;
  readonly mode: "spawn" | "attach" | "continue";
  readonly title?: string;
};

export type TSessionCloseResult = TStreamResetCode | "done" | "detach";
export type TSessionStreamResult = {
  readonly live: boolean;
  readonly stdout: ReadableStream<Uint8Array>;
  readonly write: (bytes: Uint8Array) => Promise<void>;
  readonly resize: (cols: number, rows: number) => void;
  readonly detach: () => void;
  readonly kill: () => void;
  readonly onReplayDone: (callback: () => void) => () => void;
  readonly closed: Promise<TSessionCloseResult>;
};

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
    const offReset = stream.onReset((payload) => {
      const code = resetCode(payload) ?? "protocol_error";
      finish(code);
      if (!settled) {
        settled = true;
        reject(unknownReset(payload));
      }
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
        settled = true;
        stream.reset(streamReset("protocol_error"));
        reject(new Error("session refused"));
        return;
      }
      settled = true;
      resolve({
        live: ctrl.live ?? false,
        stdout: bodyFromStream(stream),
        write: stream.write,
        resize: (cols, rows) =>
          stream.sendCtrl(encodeJsonPayload({ t: "resize", cols, rows })),
        detach: () => {
          stream.end();
          finish("detach");
        },
        kill: () => {
          stream.sendCtrl(encodeJsonPayload({ t: "close", intent: "kill" }));
          stream.end();
        },
        onReplayDone: (callback) => {
          if (replayDoneSeen) {
            callback();
            return () => {};
          }
          replayHandlers.add(callback);
          return () => replayHandlers.delete(callback);
        },
        closed,
      });
    });
    // Keep reset/end subscriptions live after open; only the open-ack listener is one-shot.
    void offReset;
    void offEnd;
    void _offCtrl;
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

export type TServeStreamsOptions = {
  readonly tunnel: TServeTunnel;
  readonly session?: TServeSession;
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
      void Promise.resolve(options.session(stream, open)).catch(() => {
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
    const body = bodyFromStream(stream, () => abort.abort());
    void options
      .tunnel(open, body, abort.signal)
      .then((response) => sendResponse(stream, response, abort.signal))
      .catch(() => {
        if (!abort.signal.aborted) stream.reset(streamReset("dispatch_failed"));
      })
      .finally(offReset);
  };
