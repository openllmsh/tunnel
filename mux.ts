import type { TFrame, TFrameType } from "./codec";
import {
  decodeFrame,
  decodeWindowPayload,
  encodeFrame,
  FRAME_TYPE,
  INITIAL_STREAM_WINDOW_BYTES,
  isConsumerStreamId,
  MAX_PAYLOAD_BYTES,
  STREAM_ID_CTRL,
  WINDOW_REPLENISH_THRESHOLD,
  windowPayload,
} from "./codec";

/** A host-owned message transport. `null` passed to `onBytes` means the peer died. */
export type TDuplex = {
  readonly send: (bytes: Uint8Array) => void;
  readonly onBytes: (callback: (bytes: Uint8Array | null) => void) => void;
  readonly close: () => void;
};

export type TChannelSide = "consumer" | "daemon";
export type TChannelCloseReason = string;
export type TMuxEventHandler = (payload: Uint8Array) => void;

export type TMuxStream = {
  readonly id: number;
  readonly write: (bytes: Uint8Array) => Promise<void>;
  readonly end: () => void;
  readonly reset: (payload?: Uint8Array) => void;
  readonly sendCtrl: (payload: Uint8Array) => void;
  readonly onData: (handler: TMuxEventHandler) => () => void;
  readonly onEnd: (handler: () => void) => () => void;
  readonly onReset: (handler: TMuxEventHandler) => () => void;
  readonly onCtrl: (handler: TMuxEventHandler) => () => void;
};

export type TMuxChannel = {
  readonly openStream: (openPayload: Uint8Array) => TMuxStream;
  readonly sendCtrl: (payload: Uint8Array) => void;
  readonly onCtrl: (handler: TMuxEventHandler) => () => void;
  readonly onStream: (
    handler: (stream: TMuxStream, openPayload: Uint8Array) => void,
  ) => () => void;
  readonly close: (reason?: TChannelCloseReason) => void;
  readonly openStreamCount: () => number;
};

export type TCreateChannelOptions = {
  readonly duplex: TDuplex;
  readonly side: TChannelSide;
  readonly onStream?: (stream: TMuxStream, openPayload: Uint8Array) => void;
  readonly onClose?: (reason: TChannelCloseReason) => void;
  /**
   * Sender-side DATA payload cap (bytes). Defaults to {@link MAX_PAYLOAD_BYTES}.
   * Used to stay under transport message-size limits (e.g. SCTP `maxMessageSize`
   * on a WebRTC data channel). Decode still accepts up to {@link MAX_PAYLOAD_BYTES}.
   * Finite values below 1 clamp to 1; undefined / non-finite / oversized fall
   * back to {@link MAX_PAYLOAD_BYTES}.
   */
  readonly maxPayloadBytes?: number;
};

type TPendingWrite = {
  readonly bytes: Uint8Array;
  offset: number;
  readonly resolve: () => void;
  readonly reject: (reason: Error) => void;
};

type TStreamState = {
  readonly id: number;
  readonly dataHandlers: Set<TMuxEventHandler>;
  readonly endHandlers: Set<() => void>;
  readonly resetHandlers: Set<TMuxEventHandler>;
  readonly ctrlHandlers: Set<TMuxEventHandler>;
  readonly pending: TPendingWrite[];
  sendCredit: number;
  receiveCredit: number;
  consumedSinceWindow: number;
  localEnded: boolean;
  remoteEnded: boolean;
  endRequested: boolean;
  reset: boolean;
  stream: TMuxStream | null;
};

const on = <T>(handlers: Set<T>, handler: T): (() => void) => {
  handlers.add(handler);
  return () => handlers.delete(handler);
};

const emit = <T>(
  handlers: ReadonlySet<T>,
  invoke: (handler: T) => void,
): void => {
  for (const handler of handlers) {
    try {
      invoke(handler);
    } catch {
      // User event handlers cannot destabilize the wire state machine.
    }
  }
};

const resetError = (payload: Uint8Array | undefined): Error => {
  const detail =
    payload === undefined || payload.byteLength === 0
      ? "stream reset"
      : "stream reset by peer";
  return new Error(detail);
};

/**
 * Stateful, sans-I/O stream multiplexer. A WebSocket host gives it one complete
 * binary message at a time; no timers, DOM APIs, Bun APIs, or transport policy
 * live here.
 */
export const createChannel = (options: TCreateChannelOptions): TMuxChannel => {
  const streams = new Map<number, TStreamState>();
  const channelCtrlHandlers = new Set<TMuxEventHandler>();
  const streamHandlers = new Set<
    (stream: TMuxStream, openPayload: Uint8Array) => void
  >();
  if (options.onStream !== undefined) streamHandlers.add(options.onStream);
  let nextStreamId = options.side === "consumer" ? 1 : 2;
  let closed = false;
  // Sender-only chunk size. Keep decode-side MAX_PAYLOAD_BYTES as the wire max.
  // Floor before validating so fractional values like 0.9 don't become 0 and
  // permanently stall drain() (Math.min(..., 0) never advances pending writes).
  const maxPayloadBytes = (() => {
    const requested = options.maxPayloadBytes;
    if (requested === undefined) return MAX_PAYLOAD_BYTES;
    if (!Number.isFinite(requested)) return MAX_PAYLOAD_BYTES;
    const floored = Math.floor(requested);
    // Finite values below 1 clamp to 1 so drain() still advances; only
    // undefined / non-finite / oversized fall back to MAX_PAYLOAD_BYTES.
    if (floored > MAX_PAYLOAD_BYTES) return MAX_PAYLOAD_BYTES;
    if (floored < 1) return 1;
    return floored;
  })();

  const send = (
    type: TFrameType,
    streamId: number,
    payload: Uint8Array,
  ): void => {
    if (closed) return;
    options.duplex.send(encodeFrame({ type, streamId, payload }));
  };

  const localReset = (state: TStreamState, payload?: Uint8Array): void => {
    if (state.reset) return;
    state.reset = true;
    for (const pending of state.pending.splice(0)) {
      pending.reject(resetError(payload));
    }
    streams.delete(state.id);
    emit(state.resetHandlers, (handler) =>
      handler(payload ?? new Uint8Array()),
    );
  };

  const close = (reason: TChannelCloseReason = "done"): void => {
    if (closed) return;
    closed = true;
    for (const state of [...streams.values()]) localReset(state);
    try {
      options.duplex.close();
    } catch {
      // A dead transport is already closed from the mux's perspective.
    }
    try {
      options.onClose?.(reason);
    } catch {
      // close is terminal regardless of observer failures.
    }
  };

  const protocolError = (): void => close("protocol_error");

  const sendEndIfReady = (state: TStreamState): void => {
    if (
      !state.endRequested ||
      state.localEnded ||
      state.pending.length > 0 ||
      state.reset ||
      closed
    )
      return;
    state.localEnded = true;
    send(FRAME_TYPE.end, state.id, new Uint8Array());
  };

  const drain = (state: TStreamState): void => {
    while (
      !closed &&
      !state.reset &&
      state.sendCredit > 0 &&
      state.pending.length > 0
    ) {
      const pending = state.pending[0];
      const remaining = pending.bytes.byteLength - pending.offset;
      const size = Math.min(remaining, state.sendCredit, maxPayloadBytes);
      if (size <= 0) break;
      const chunk = pending.bytes.subarray(
        pending.offset,
        pending.offset + size,
      );
      send(FRAME_TYPE.data, state.id, chunk);
      pending.offset += size;
      state.sendCredit -= size;
      if (pending.offset === pending.bytes.byteLength) {
        state.pending.shift();
        pending.resolve();
      }
    }
    sendEndIfReady(state);
  };

  const makeState = (id: number): TStreamState => ({
    id,
    dataHandlers: new Set(),
    endHandlers: new Set(),
    resetHandlers: new Set(),
    ctrlHandlers: new Set(),
    pending: [],
    sendCredit: INITIAL_STREAM_WINDOW_BYTES,
    receiveCredit: INITIAL_STREAM_WINDOW_BYTES,
    consumedSinceWindow: 0,
    localEnded: false,
    remoteEnded: false,
    endRequested: false,
    reset: false,
    stream: null,
  });

  const makeStream = (state: TStreamState): TMuxStream => {
    const stream: TMuxStream = {
      id: state.id,
      write: (bytes) => {
        if (state.localEnded || state.endRequested) {
          throw new Error("write after end");
        }
        if (state.reset || closed)
          return Promise.reject(new Error("stream is closed"));
        if (bytes.byteLength === 0) return Promise.resolve();
        return new Promise<void>((resolve, reject) => {
          state.pending.push({ bytes, offset: 0, resolve, reject });
          drain(state);
        });
      },
      end: () => {
        if (state.localEnded || state.endRequested || state.reset || closed)
          return;
        state.endRequested = true;
        sendEndIfReady(state);
      },
      reset: (payload = new Uint8Array()) => {
        if (state.reset || closed) return;
        send(FRAME_TYPE.reset, state.id, payload);
        localReset(state, payload);
      },
      sendCtrl: (payload) => {
        if (!state.reset && !closed) send(FRAME_TYPE.ctrl, state.id, payload);
      },
      onData: (handler) => on(state.dataHandlers, handler),
      onEnd: (handler) => on(state.endHandlers, handler),
      onReset: (handler) => on(state.resetHandlers, handler),
      onCtrl: (handler) => on(state.ctrlHandlers, handler),
    };
    state.stream = stream;
    return stream;
  };

  const openStream = (openPayload: Uint8Array): TMuxStream => {
    if (closed) throw new Error("channel is closed");
    if (nextStreamId > 0xffff_ffff) throw new Error("stream ids exhausted");
    const id = nextStreamId;
    nextStreamId += 2;
    const state = makeState(id);
    const stream = makeStream(state);
    streams.set(id, state);
    send(FRAME_TYPE.open, id, openPayload);
    return stream;
  };

  const onFrame = (frame: TFrame): void => {
    if (closed) return;
    if (frame.type === FRAME_TYPE.ctrl && frame.streamId === STREAM_ID_CTRL) {
      emit(channelCtrlHandlers, (handler) => handler(frame.payload));
      return;
    }
    if (frame.streamId === STREAM_ID_CTRL) {
      protocolError();
      return;
    }

    if (frame.type === FRAME_TYPE.open) {
      const expectedConsumer = options.side === "daemon";
      if (
        isConsumerStreamId(frame.streamId) !== expectedConsumer ||
        streams.has(frame.streamId)
      ) {
        protocolError();
        return;
      }
      const state = makeState(frame.streamId);
      const stream = makeStream(state);
      streams.set(frame.streamId, state);
      try {
        emit(streamHandlers, (handler) => handler(stream, frame.payload));
      } catch {
        stream.reset();
      }
      return;
    }

    const state = streams.get(frame.streamId);
    if (state === undefined) {
      // RESET removes state immediately; delayed frames must never recreate it.
      return;
    }

    switch (frame.type) {
      case FRAME_TYPE.data: {
        if (
          state.remoteEnded ||
          frame.payload.byteLength > state.receiveCredit
        ) {
          protocolError();
          return;
        }
        state.receiveCredit -= frame.payload.byteLength;
        state.consumedSinceWindow += frame.payload.byteLength;
        emit(state.dataHandlers, (handler) => handler(frame.payload));
        if (state.consumedSinceWindow >= WINDOW_REPLENISH_THRESHOLD) {
          const delta = state.consumedSinceWindow;
          state.receiveCredit += delta;
          state.consumedSinceWindow = 0;
          send(FRAME_TYPE.window, state.id, windowPayload(delta));
        }
        return;
      }
      case FRAME_TYPE.end:
        if (frame.payload.byteLength !== 0 || state.remoteEnded) {
          protocolError();
          return;
        }
        state.remoteEnded = true;
        emit(state.endHandlers, (handler) => handler());
        return;
      case FRAME_TYPE.reset:
        localReset(state, frame.payload);
        return;
      case FRAME_TYPE.window: {
        const delta = decodeWindowPayload(frame.payload);
        if (delta === null || delta > 0x7fff_ffff) {
          protocolError();
          return;
        }
        state.sendCredit += delta;
        drain(state);
        return;
      }
      case FRAME_TYPE.ctrl:
        emit(state.ctrlHandlers, (handler) => handler(frame.payload));
        return;
      default:
        protocolError();
        return;
    }
  };

  options.duplex.onBytes((bytes) => {
    try {
      if (bytes === null) {
        close("peer_gone");
        return;
      }
      const decoded = decodeFrame(bytes);
      if (!decoded.ok) {
        protocolError();
        return;
      }
      onFrame(decoded.frame);
    } catch {
      // The public onBytes boundary must never throw into the WebSocket host.
      protocolError();
    }
  });

  return {
    openStream,
    sendCtrl: (payload) => send(FRAME_TYPE.ctrl, STREAM_ID_CTRL, payload),
    onCtrl: (handler) => on(channelCtrlHandlers, handler),
    onStream: (handler) => on(streamHandlers, handler),
    close,
    openStreamCount: () => streams.size,
  };
};
