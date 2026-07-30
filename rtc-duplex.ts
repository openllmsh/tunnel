/**
 * ~20-line TDuplex over an RTCDataChannel (browser DOM or werift).
 *
 * The mux contract is message-oriented: one complete binary message per
 * `onBytes` call. RTCDataChannel is already message-oriented when used with
 * binary payloads, so this adapter only bridges the event surface.
 *
 * werift notes (v0.24.x, verified under Bun):
 * - no `binaryType` property — payloads arrive as Buffer/Uint8Array via
 *   `onmessage` callback (or addEventListener where available);
 * - `onmessage` receives `{ data: string | Buffer }`.
 *
 * Callers must set an ordered, negotiated (or offerer-created) data channel
 * and open it before the mux starts writing. Closing the duplex closes the
 * channel; a null `onBytes` delivery signals peer death to the mux.
 */
import type { TDuplex } from "./mux";

/**
 * Minimal surface shared by the browser `RTCDataChannel` and werift's channel.
 * Intentionally narrower than the full DOM type so werift is assignable without
 * casting at every call site.
 */
export type TRtcDataChannelLike = {
  readonly readyState: string;
  readonly bufferedAmount: number;
  send: (data: string | ArrayBuffer | ArrayBufferView) => void;
  close: () => void;
  /**
   * DOM: EventTarget. werift: may only expose the `onmessage` property. We
   * prefer addEventListener when present and fall back to the property.
   */
  addEventListener?: (
    type: string,
    listener: (event: { data: unknown }) => void,
  ) => void;
  removeEventListener?: (
    type: string,
    listener: (event: { data: unknown }) => void,
  ) => void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onclose: ((event?: unknown) => void) | null;
  onerror: ((event?: unknown) => void) | null;
};

const toUint8 = (data: unknown): Uint8Array | null => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  // Text payloads are not part of the mux contract — drop them.
  return null;
};

/**
 * Wrap an open (or soon-to-open) data channel as a {@link TDuplex}.
 *
 * Sends that fire before `readyState === "open"` are dropped (the mux only
 * writes after the channel is open in practice; a defensive no-op keeps a
 * racy close from throwing into the mux state machine).
 */
export const rtcDuplex = (dc: TRtcDataChannelLike): TDuplex => {
  let listener: ((bytes: Uint8Array | null) => void) | null = null;
  let closed = false;

  const deliver = (bytes: Uint8Array | null): void => {
    try {
      listener?.(bytes);
    } catch {
      // Mux onBytes boundary is never allowed to throw into the host.
    }
  };

  const onMessage = (event: { data: unknown }): void => {
    if (closed) return;
    const bytes = toUint8(event.data);
    if (bytes === null) return;
    deliver(bytes);
  };

  const onPeerGone = (): void => {
    if (closed) return;
    closed = true;
    // Deliver AFTER flipping closed so re-entrant close is a no-op, but the
    // terminal null still reaches the mux.
    deliver(null);
  };

  if (typeof dc.addEventListener === "function") {
    dc.addEventListener("message", onMessage);
    dc.addEventListener("close", onPeerGone);
    dc.addEventListener("error", onPeerGone);
  } else {
    dc.onmessage = onMessage;
    dc.onclose = onPeerGone;
    dc.onerror = onPeerGone;
  }

  return {
    send: (bytes) => {
      if (closed || dc.readyState !== "open") return;
      try {
        // Pass a copy-friendly view; WebRTC/werift copy into the SCTP stack.
        dc.send(bytes);
      } catch {
        onPeerGone();
      }
    },
    onBytes: (callback) => {
      listener = callback;
    },
    close: () => {
      if (closed) return;
      closed = true;
      try {
        dc.close();
      } catch {
        // already closed
      }
      // Do not deliver null here — local close is not peer death; the mux's
      // own close() already tears streams down before calling duplex.close().
    },
  };
};
