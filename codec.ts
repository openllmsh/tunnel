/**
 * The P1 mux wire codec. This module is dependency-free by design so the
 * relay can validate and forward a frame without learning its payload shape.
 */

export const FRAME_HEADER_BYTES = 9;
export const MAX_PAYLOAD_BYTES = 256 * 1024;
export const INITIAL_STREAM_WINDOW_BYTES = 256 * 1024;
export const WINDOW_REPLENISH_THRESHOLD = 128 * 1024;
export const STREAM_ID_CTRL = 0;
export const MAX_STREAM_ID = 0xffff_ffff;

export const FRAME_TYPE = {
  open: 0x01,
  data: 0x02,
  end: 0x03,
  reset: 0x04,
  window: 0x05,
  ctrl: 0x06,
} as const;

export type TFrameType = (typeof FRAME_TYPE)[keyof typeof FRAME_TYPE];

export type TFrame = {
  readonly type: TFrameType;
  readonly streamId: number;
  readonly payload: Uint8Array;
};

export type TFrameDecodeError =
  | "truncated_header"
  | "unknown_frame_type"
  | "length_mismatch"
  | "payload_too_large";

export type TFrameDecodeResult =
  | { readonly ok: true; readonly frame: TFrame }
  | { readonly ok: false; readonly error: TFrameDecodeError };

export type TFrameHeader = {
  readonly type: number;
  readonly streamId: number;
  readonly length: number;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const isKnownFrameType = (value: number): value is TFrameType =>
  value === FRAME_TYPE.open ||
  value === FRAME_TYPE.data ||
  value === FRAME_TYPE.end ||
  value === FRAME_TYPE.reset ||
  value === FRAME_TYPE.window ||
  value === FRAME_TYPE.ctrl;

export const isConsumerStreamId = (streamId: number): boolean =>
  Number.isInteger(streamId) &&
  streamId > 0 &&
  streamId <= MAX_STREAM_ID &&
  streamId % 2 === 1;

const isUint32 = (value: number): boolean =>
  Number.isInteger(value) && value >= 0 && value <= MAX_STREAM_ID;

/** Return the fixed header without allocating a payload view. */
export const peekFrameHeader = (bytes: Uint8Array): TFrameHeader | null => {
  if (bytes.byteLength < FRAME_HEADER_BYTES) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    type: bytes[0],
    streamId: view.getUint32(1, false),
    length: view.getUint32(5, false),
  };
};

/** Encode one whole WebSocket message. Caller contract violations throw RangeError. */
export const encodeFrame = (frame: TFrame): Uint8Array => {
  if (!isKnownFrameType(frame.type)) throw new RangeError("unknown frame type");
  if (!isUint32(frame.streamId))
    throw new RangeError("stream id must be a u32");
  if (frame.payload.byteLength > MAX_PAYLOAD_BYTES) {
    throw new RangeError("payload exceeds MAX_PAYLOAD_BYTES");
  }

  const encoded = new Uint8Array(FRAME_HEADER_BYTES + frame.payload.byteLength);
  const view = new DataView(
    encoded.buffer,
    encoded.byteOffset,
    encoded.byteLength,
  );
  encoded[0] = frame.type;
  view.setUint32(1, frame.streamId, false);
  view.setUint32(5, frame.payload.byteLength, false);
  encoded.set(frame.payload, FRAME_HEADER_BYTES);
  return encoded;
};

/** Decode one whole message. Never throws and never allocates from a claimed length. */
export const decodeFrame = (bytes: Uint8Array): TFrameDecodeResult => {
  const header = peekFrameHeader(bytes);
  if (header === null) return { ok: false, error: "truncated_header" };
  if (!isKnownFrameType(header.type)) {
    return { ok: false, error: "unknown_frame_type" };
  }
  if (header.length > MAX_PAYLOAD_BYTES) {
    return { ok: false, error: "payload_too_large" };
  }
  if (header.length !== bytes.byteLength - FRAME_HEADER_BYTES) {
    return { ok: false, error: "length_mismatch" };
  }
  return {
    ok: true,
    frame: {
      type: header.type,
      streamId: header.streamId,
      payload: bytes.subarray(FRAME_HEADER_BYTES),
    },
  };
};

export const windowPayload = (delta: number): Uint8Array => {
  if (!isUint32(delta)) throw new RangeError("window delta must be a u32");
  const payload = new Uint8Array(4);
  new DataView(payload.buffer).setUint32(0, delta, false);
  return payload;
};

export const decodeWindowPayload = (payload: Uint8Array): number | null => {
  if (payload.byteLength !== 4) return null;
  return new DataView(
    payload.buffer,
    payload.byteOffset,
    payload.byteLength,
  ).getUint32(0, false);
};

export const encodeJsonPayload = (value: unknown): Uint8Array => {
  let text: string;
  try {
    text = JSON.stringify(value);
  } catch {
    throw new RangeError("value is not JSON serializable");
  }
  if (text === undefined)
    throw new RangeError("value is not JSON serializable");
  const payload = encoder.encode(text);
  if (payload.byteLength > MAX_PAYLOAD_BYTES) {
    throw new RangeError("JSON payload exceeds MAX_PAYLOAD_BYTES");
  }
  return payload;
};

export const decodeJsonPayload = (payload: Uint8Array): unknown | undefined => {
  if (payload.byteLength > MAX_PAYLOAD_BYTES) return undefined;
  try {
    return JSON.parse(decoder.decode(payload));
  } catch {
    return undefined;
  }
};
