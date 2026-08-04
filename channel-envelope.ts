/**
 * Channel-tagged binary envelope for the relay-mux WebSocket hop.
 *
 * The frozen mux codec (`codec.ts`) has no channel id in its nine-byte header,
 * so a relay route by sender-socket identity alone caps every socket at one
 * mux channel. The envelope fixes that WITHOUT touching the frozen codec: it
 * wraps the WHOLE WebSocket message — a 16-byte channel UUID (RFC 4122 text
 * form, hyphenated lowercase, 36 chars) prepended to the binary payload:
 *
 * ```
 * ┌───────────────────────────┬──────────────────────────┐
 * │ channel UUID (16 bytes)   │ mux frame(s) payload     │
 * └───────────────────────────┴──────────────────────────┘
 * ```
 *
 * Peers negotiate the envelope out-of-band with the `mux2` capability; it is
 * applied only on channels where the relay recorded `enc`. RTC data channels
 * never carry it (no relay hop — the data channel itself is the channel).
 *
 * This module is dependency-free, mirroring `codec.ts`'s posture: the relay
 * can validate and unwrap a message without learning the payload shape.
 */

export const CHANNEL_ENVELOPE_TAG_BYTES = 16;

/** RFC 4122 text form: 8-4-4-4-12 lowercase hex, variant nibble `8|9|a|b`. */
const CHANNEL_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const isChannelId = (value: string): boolean =>
  CHANNEL_ID_PATTERN.test(value);

/** The 16 wire bytes of a canonical UUID. Throws RangeError on bad input. */
export const channelIdToBytes = (channelId: string): Uint8Array => {
  if (!isChannelId(channelId)) {
    throw new RangeError("channel id must be a canonical lowercase UUID");
  }
  const hex = channelId.replaceAll("-", "");
  const bytes = new Uint8Array(CHANNEL_ENVELOPE_TAG_BYTES);
  for (let index = 0; index < CHANNEL_ENVELOPE_TAG_BYTES; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
};

const HEX = "0123456789abcdef";

/** Canonical lowercase text form of 16 tag bytes. Never throws. */
export const channelIdFromBytes = (tag: Uint8Array): string | null => {
  if (tag.byteLength !== CHANNEL_ENVELOPE_TAG_BYTES) return null;
  let text = "";
  for (let index = 0; index < CHANNEL_ENVELOPE_TAG_BYTES; index += 1) {
    const byte = tag[index];
    text += HEX[byte >> 4] + HEX[byte & 0x0f];
    if (index === 3 || index === 5 || index === 7 || index === 9) text += "-";
  }
  return isChannelId(text) ? text : null;
};

/**
 * Derive a reconnect-stable UUID for one browser-device-to-device mux channel.
 * NUL delimiters make the UTF-8 identity encoding unambiguous.
 */
export const stableChannelId = async (
  userId: string,
  keyId: string,
  browserDeviceId: string,
  slot = 0,
): Promise<string> => {
  const identity = `${userId}\0${keyId}\0${browserDeviceId}\0${slot}`;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(identity),
  );
  const tag = new Uint8Array(digest.slice(0, CHANNEL_ENVELOPE_TAG_BYTES));
  tag[6] = (tag[6] & 0x0f) | 0x40;
  tag[8] = (tag[8] & 0x3f) | 0x80;

  const channelId = channelIdFromBytes(tag);
  if (channelId === null) {
    throw new Error("derived channel id is not canonical");
  }
  return channelId;
};

/** Wrap one whole WebSocket message. Caller contract violations throw RangeError. */
export const encodeChannelEnvelope = (
  channelId: string,
  payload: Uint8Array,
): Uint8Array => {
  const tag = channelIdToBytes(channelId);
  const encoded = new Uint8Array(
    CHANNEL_ENVELOPE_TAG_BYTES + payload.byteLength,
  );
  encoded.set(tag, 0);
  encoded.set(payload, CHANNEL_ENVELOPE_TAG_BYTES);
  return encoded;
};

export type TChannelEnvelopeDecodeResult =
  | {
      readonly ok: true;
      readonly channelId: string;
      readonly payload: Uint8Array;
    }
  | { readonly ok: false; readonly error: "truncated_envelope" | "bad_tag" };

/** Unwrap one whole message. Never throws; the payload is a view (no copy). */
export const decodeChannelEnvelope = (
  bytes: Uint8Array,
): TChannelEnvelopeDecodeResult => {
  if (bytes.byteLength < CHANNEL_ENVELOPE_TAG_BYTES) {
    return { ok: false, error: "truncated_envelope" };
  }
  const channelId = channelIdFromBytes(
    bytes.subarray(0, CHANNEL_ENVELOPE_TAG_BYTES),
  );
  if (channelId === null) return { ok: false, error: "bad_tag" };
  return {
    ok: true,
    channelId,
    payload: bytes.subarray(CHANNEL_ENVELOPE_TAG_BYTES),
  };
};
