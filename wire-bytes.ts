/**
 * The two byte-level primitives every signed control-plane envelope shares
 * (device grants, control-key rotations, device-sessions commands, daemon
 * attestations): the canonical signed bytes and the base64(JSON) wire form.
 * Bytes + JSON only — no crypto.
 */

/** Standard (padded) base64 of `bytes`. */
export const toB64Bytes = (bytes: Uint8Array): string => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i] as number);
  }
  return btoa(bin);
};

/** Inverse of {@link toB64Bytes}; null when `b64` is not valid standard base64. */
export const fromB64Bytes = (b64: string): Uint8Array | null => {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

/**
 * Canonical signed bytes: `utf8(label) || 0x00 || utf8(json)`. Callers build
 * `json` from an object literal in a fixed key order, so identical fields
 * give identical bytes on every runtime.
 */
export const labelledMessage = (label: string, json: string): Uint8Array => {
  const enc = new TextEncoder();
  const head = enc.encode(label);
  const body = enc.encode(json);
  const out = new Uint8Array(head.length + 1 + body.length);
  out.set(head, 0);
  out[head.length] = 0x00;
  out.set(body, head.length + 1);
  return out;
};

/**
 * `base64(utf8(JSON.stringify(value)))`. Throws `RangeError(overflow)` when
 * the result is longer than `max`, so an oversized envelope never reaches
 * the wire.
 */
export const encodeB64Json = (
  value: unknown,
  max: number,
  overflow: string,
): string => {
  const b64 = toB64Bytes(new TextEncoder().encode(JSON.stringify(value)));
  if (b64.length > max) throw new RangeError(overflow);
  return b64;
};

/**
 * Strict inverse of {@link encodeB64Json}: the parsed JSON object, or null
 * when `b64` is empty, longer than `max`, not base64, not UTF-8, not JSON, or
 * not a plain (non-array) object. Field validation is the caller's.
 */
export const decodeB64Json = (
  b64: string,
  max: number,
): Record<string, unknown> | null => {
  if (b64.length === 0 || b64.length > max) return null;
  let parsed: unknown;
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    parsed = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
};

/** A non-empty string field. */
export const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** True when `value` is standard base64 of exactly `bytes` bytes (a nonce). */
export const isB64OfLength = (
  value: unknown,
  bytes: number,
): value is string => {
  if (!isNonEmptyString(value)) return false;
  try {
    return atob(value).length === bytes;
  } catch {
    return false;
  }
};
