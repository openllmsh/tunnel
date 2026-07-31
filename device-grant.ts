/**
 * Canonical device-grant wire format shared by the browser (which
 * SIGNS grants with the vault-derived device-access key) and the
 * daemon (which VERIFIES them). Dependency-free: bytes + JSON only —
 * no crypto lives here.
 */

export const DEVICE_GRANT_LABEL = "openllm-device-grant-v1";
export const DEVICE_GRANT_VERSION = 1 as const;
export const DEVICE_GRANT_TS_WINDOW_MS = 120_000;
export const DEVICE_GRANT_NONCE_BYTES = 16;
/**
 * Soft upper bound on the base64 envelope string. Matches
 * `DEVICE_GRANT_B64_MAX` in `@openllmsh/protocol` relay frames so codec and
 * Schema reject the same oversized grants. Kept as a literal here because
 * tunnel is dep-free of protocol.
 */
export const DEVICE_GRANT_B64_MAX = 4 * 1024;

export type TDeviceGrantFields = {
  readonly v: 1;
  /** 16-byte nonce, base64. */
  readonly n: string;
  /** ms since epoch at signing time. */
  readonly ts: number;
  /** The daemon's api key id. */
  readonly key_id: string;
  /** channel_id / tunnel_id / rtc channel_id being granted. */
  readonly cid: string;
  /** Daemon X25519 pubkey b64 ("" when unknown — legacy tunnel path). */
  readonly aud: string;
};

export type TDeviceGrantEnvelope = TDeviceGrantFields & {
  readonly sig: string;
};

/**
 * Canonical signed bytes: `utf8(LABEL) || 0x00 || utf8(json)`.
 *
 * The JSON is canonical-by-construction: it is produced by
 * `JSON.stringify` of an object literal written in the fixed field
 * order `v, n, ts, key_id, cid, aud`. ECMAScript guarantees own
 * string-keyed property enumeration (and therefore stringify output)
 * follows insertion order, so building the literal in that order
 * yields identical bytes for identical fields on every runtime.
 */
export const buildDeviceGrantMessage = (
  fields: TDeviceGrantFields,
): Uint8Array => {
  const json = JSON.stringify({
    v: fields.v,
    n: fields.n,
    ts: fields.ts,
    key_id: fields.key_id,
    cid: fields.cid,
    aud: fields.aud,
  });
  const label = new TextEncoder().encode(DEVICE_GRANT_LABEL);
  const body = new TextEncoder().encode(json);
  const out = new Uint8Array(label.length + 1 + body.length);
  out.set(label, 0);
  out[label.length] = 0x00;
  out.set(body, label.length + 1);
  return out;
};

/** base64(JSON) envelope encoding for the wire. */
export const encodeDeviceGrant = (envelope: TDeviceGrantEnvelope): string => {
  const json = JSON.stringify(envelope);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i] as number);
  }
  return btoa(bin);
};

const isNonEmptyString = (value: unknown): value is string => {
  return typeof value === "string" && value.length > 0;
};

/** True when `n` is base64 of exactly {@link DEVICE_GRANT_NONCE_BYTES} bytes. */
const isValidNonce = (value: unknown): value is string => {
  if (!isNonEmptyString(value)) return false;
  try {
    const bin = atob(value);
    return bin.length === DEVICE_GRANT_NONCE_BYTES;
  } catch {
    return false;
  }
};

/**
 * Strict decode: returns null on any shape mismatch. `aud` may be the
 * empty string (legacy tunnel path); every other string field must be
 * non-empty, `v` must be exactly 1, `n` base64 of
 * {@link DEVICE_GRANT_NONCE_BYTES} bytes, and `ts` a finite positive integer.
 */
export const decodeDeviceGrant = (b64: string): TDeviceGrantEnvelope | null => {
  if (b64.length > DEVICE_GRANT_B64_MAX) return null;
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
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const o = parsed as Record<string, unknown>;
  if (o.v !== DEVICE_GRANT_VERSION) return null;
  if (!isValidNonce(o.n)) return null;
  if (
    typeof o.ts !== "number" ||
    !Number.isFinite(o.ts) ||
    !Number.isInteger(o.ts) ||
    o.ts <= 0
  ) {
    return null;
  }
  if (!isNonEmptyString(o.key_id)) return null;
  if (!isNonEmptyString(o.cid)) return null;
  if (typeof o.aud !== "string") return null;
  if (!isNonEmptyString(o.sig)) return null;
  return {
    v: DEVICE_GRANT_VERSION,
    n: o.n,
    ts: o.ts,
    key_id: o.key_id,
    cid: o.cid,
    aud: o.aud,
    sig: o.sig,
  };
};
