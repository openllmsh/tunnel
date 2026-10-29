/**
 * Origin-signed team device grant. Short-lived admission for a cross-user
 * relay mux channel: the consumer may reach one contributor device for one
 * model. Wire is labelled canonical JSON + HMAC-SHA256 (WebCrypto) under the
 * per-contributor key derived at origin
 * (`HMAC-SHA256(NEON_AUTH_COOKIE_SECRET, "openllm-team-grant-v1:" + userId)`).
 * The contributor daemon verifies with the same key from bootstrap
 * (`team_grant_key`). The relay does NOT verify — it only stamps
 * `peer_user_id` and requires a non-empty `team_grant` for cross-user opens.
 *
 * Unknown future envelope fields are ignored on decode; the signed message is
 * rebuilt from the known field set only, so a v2 verifier stays compatible
 * when optional fields are added later (each optional is part of the signed
 * bytes only when present). v1 (Ed25519) envelopes are rejected.
 */

import { TEAM_GRANT_B64_MAX } from "@openllmsh/protocol";
import {
  decodeB64Json,
  encodeB64Json,
  isB64OfLength,
  isNonEmptyString,
  labelledMessage,
} from "./wire-bytes";

export { TEAM_GRANT_B64_MAX };

/** Canonical message label for the signed JSON body (format version). */
export const TEAM_GRANT_LABEL = "openllm-team-grant-v2";
export const TEAM_GRANT_VERSION = 2 as const;
export const TEAM_GRANT_NONCE_BYTES = 16;

export type TTeamGrant = {
  readonly v: 2;
  readonly team_id: string;
  readonly share_id: string;
  /** Consumer user id (the member opening the channel). */
  readonly consumer: string;
  /** Contributor account that owns the serving device. */
  readonly device_user_id: string;
  /** Serving daemon api_key id. */
  readonly device_key_id: string;
  /** Model id the grant authorises on that device. */
  readonly model: string;
  /** 16-byte nonce, standard base64. */
  readonly n: string;
  /** Expiry, ms since epoch. */
  readonly exp: number;
  /**
   * Optional local monthly token cap the contributor daemon enforces as a
   * second line (origin already reserves). Absent = no local hard cap.
   */
  readonly cap_tokens?: number;
};

export type TTeamGrantEnvelope = TTeamGrant & {
  readonly sig: string;
};

export type TTeamGrantSignFields = Omit<TTeamGrant, "v" | "n" | "exp"> & {
  readonly n?: string;
  readonly exp?: number;
  readonly v?: 2;
};

const isValidNonce = (value: unknown): value is string =>
  isB64OfLength(value, TEAM_GRANT_NONCE_BYTES);

const isPositiveInt = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isFinite(value) &&
  Number.isInteger(value) &&
  value > 0;

const isHex = (value: string): boolean =>
  value.length > 0 && value.length % 2 === 0 && /^[0-9a-f]+$/i.test(value);

const hexOf = (bytes: Uint8Array): string => {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += (bytes[i] as number).toString(16).padStart(2, "0");
  }
  return out;
};

const bytesOfHex = (hex: string): Uint8Array | null => {
  if (!isHex(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (!Number.isFinite(byte)) return null;
    out[i] = byte;
  }
  return out;
};

/** Constant-time compare of equal-length byte arrays. */
const timingSafeEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
};

/**
 * Canonical signed bytes: `utf8(LABEL) || 0x00 || utf8(json)`.
 * Fixed key order `v, team_id, share_id, consumer, device_user_id,
 * device_key_id, model, n, exp[, cap_tokens]`.
 */
export const buildTeamGrantMessage = (fields: TTeamGrant): Uint8Array =>
  labelledMessage(
    TEAM_GRANT_LABEL,
    JSON.stringify({
      v: fields.v,
      team_id: fields.team_id,
      share_id: fields.share_id,
      consumer: fields.consumer,
      device_user_id: fields.device_user_id,
      device_key_id: fields.device_key_id,
      model: fields.model,
      n: fields.n,
      exp: fields.exp,
      ...(fields.cap_tokens === undefined
        ? {}
        : { cap_tokens: fields.cap_tokens }),
    }),
  );

/** base64(JSON) envelope encoding for the wire. */
export const encodeTeamGrant = (envelope: TTeamGrantEnvelope): string =>
  encodeB64Json(
    envelope,
    TEAM_GRANT_B64_MAX,
    "team grant exceeds TEAM_GRANT_B64_MAX",
  );

/** Every key a grant envelope may carry; anything else is refused. */
const TEAM_GRANT_KEYS: ReadonlySet<string> = new Set([
  "v",
  "team_id",
  "share_id",
  "consumer",
  "device_user_id",
  "device_key_id",
  "model",
  "n",
  "exp",
  "cap_tokens",
  "sig",
]);

/**
 * Strict decode. An unknown key is refused, never ignored: a future
 * restriction an older peer can't read must fail closed. Returns null on any
 * unknown key or field mismatch (including rejected v1 envelopes).
 */
export const decodeTeamGrant = (b64: string): TTeamGrantEnvelope | null => {
  const o = decodeB64Json(b64, TEAM_GRANT_B64_MAX);
  if (o === null) return null;
  if (Object.keys(o).some((key) => !TEAM_GRANT_KEYS.has(key))) return null;
  if (o.v !== TEAM_GRANT_VERSION) return null;
  if (!isNonEmptyString(o.team_id)) return null;
  if (!isNonEmptyString(o.share_id)) return null;
  if (!isNonEmptyString(o.consumer)) return null;
  if (!isNonEmptyString(o.device_user_id)) return null;
  if (!isNonEmptyString(o.device_key_id)) return null;
  if (!isNonEmptyString(o.model)) return null;
  if (!isValidNonce(o.n)) return null;
  if (!isPositiveInt(o.exp)) return null;
  if (!isNonEmptyString(o.sig) || !isHex(o.sig)) return null;
  let capTokens: number | undefined;
  if (o.cap_tokens !== undefined) {
    if (!isPositiveInt(o.cap_tokens)) return null;
    capTokens = o.cap_tokens;
  }
  return {
    v: TEAM_GRANT_VERSION,
    team_id: o.team_id,
    share_id: o.share_id,
    consumer: o.consumer,
    device_user_id: o.device_user_id,
    device_key_id: o.device_key_id,
    model: o.model,
    n: o.n,
    exp: o.exp,
    ...(capTokens === undefined ? {} : { cap_tokens: capTokens }),
    sig: o.sig.toLowerCase(),
  };
};

const hmacSha256Hex = async (
  key: string,
  message: Uint8Array,
): Promise<string | null> => {
  if (key.length === 0) return null;
  try {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = new Uint8Array(
      await globalThis.crypto.subtle.sign(
        "HMAC",
        cryptoKey,
        message as BufferSource,
      ),
    );
    return hexOf(sig);
  } catch {
    return null;
  }
};

/**
 * Sign a team grant with the per-contributor HMAC key (hex string, same
 * shape as `perUserTeamGrantKey` / bootstrap `team_grant_key`). Returns the
 * wire token, or null when the key is empty / HMAC fails.
 */
export const signTeamGrant = async (
  fields: TTeamGrant,
  hmacKey: string,
): Promise<string | null> => {
  const message = buildTeamGrantMessage(fields);
  const sig = await hmacSha256Hex(hmacKey, message);
  if (sig === null) return null;
  return encodeTeamGrant({ ...fields, sig });
};

/**
 * Verify a team-grant wire token against a per-contributor HMAC key.
 * Returns the grant fields when the signature matches (constant-time) and
 * `exp > nowMs`; otherwise null. Never throws. Rejects v1 envelopes.
 */
export const verifyTeamGrant = async (
  token: string,
  hmacKey: string,
  nowMs: number,
): Promise<TTeamGrant | null> => {
  const envelope = decodeTeamGrant(token);
  if (envelope === null) return null;
  if (envelope.exp <= nowMs) return null;
  if (hmacKey.length === 0) return null;
  const { sig, ...fields } = envelope;
  const message = buildTeamGrantMessage(fields);
  const expected = await hmacSha256Hex(hmacKey, message);
  if (expected === null) return null;
  const a = bytesOfHex(expected);
  const b = bytesOfHex(sig);
  if (a === null || b === null) return null;
  if (!timingSafeEqual(a, b)) return null;
  return fields;
};
