/**
 * Origin-signed team device grant. Short-lived admission for a cross-user
 * relay mux channel: the consumer may reach one contributor device for one
 * model. Wire is labelled canonical JSON + Ed25519 (WebCrypto); the relay and
 * daemon verify against the origin public key (bootstrap / env) — neither
 * holds the signing secret.
 *
 * Unknown future envelope fields are ignored on decode; the signed message is
 * rebuilt from the known field set only, so a v1 verifier stays compatible
 * when optional fields are added later (each optional is part of the signed
 * bytes only when present).
 */

import { TEAM_GRANT_B64_MAX } from "@openllmsh/protocol";
import {
  decodeB64Json,
  encodeB64Json,
  labelledMessage,
  toB64Bytes,
} from "./wire-bytes";

export { TEAM_GRANT_B64_MAX };

export const TEAM_GRANT_LABEL = "openllm-team-grant-v1";
export const TEAM_GRANT_VERSION = 1 as const;
export const TEAM_GRANT_NONCE_BYTES = 16;

/** DER SPKI prefix for an Ed25519 public key (RFC 8410). */
const ED25519_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/** DER PKCS8 prefix for a 32-byte Ed25519 seed (RFC 8410). */
const ED25519_PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

const ED25519_RAW_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const ED25519_SPKI_BYTES = ED25519_SPKI_PREFIX.length + ED25519_RAW_KEY_BYTES;
const ED25519_PKCS8_BYTES = ED25519_PKCS8_PREFIX.length + ED25519_RAW_KEY_BYTES;

export type TTeamGrant = {
  readonly v: 1;
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
  readonly v?: 1;
};

const isNonEmptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** True when `n` is standard base64 of exactly {@link TEAM_GRANT_NONCE_BYTES}. */
const isValidNonce = (value: unknown): value is string => {
  if (!isNonEmptyString(value)) return false;
  try {
    const bin = atob(value);
    return bin.length === TEAM_GRANT_NONCE_BYTES;
  } catch {
    return false;
  }
};

const isPositiveInt = (value: unknown): value is number =>
  typeof value === "number" &&
  Number.isFinite(value) &&
  Number.isInteger(value) &&
  value > 0;

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

/**
 * Strict decode of known fields. Extra JSON keys are tolerated (forward
 * compatible) but never returned. Returns null on any known-field mismatch.
 */
export const decodeTeamGrant = (b64: string): TTeamGrantEnvelope | null => {
  const o = decodeB64Json(b64, TEAM_GRANT_B64_MAX);
  if (o === null) return null;
  if (o.v !== TEAM_GRANT_VERSION) return null;
  if (!isNonEmptyString(o.team_id)) return null;
  if (!isNonEmptyString(o.share_id)) return null;
  if (!isNonEmptyString(o.consumer)) return null;
  if (!isNonEmptyString(o.device_user_id)) return null;
  if (!isNonEmptyString(o.device_key_id)) return null;
  if (!isNonEmptyString(o.model)) return null;
  if (!isValidNonce(o.n)) return null;
  if (!isPositiveInt(o.exp)) return null;
  if (!isNonEmptyString(o.sig)) return null;
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
    sig: o.sig,
  };
};

const fromB64 = (b64: string): Uint8Array | null => {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

const spkiBytes = (spkiB64: string): Uint8Array | null => {
  const spki = fromB64(spkiB64);
  if (spki === null || spki.length !== ED25519_SPKI_BYTES) return null;
  for (let i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
    if (spki[i] !== ED25519_SPKI_PREFIX[i]) return null;
  }
  return spki;
};

const pkcs8Bytes = (pkcs8: Uint8Array): Uint8Array | null => {
  if (pkcs8.length !== ED25519_PKCS8_BYTES) return null;
  for (let i = 0; i < ED25519_PKCS8_PREFIX.length; i++) {
    if (pkcs8[i] !== ED25519_PKCS8_PREFIX[i]) return null;
  }
  return pkcs8;
};

const importVerifyKey = async (
  pubkeySpkiB64: string,
): Promise<CryptoKey | null> => {
  const spki = spkiBytes(pubkeySpkiB64);
  if (spki === null) return null;
  try {
    return await globalThis.crypto.subtle.importKey(
      "spki",
      spki as BufferSource,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch {
    return null;
  }
};

const importSignKey = async (
  privateKey: CryptoKey | Uint8Array,
  extractable = false,
): Promise<CryptoKey | null> => {
  if (typeof CryptoKey !== "undefined" && privateKey instanceof CryptoKey) {
    return privateKey;
  }
  const pkcs8 = pkcs8Bytes(privateKey as Uint8Array);
  if (pkcs8 === null) return null;
  try {
    return await globalThis.crypto.subtle.importKey(
      "pkcs8",
      pkcs8 as BufferSource,
      { name: "Ed25519" },
      extractable,
      ["sign"],
    );
  } catch {
    return null;
  }
};

/**
 * Sign a team grant. `privateKey` is a WebCrypto Ed25519 CryptoKey or PKCS8
 * DER bytes. Returns the wire token, or null when the key cannot be imported.
 */
export const signTeamGrant = async (
  fields: TTeamGrant,
  privateKey: CryptoKey | Uint8Array,
): Promise<string | null> => {
  const key = await importSignKey(privateKey);
  if (key === null) return null;
  const message = buildTeamGrantMessage(fields);
  const sig = new Uint8Array(
    await globalThis.crypto.subtle.sign(
      "Ed25519",
      key,
      message as BufferSource,
    ),
  );
  return encodeTeamGrant({ ...fields, sig: toB64Bytes(sig) });
};

/**
 * Verify a team-grant wire token against an origin SPKI public key (base64).
 * Returns the grant fields when the signature is valid and `exp > nowMs`;
 * otherwise null. Never throws.
 */
export const verifyTeamGrant = async (
  token: string,
  pubkeySpkiB64: string,
  nowMs: number,
): Promise<TTeamGrant | null> => {
  const envelope = decodeTeamGrant(token);
  if (envelope === null) return null;
  if (envelope.exp <= nowMs) return null;
  const key = await importVerifyKey(pubkeySpkiB64);
  if (key === null) return null;
  const sig = fromB64(envelope.sig);
  if (sig === null || sig.length !== ED25519_SIGNATURE_BYTES) return null;
  const { sig: _sig, ...fields } = envelope;
  const message = buildTeamGrantMessage(fields);
  try {
    const ok = await globalThis.crypto.subtle.verify(
      "Ed25519",
      key,
      sig as BufferSource,
      message as BufferSource,
    );
    if (!ok) return null;
  } catch {
    return null;
  }
  return fields;
};

/**
 * Export the SPKI public half of an already-generated Ed25519 key pair.
 * Prefer this over deriving SPKI from PKCS8: WebCrypto (Bun/Chrome) cannot
 * `exportKey("spki")` from a PKCS8-imported private key. Origin derives the
 * public key with node:crypto in `@openllm/api` `team-grant.ts`.
 */
export const exportTeamGrantPublicKey = async (
  publicKey: CryptoKey,
): Promise<string | null> => {
  try {
    const spki = new Uint8Array(
      await globalThis.crypto.subtle.exportKey("spki", publicKey),
    );
    return toB64Bytes(spki);
  } catch {
    return null;
  }
};
