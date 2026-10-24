/**
 * Device trust anchor + daemon-key proof + signed device-sessions command —
 * the wire formats only. Bytes + JSON, no crypto: the browser computes with
 * WebCrypto (`@openllm/vault` `device-anchor.ts`), the daemon with
 * node:crypto (`packages/cli/daemon/src/device-anchor.ts`).
 *
 * - **Anchor** = base64url(control pubkey raw 32 || pair_secret 32), where
 *   `pair_secret = HKDF-SHA256(ikm = control seed, salt = utf8(key_id),
 *   info = "openllm-pair-v1", 32)`. It rides the install / setup command as a
 *   suffix of the API key (`sk-llm-<id>.<secret>.<anchor>`) and NEVER leaves
 *   the device: the daemon splits it off and keeps it in `state.json`.
 * - **dpk proof** = `HMAC-SHA256(pair_secret, "openllm-dpk-proof-v1" ||
 *   key_id || dpk)`, base64url. The daemon publishes it in its status; any browser
 *   holding the control seed recomputes `pair_secret` and verifies it, so the
 *   daemon's static X25519 key is trusted without a first-use window.
 * - **Device-sessions command** = `{ v, key_id, enable, ts, nonce }` signed by
 *   the control key, delivered over the control channel. The daemon verifies
 *   it against its anchored pin.
 */
import {
  isOpenllmDeviceAnchorSyntax,
  OPENLLM_DEVICE_ANCHOR_LENGTH,
} from "@openllmsh/protocol";
import {
  decodeB64Json,
  encodeB64Json,
  labelledMessage,
  toB64Bytes,
} from "./wire-bytes";

/** HKDF info for the per-key pair secret. */
export const DEVICE_PAIR_HKDF_INFO = "openllm-pair-v1";
/** Raw bytes in an anchor: control pubkey (32) || pair secret (32). */
export const DEVICE_ANCHOR_BYTES = 64;
export const DEVICE_ANCHOR_LENGTH = OPENLLM_DEVICE_ANCHOR_LENGTH;
export const DEVICE_PAIR_SECRET_BYTES = 32;
const ED25519_RAW_BYTES = 32;

/** Domain label of the dpk proof MAC input. */
export const DPK_PROOF_LABEL = "openllm-dpk-proof-v1";
/** base64url of a 32-byte HMAC-SHA256. */
export const DPK_PROOF_LENGTH = 43;

/** Domain label of the signed device-sessions command. */
export const DEVICE_SESSIONS_COMMAND_LABEL = "openllm-device-sessions-v1";
export const DEVICE_SESSIONS_COMMAND_VERSION = 1 as const;
/** A command older (or further in the future) than this is refused. */
export const DEVICE_SESSIONS_COMMAND_TS_WINDOW_MS = 5 * 60 * 1000;
export const DEVICE_SESSIONS_COMMAND_B64_MAX = 1024;

/** DER SPKI prefix of an Ed25519 public key. */
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const B64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** base64url, unpadded. */
export const toB64UrlBytes = (bytes: Uint8Array): string =>
  toB64Bytes(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Strict unpadded base64url → bytes; null on any foreign character. */
export const fromB64UrlBytes = (value: string): Uint8Array | null => {
  for (const ch of value) {
    if (!B64URL_ALPHABET.includes(ch)) return null;
  }
  if (value.length % 4 === 1) return null;
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
};

/** Ed25519 raw (32 bytes) → base64(SPKI DER), the form daemons pin. */
export const ed25519SpkiB64FromRaw = (raw: Uint8Array): string => {
  if (raw.length !== ED25519_RAW_BYTES) {
    throw new RangeError("ed25519 raw public key must be 32 bytes");
  }
  const spki = new Uint8Array(ED25519_SPKI_PREFIX.length + raw.length);
  spki.set(ED25519_SPKI_PREFIX, 0);
  spki.set(raw, ED25519_SPKI_PREFIX.length);
  return toB64Bytes(spki);
};

export type TDeviceAnchor = {
  /** The account control public key, base64(SPKI DER). */
  readonly controlPubkey: string;
  /** `HKDF(control seed, utf8(key_id), "openllm-pair-v1")`, 32 bytes. */
  readonly pairSecret: Uint8Array;
};

/** `base64url(control raw || pair secret)`. */
export const encodeDeviceAnchor = (
  controlPubkeyRaw: Uint8Array,
  pairSecret: Uint8Array,
): string => {
  if (controlPubkeyRaw.length !== ED25519_RAW_BYTES) {
    throw new RangeError("anchor control key must be 32 raw bytes");
  }
  if (pairSecret.length !== DEVICE_PAIR_SECRET_BYTES) {
    throw new RangeError("anchor pair secret must be 32 bytes");
  }
  const bytes = new Uint8Array(DEVICE_ANCHOR_BYTES);
  bytes.set(controlPubkeyRaw, 0);
  bytes.set(pairSecret, ED25519_RAW_BYTES);
  return toB64UrlBytes(bytes);
};

/** Decode an anchor; null unless exactly 86 base64url chars of 64 bytes. */
export const decodeDeviceAnchor = (anchor: string): TDeviceAnchor | null => {
  if (!isOpenllmDeviceAnchorSyntax(anchor)) return null;
  const bytes = fromB64UrlBytes(anchor);
  if (bytes === null || bytes.length !== DEVICE_ANCHOR_BYTES) return null;
  return {
    controlPubkey: ed25519SpkiB64FromRaw(bytes.slice(0, ED25519_RAW_BYTES)),
    pairSecret: bytes.slice(ED25519_RAW_BYTES),
  };
};

/**
 * MAC input of the dpk proof:
 * `utf8("openllm-dpk-proof-v1") || utf8(key_id) || utf8(dpk)` — plain
 * concatenation, unambiguous because `key_id` is the fixed-length (14 char)
 * api key id. `dpk` is the daemon's X25519 SPKI DER, base64 — exactly
 * `DaemonStatus.pubkey`.
 */
export const buildDpkProofMessage = (
  keyId: string,
  dpk: string,
): Uint8Array => {
  const enc = new TextEncoder();
  const label = enc.encode(DPK_PROOF_LABEL);
  const kid = enc.encode(keyId);
  const key = enc.encode(dpk);
  const out = new Uint8Array(label.length + kid.length + key.length);
  out.set(label, 0);
  out.set(kid, label.length);
  out.set(key, label.length + kid.length);
  return out;
};

/** True when `proof` has the shape of a dpk proof (43 base64url chars). */
export const isDpkProofSyntax = (proof: string): boolean =>
  proof.length === DPK_PROOF_LENGTH && fromB64UrlBytes(proof)?.length === 32;

export type TDeviceSessionsCommandFields = {
  readonly v: 1;
  /** The target daemon's api key id — a command for another key is refused. */
  readonly key_id: string;
  readonly enable: boolean;
  /** ms since epoch; must be fresh and greater than the last accepted one. */
  readonly ts: number;
  /** 16 random bytes, base64url — makes every statement unique. */
  readonly nonce: string;
};

export type TDeviceSessionsCommandEnvelope = TDeviceSessionsCommandFields & {
  /** Ed25519 signature by the control key, base64. */
  readonly sig: string;
};

/**
 * Canonical signed bytes: `utf8(LABEL) || 0x00 || utf8(json)`, fixed key
 * order `v, key_id, enable, ts, nonce`.
 */
export const buildDeviceSessionsCommandMessage = (
  fields: TDeviceSessionsCommandFields,
): Uint8Array =>
  labelledMessage(
    DEVICE_SESSIONS_COMMAND_LABEL,
    JSON.stringify({
      v: fields.v,
      key_id: fields.key_id,
      enable: fields.enable,
      ts: fields.ts,
      nonce: fields.nonce,
    }),
  );

export const encodeDeviceSessionsCommand = (
  envelope: TDeviceSessionsCommandEnvelope,
): string =>
  encodeB64Json(
    {
      v: envelope.v,
      key_id: envelope.key_id,
      enable: envelope.enable,
      ts: envelope.ts,
      nonce: envelope.nonce,
      sig: envelope.sig,
    },
    DEVICE_SESSIONS_COMMAND_B64_MAX,
    "device sessions command exceeds its wire cap",
  );

export const decodeDeviceSessionsCommand = (
  b64: string,
): TDeviceSessionsCommandEnvelope | null => {
  const o = decodeB64Json(b64, DEVICE_SESSIONS_COMMAND_B64_MAX);
  if (o === null) return null;
  if (o.v !== DEVICE_SESSIONS_COMMAND_VERSION) return null;
  if (typeof o.key_id !== "string" || o.key_id.length === 0) return null;
  if (typeof o.enable !== "boolean") return null;
  if (
    typeof o.ts !== "number" ||
    !Number.isInteger(o.ts) ||
    !Number.isFinite(o.ts) ||
    o.ts <= 0
  ) {
    return null;
  }
  if (typeof o.nonce !== "string" || o.nonce.length === 0) return null;
  if (typeof o.sig !== "string" || o.sig.length === 0) return null;
  return {
    v: DEVICE_SESSIONS_COMMAND_VERSION,
    key_id: o.key_id,
    enable: o.enable,
    ts: o.ts,
    nonce: o.nonce,
    sig: o.sig,
  };
};
