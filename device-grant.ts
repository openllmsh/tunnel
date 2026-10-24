/**
 * Canonical device-grant wire format shared by the browser (which
 * SIGNS grants with the account device-control key — derived from the
 * recovery phrase, never the DEK; see `device-control.ts`) and the
 * daemon (which VERIFIES them against its pinned control pubkey). Bytes + JSON only — no crypto lives
 * here. Wire size cap is owned by protocol and re-exported.
 */

import { DEVICE_GRANT_B64_MAX } from "@openllmsh/protocol";
import { decodeB64Json, encodeB64Json, labelledMessage } from "./wire-bytes";

export { DEVICE_GRANT_B64_MAX };

export const DEVICE_GRANT_LABEL = "openllm-device-grant-v1";
export const DEVICE_GRANT_VERSION = 1 as const;
export const DEVICE_GRANT_TS_WINDOW_MS = 120_000;
export const DEVICE_GRANT_NONCE_BYTES = 16;

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
  /**
   * The daemon X25519 pubkey (SPKI DER, base64) the signer TRUSTS — taken
   * from a daemon attestation signed by the device-control key
   * (`@openllm/vault` `daemon-attest.ts`), not from the cloud — and used as
   * the Noise_IK responder key (`secure.ts`) on the relay mux. The daemon
   * refuses a grant whose `dpk` is not its own key. Absent on legacy grants;
   * when absent it is also absent from the signed message, so legacy bytes
   * are unchanged.
   */
  readonly dpk?: string;
};

export type TDeviceGrantEnvelope = TDeviceGrantFields & {
  readonly sig: string;
};

/**
 * Canonical signed bytes: `utf8(LABEL) || 0x00 || utf8(json)`.
 *
 * The JSON is canonical-by-construction: it is produced by
 * `JSON.stringify` of an object literal written in the fixed field
 * order `v, n, ts, key_id, cid, aud[, dpk]` (`dpk` only when present).
 * ECMAScript guarantees own string-keyed property enumeration (and
 * therefore stringify output) follows insertion order, so building the
 * literal in that order yields identical bytes for identical fields on
 * every runtime.
 */
export const buildDeviceGrantMessage = (
  fields: TDeviceGrantFields,
): Uint8Array =>
  labelledMessage(
    DEVICE_GRANT_LABEL,
    JSON.stringify({
      v: fields.v,
      n: fields.n,
      ts: fields.ts,
      key_id: fields.key_id,
      cid: fields.cid,
      aud: fields.aud,
      ...(fields.dpk === undefined ? {} : { dpk: fields.dpk }),
    }),
  );

/** base64(JSON) envelope encoding for the wire. */
export const encodeDeviceGrant = (envelope: TDeviceGrantEnvelope): string =>
  encodeB64Json(
    envelope,
    DEVICE_GRANT_B64_MAX,
    "device grant exceeds DEVICE_GRANT_B64_MAX",
  );

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
 * empty string (legacy tunnel path); `dpk` may be absent (legacy grant) but,
 * when present, must be a non-empty string; every other string field must be
 * non-empty, `v` must be exactly 1, `n` base64 of
 * {@link DEVICE_GRANT_NONCE_BYTES} bytes, and `ts` a finite positive integer.
 */
export const decodeDeviceGrant = (b64: string): TDeviceGrantEnvelope | null => {
  const o = decodeB64Json(b64, DEVICE_GRANT_B64_MAX);
  if (o === null) return null;
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
  const rawDpk = o.dpk;
  const dpk: string | undefined | null =
    rawDpk === undefined ? undefined : isNonEmptyString(rawDpk) ? rawDpk : null;
  if (dpk === null) return null;
  return {
    v: DEVICE_GRANT_VERSION,
    n: o.n,
    ts: o.ts,
    key_id: o.key_id,
    cid: o.cid,
    aud: o.aud,
    ...(dpk === undefined ? {} : { dpk }),
    sig: o.sig,
  };
};
