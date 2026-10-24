/**
 * Device-control rotation wire format + key fingerprint helper.
 *
 * Shared by the browser (which signs rotations with the old control seed)
 * and the daemon (which verifies them against its pinned control pubkey).
 * Bytes + JSON only — no crypto. The v2 format drops the timestamp window
 * that made stored statements unusable: being signed by the current pin is
 * enough, because freshly derived phrases never repeat keys.
 */

import { decodeB64Json, encodeB64Json, labelledMessage } from "./wire-bytes";

export const DEVICE_CONTROL_ROTATE_LABEL = "openllm-device-control-rotate-v2";
export const DEVICE_CONTROL_ROTATE_VERSION = 2 as const;
/** Alias used by `@openllm/vault` `signDeviceControlRotation`. */
export const DEVICE_CONTROL_ROTATION_VERSION = DEVICE_CONTROL_ROTATE_VERSION;
/** Soft wire cap — matches attestation envelopes. */
export const DEVICE_CONTROL_ROTATION_B64_MAX = 1024;
/** Most statements bootstrap hands a daemon / a daemon walks per attempt. */
export const DEVICE_CONTROL_ROTATION_CHAIN_MAX = 8;

export type TDeviceControlRotationFields = {
  readonly v: 2;
  /** Current (old) control public key, SPKI base64. */
  readonly old: string;
  /** Next control public key, SPKI base64. */
  readonly new: string;
  /** New control / vault version — must exceed the daemon's pin version. */
  readonly cv: number;
};

export type TDeviceControlRotationEnvelope = TDeviceControlRotationFields & {
  readonly sig: string;
};

/**
 * Canonical signed bytes: `utf8(LABEL) || 0x00 || utf8(json)`.
 * Fixed key order `v, old, new, cv`.
 */
export const buildDeviceControlRotationMessage = (
  fields: Omit<TDeviceControlRotationFields, "v"> & { readonly v?: 2 },
): Uint8Array =>
  labelledMessage(
    DEVICE_CONTROL_ROTATE_LABEL,
    JSON.stringify({
      v: DEVICE_CONTROL_ROTATE_VERSION,
      old: fields.old,
      new: fields.new,
      cv: fields.cv,
    }),
  );

export const encodeDeviceControlRotation = (
  envelope: TDeviceControlRotationEnvelope,
): string =>
  encodeB64Json(
    envelope,
    DEVICE_CONTROL_ROTATION_B64_MAX,
    "device control rotation exceeds DEVICE_CONTROL_ROTATION_B64_MAX",
  );

export const decodeDeviceControlRotation = (
  b64: string,
): TDeviceControlRotationEnvelope | null => {
  const o = decodeB64Json(b64, DEVICE_CONTROL_ROTATION_B64_MAX);
  if (o === null) return null;
  if (o.v !== DEVICE_CONTROL_ROTATE_VERSION) return null;
  if (typeof o.old !== "string" || o.old.length === 0) return null;
  if (typeof o.new !== "string" || o.new.length === 0) return null;
  if (o.old === o.new) return null;
  if (typeof o.cv !== "number" || !Number.isInteger(o.cv) || o.cv < 1) {
    return null;
  }
  if (typeof o.sig !== "string" || o.sig.length === 0) return null;
  return {
    v: DEVICE_CONTROL_ROTATE_VERSION,
    old: o.old,
    new: o.new,
    cv: o.cv,
    sig: o.sig,
  };
};

/**
 * Short fingerprint of an SPKI (base64): SHA-256, first 16 hex chars as
 * four groups of four (`abcd efgh ijkl mnop`). Used in verify-device UI
 * and `openllm daemon identity` output.
 */
export const keyFingerprint = async (spkiB64: string): Promise<string> => {
  let spki: Uint8Array;
  try {
    const bin = atob(spkiB64);
    spki = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) spki[i] = bin.charCodeAt(i);
  } catch {
    throw new Error("keyFingerprint: malformed SPKI base64");
  }
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", spki as BufferSource),
  );
  return formatKeyFingerprint(digest);
};

/**
 * The {@link keyFingerprint} format from a precomputed SHA-256 digest of the
 * SPKI DER — lets the daemon compute it synchronously with node:crypto while
 * every surface prints the identical string.
 */
export const formatKeyFingerprint = (sha256Digest: Uint8Array): string => {
  if (sha256Digest.length < 8) {
    throw new Error("formatKeyFingerprint: digest too short");
  }
  let hex = "";
  for (let i = 0; i < 8; i++) {
    hex += (sha256Digest[i] as number).toString(16).padStart(2, "0");
  }
  return `${hex.slice(0, 4)} ${hex.slice(4, 8)} ${hex.slice(8, 12)} ${hex.slice(12, 16)}`;
};
